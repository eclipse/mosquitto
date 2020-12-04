/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR EDL-1.0

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <uthash.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "json_help.h"

#include "dynamic_security.h"

/* ################################################################
 * #
 * # Function declarations
 * #
 * ################################################################ */

static int dynsec__remove_client_from_all_groups(const char *username);

/* ################################################################
 * #
 * # Local variables
 * #
 * ################################################################ */

static struct dynsec__client *local_clients = NULL;


/* ################################################################
 * #
 * # Utility functions
 * #
 * ################################################################ */

static int client_cmp(void *a, void *b)
{
	struct dynsec__client *client_a = a;
	struct dynsec__client *client_b = b;

	return strcmp(client_a->username, client_b->username);
}

struct dynsec__client *dynsec_clients__find(const char *username)
{
	struct dynsec__client *client = NULL;

	if(username){
		HASH_FIND(hh, local_clients, username, strlen(username), client);
	}
	return client;
}


static void client__free_item(struct dynsec__client *client)
{
	struct dynsec__client *client_found;
	if(client == NULL) return;

	client_found = dynsec_clients__find(client->username);
	if(client_found){
		HASH_DEL(local_clients, client_found);
	}
	dynsec_rolelist__cleanup(&client->rolelist);
	dynsec__remove_client_from_all_groups(client->username);
	mosquitto_free(client->text_name);
	mosquitto_free(client->text_description);
	mosquitto_free(client->clientid);
	mosquitto_free(client->username);
	mosquitto_free(client);
}

void dynsec_clients__cleanup(void)
{
	struct dynsec__client *client, *client_tmp;

	HASH_ITER(hh, local_clients, client, client_tmp){
		client__free_item(client);
	}
}

/* ################################################################
 * #
 * # Config file load and save
 * #
 * ################################################################ */

int dynsec_clients__config_load(cJSON *tree)
{
	cJSON *j_clients, *j_client, *jtmp, *j_roles, *j_role;
	cJSON *j_salt, *j_password, *j_iterations;
	struct dynsec__client *client;
	struct dynsec__role *role;
	unsigned char *buf;
	int buf_len;
	int priority;
	int iterations;

	j_clients = cJSON_GetObjectItem(tree, "clients");
	if(j_clients == NULL){
		return 0;
	}

	if(cJSON_IsArray(j_clients) == false){
		return 1;
	}

	cJSON_ArrayForEach(j_client, j_clients){
		if(cJSON_IsObject(j_client) == true){
			client = mosquitto_calloc(1, sizeof(struct dynsec__client));
			if(client == NULL){
				return MOSQ_ERR_NOMEM;
			}

			/* Username */
			jtmp = cJSON_GetObjectItem(j_client, "username");
			if(jtmp == NULL || !cJSON_IsString(jtmp)){
				mosquitto_free(client);
				continue;
			}
			client->username = mosquitto_strdup(jtmp->valuestring);
			if(client->username == NULL){
				mosquitto_free(client);
				continue;
			}

			jtmp = cJSON_GetObjectItem(j_client, "disabled");
			if(jtmp && cJSON_IsBool(jtmp)){
				client->disabled = cJSON_IsTrue(jtmp);
			}

			/* Salt */
			j_salt = cJSON_GetObjectItem(j_client, "salt");
			j_password = cJSON_GetObjectItem(j_client, "password");
			j_iterations = cJSON_GetObjectItem(j_client, "iterations");

			if(j_salt && cJSON_IsString(j_salt) 
					&& j_password && cJSON_IsString(j_password)
					&& j_iterations && cJSON_IsNumber(j_iterations)){

				iterations = (int)j_iterations->valuedouble;
				if(iterations < 1){
					mosquitto_free(client->username);
					mosquitto_free(client);
					continue;
				}else{
					client->pw.iterations = iterations;
				}

				if(dynsec_auth__base64_decode(j_salt->valuestring, &buf, &buf_len) != MOSQ_ERR_SUCCESS
						|| buf_len != sizeof(client->pw.salt)){

					mosquitto_free(client->username);
					mosquitto_free(client);
					continue;
				}
				memcpy(client->pw.salt, buf, (size_t)buf_len);
				mosquitto_free(buf);

				if(dynsec_auth__base64_decode(j_password->valuestring, &buf, &buf_len) != MOSQ_ERR_SUCCESS
						|| buf_len != sizeof(client->pw.password_hash)){

					mosquitto_free(client->username);
					mosquitto_free(client);
					continue;
				}
				memcpy(client->pw.password_hash, buf, (size_t)buf_len);
				mosquitto_free(buf);
				client->pw.valid = true;
			}else{
				client->pw.valid = false;
			}

			/* Client id */
			jtmp = cJSON_GetObjectItem(j_client, "clientid");
			if(jtmp != NULL && cJSON_IsString(jtmp)){
				client->clientid = mosquitto_strdup(jtmp->valuestring);
				if(client->clientid == NULL){
					mosquitto_free(client->username);
					mosquitto_free(client);
					continue;
				}
			}

			/* Text name */
			jtmp = cJSON_GetObjectItem(j_client, "textname");
			if(jtmp != NULL && cJSON_IsString(jtmp)){
				client->text_name = mosquitto_strdup(jtmp->valuestring);
				if(client->text_name == NULL){
					mosquitto_free(client->clientid);
					mosquitto_free(client->username);
					mosquitto_free(client);
					continue;
				}
			}

			/* Text description */
			jtmp = cJSON_GetObjectItem(j_client, "textdescription");
			if(jtmp != NULL && cJSON_IsString(jtmp)){
				client->text_description = mosquitto_strdup(jtmp->valuestring);
				if(client->text_description == NULL){
					mosquitto_free(client->text_name);
					mosquitto_free(client->clientid);
					mosquitto_free(client->username);
					mosquitto_free(client);
					continue;
				}
			}

			/* Roles */
			j_roles = cJSON_GetObjectItem(j_client, "roles");
			if(j_roles && cJSON_IsArray(j_roles)){
				cJSON_ArrayForEach(j_role, j_roles){
					if(cJSON_IsObject(j_role)){
						jtmp = cJSON_GetObjectItem(j_role, "rolename");
						if(jtmp && cJSON_IsString(jtmp)){
							json_get_int(j_role, "priority", &priority, true, -1);
							role = dynsec_roles__find(jtmp->valuestring);
							dynsec_rolelist__client_add(client, role, priority);
						}
					}
				}
			}

			HASH_ADD_KEYPTR(hh, local_clients, client->username, strlen(client->username), client);
		}
	}
	HASH_SORT(local_clients, client_cmp);

	return 0;
}


static int dynsec__config_add_clients(cJSON *j_clients)
{
	struct dynsec__client *client, *client_tmp;
	cJSON *j_client, *j_roles, *jtmp;
	char *buf;

	HASH_ITER(hh, local_clients, client, client_tmp){
		j_client = cJSON_CreateObject();
		if(j_client == NULL) return 1;
		cJSON_AddItemToArray(j_clients, j_client);

		if(cJSON_AddStringToObject(j_client, "username", client->username) == NULL
				|| (client->clientid && cJSON_AddStringToObject(j_client, "clientid", client->clientid) == NULL)
				|| (client->text_name && cJSON_AddStringToObject(j_client, "textname", client->text_name) == NULL)
				|| (client->text_description && cJSON_AddStringToObject(j_client, "textdescription", client->text_description) == NULL)
				|| (client->disabled && cJSON_AddBoolToObject(j_client, "disabled", true) == NULL)
				){

			return 1;
		}

		j_roles = dynsec_rolelist__all_to_json(client->rolelist);
		if(j_roles == NULL){
			return 1;
		}
		cJSON_AddItemToObject(j_client, "roles", j_roles);

		if(client->pw.valid){
			if(dynsec_auth__base64_encode(client->pw.password_hash, sizeof(client->pw.password_hash), &buf) != MOSQ_ERR_SUCCESS){
				return 1;
			}
			jtmp = cJSON_CreateString(buf);
			mosquitto_free(buf);
			if(jtmp == NULL) return 1;
			cJSON_AddItemToObject(j_client, "password", jtmp);

			if(dynsec_auth__base64_encode(client->pw.salt, sizeof(client->pw.salt), &buf) != MOSQ_ERR_SUCCESS){
				return 1;
			}

			jtmp = cJSON_CreateString(buf);
			mosquitto_free(buf);
			if(jtmp == NULL) return 1;
			cJSON_AddItemToObject(j_client, "salt", jtmp);

			if(cJSON_AddIntToObject(j_client, "iterations", client->pw.iterations) == NULL){
				return 1;
			}
		}
	}

	return 0;
}


int dynsec_clients__config_save(cJSON *tree)
{
	cJSON *j_clients;

	if((j_clients = cJSON_AddArrayToObject(tree, "clients")) == NULL){
		return 1;
	}
	if(dynsec__config_add_clients(j_clients)){
		return 1;
	}

	return 0;
}


int dynsec_clients__process_create(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *username, *password, *clientid = NULL;
	char *text_name, *text_description;
	struct dynsec__client *client;
	int rc;
	cJSON *j_groups, *j_group, *jtmp;
	int priority;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "username", &username, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createClient", "Invalid/missing username", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(username, (int)strlen(username)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createClient", "Username not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "password", &password, true) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createClient", "Invalid/missing password", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "clientid", &clientid, true) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createClient", "Invalid/missing client id", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(clientid && mosquitto_validate_utf8(clientid, (int)strlen(clientid)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createClient", "Client ID not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}


	if(json_get_string(command, "textname", &text_name, true) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createClient", "Invalid/missing textname", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "textdescription", &text_description, true) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createClient", "Invalid/missing textdescription", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	client = dynsec_clients__find(username);
	if(client){
		dynsec__command_reply(j_responses, context, "createClient", "Client already exists", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	client = mosquitto_calloc(1, sizeof(struct dynsec__client));
	if(client == NULL){
		dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}
	client->username = mosquitto_strdup(username);
	if(client->username == NULL){
		dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
		client__free_item(client);
		return MOSQ_ERR_NOMEM;
	}
	if(text_name){
		client->text_name = mosquitto_strdup(text_name);
		if(client->text_name == NULL){
			dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
			client__free_item(client);
			return MOSQ_ERR_NOMEM;
		}
	}
	if(text_description){
		client->text_description = mosquitto_strdup(text_description);
		if(client->text_description == NULL){
			dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
			client__free_item(client);
			return MOSQ_ERR_NOMEM;
		}
	}

	if(password){
		if(dynsec_auth__pw_hash(client, password, client->pw.password_hash, sizeof(client->pw.password_hash), true)){
			dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
			client__free_item(client);
			return MOSQ_ERR_NOMEM;
		}
		client->pw.valid = true;
	}
	if(clientid && strlen(clientid) > 0){
		client->clientid = mosquitto_strdup(clientid);
		if(client->clientid == NULL){
			dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
			client__free_item(client);
			return MOSQ_ERR_NOMEM;
		}
	}

	rc = dynsec_rolelist__load_from_json(command, &client->rolelist);
	if(rc == MOSQ_ERR_SUCCESS || rc == ERR_LIST_NOT_FOUND){
	}else if(rc == MOSQ_ERR_NOT_FOUND){
		dynsec__command_reply(j_responses, context, "createClient", "Role not found", correlation_data);
		client__free_item(client);
		return MOSQ_ERR_INVAL;
	}else{
		if(rc == MOSQ_ERR_INVAL){
			dynsec__command_reply(j_responses, context, "createClient", "'roles' not an array or missing/invalid rolename", correlation_data);
		}else{
			dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
		}
		client__free_item(client);
		return MOSQ_ERR_INVAL;
	}

	/* Must add user before groups, otherwise adding groups will fail */
	HASH_ADD_KEYPTR_INORDER(hh, local_clients, client->username, strlen(client->username), client, client_cmp);

	j_groups = cJSON_GetObjectItem(command, "groups");
	if(j_groups && cJSON_IsArray(j_groups)){
		cJSON_ArrayForEach(j_group, j_groups){
			if(cJSON_IsObject(j_group)){
				jtmp = cJSON_GetObjectItem(j_group, "groupname");
				if(jtmp && cJSON_IsString(jtmp)){
					json_get_int(j_group, "priority", &priority, true, -1);
					rc = dynsec_groups__add_client(username, jtmp->valuestring, priority, false);
					if(rc == ERR_GROUP_NOT_FOUND){
						dynsec__command_reply(j_responses, context, "createClient", "Group not found", correlation_data);
						client__free_item(client);
						return MOSQ_ERR_INVAL;
					}else if(rc != MOSQ_ERR_SUCCESS){
						dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
						client__free_item(client);
						return MOSQ_ERR_INVAL;
					}
				}
			}
		}
	}

	dynsec__config_save();

	dynsec__command_reply(j_responses, context, "createClient", NULL, correlation_data);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | createClient | username=%s | password=%s",
			admin_clientid, admin_username, username, password?"*****":"no password");

	return MOSQ_ERR_SUCCESS;
}


int dynsec_clients__process_delete(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *username;
	struct dynsec__client *client;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "username", &username, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "deleteClient", "Invalid/missing username", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	client = dynsec_clients__find(username);
	if(client){
		dynsec__remove_client_from_all_groups(username);
		client__free_item(client);
		dynsec__config_save();
		dynsec__command_reply(j_responses, context, "deleteClient", NULL, correlation_data);

		/* Enforce any changes */
		mosquitto_kick_client_by_username(username, false);

		admin_clientid = mosquitto_client_id(context);
		admin_username = mosquitto_client_username(context);
		mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | deleteClient | username=%s",
				admin_clientid, admin_username, username);

		return MOSQ_ERR_SUCCESS;
	}else{
		dynsec__command_reply(j_responses, context, "deleteClient", "Client not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_clients__process_disable(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *username;
	struct dynsec__client *client;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "username", &username, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "disableClient", "Invalid/missing username", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(username, (int)strlen(username)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "disableClient", "Username not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	client = dynsec_clients__find(username);
	if(client == NULL){
		dynsec__command_reply(j_responses, context, "disableClient", "Client not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	client->disabled = true;

	mosquitto_kick_client_by_username(username, false);

	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "disableClient", NULL, correlation_data);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | disableClient | username=%s",
			admin_clientid, admin_username, username);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_clients__process_enable(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *username;
	struct dynsec__client *client;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "username", &username, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "enableClient", "Invalid/missing username", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(username, (int)strlen(username)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "enableClient", "Username not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	client = dynsec_clients__find(username);
	if(client == NULL){
		dynsec__command_reply(j_responses, context, "enableClient", "Client not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	client->disabled = false;

	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "enableClient", NULL, correlation_data);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | enableClient | username=%s",
			admin_clientid, admin_username, username);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_clients__process_set_id(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *username, *clientid, *clientid_heap = NULL;
	struct dynsec__client *client;
	size_t slen;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "username", &username, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "setClientId", "Invalid/missing username", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(username, (int)strlen(username)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "setClientId", "Username not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "clientid", &clientid, true) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "setClientId", "Invalid/missing client ID", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(clientid){
		slen = strlen(clientid);
		if(mosquitto_validate_utf8(clientid, (int)slen) != MOSQ_ERR_SUCCESS){
			dynsec__command_reply(j_responses, context, "setClientId", "Client ID not valid UTF-8", correlation_data);
			return MOSQ_ERR_INVAL;
		}
		if(slen > 0){
			clientid_heap = mosquitto_strdup(clientid);
			if(clientid_heap == NULL){
				dynsec__command_reply(j_responses, context, "setClientId", "Internal error", correlation_data);
				return MOSQ_ERR_NOMEM;
			}
		}else{
			clientid_heap = NULL;
		}
	}

	client = dynsec_clients__find(username);
	if(client == NULL){
		mosquitto_free(clientid_heap);
		dynsec__command_reply(j_responses, context, "setClientId", "Client not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	mosquitto_free(client->clientid);
	client->clientid = clientid_heap;

	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "setClientId", NULL, correlation_data);

	/* Enforce any changes */
	mosquitto_kick_client_by_username(username, false);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | setClientId | username=%s | clientid=%s",
			admin_clientid, admin_username, username, client->clientid);

	return MOSQ_ERR_SUCCESS;
}


static int client__set_password(struct dynsec__client *client, const char *password)
{
	if(dynsec_auth__pw_hash(client, password, client->pw.password_hash, sizeof(client->pw.password_hash), true) == MOSQ_ERR_SUCCESS){
		client->pw.valid = true;

		return MOSQ_ERR_SUCCESS;
	}else{
		client->pw.valid = false;
		// FIXME - this should fail safe without modifying the existing password
		return MOSQ_ERR_NOMEM;
	}
}

int dynsec_clients__process_set_password(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *username, *password;
	struct dynsec__client *client;
	int rc;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "username", &username, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "setClientPassword", "Invalid/missing username", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(username, (int)strlen(username)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "setClientPassword", "Username not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "password", &password, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "setClientPassword", "Invalid/missing password", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(strlen(password) == 0){
		dynsec__command_reply(j_responses, context, "setClientPassword", "Empty password is not allowed", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	client = dynsec_clients__find(username);
	if(client == NULL){
		dynsec__command_reply(j_responses, context, "setClientPassword", "Client not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}
	rc = client__set_password(client, password);
	if(rc == MOSQ_ERR_SUCCESS){
		dynsec__config_save();
		dynsec__command_reply(j_responses, context, "setClientPassword", NULL, correlation_data);

		/* Enforce any changes */
		mosquitto_kick_client_by_username(username, false);

		admin_clientid = mosquitto_client_id(context);
		admin_username = mosquitto_client_username(context);
		mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | setClientPassword | username=%s | password=******",
				admin_clientid, admin_username, username);
	}else{
		dynsec__command_reply(j_responses, context, "setClientPassword", "Internal error", correlation_data);
	}
	return rc;
}


static void client__add_new_roles(struct dynsec__client *client, struct dynsec__rolelist *base_rolelist)
{
	struct dynsec__rolelist *rolelist, *rolelist_tmp;

	HASH_ITER(hh, base_rolelist, rolelist, rolelist_tmp){
		dynsec_rolelist__client_add(client, rolelist->role, rolelist->priority);
	}
}

static void client__remove_all_roles(struct dynsec__client *client)
{
	struct dynsec__rolelist *rolelist, *rolelist_tmp;

	HASH_ITER(hh, client->rolelist, rolelist, rolelist_tmp){
		dynsec_rolelist__client_remove(client, rolelist->role);
	}
}

int dynsec_clients__process_modify(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *username;
	char *clientid;
	char *password;
	char *text_name, *text_description;
	struct dynsec__client *client;
	struct dynsec__rolelist *rolelist = NULL;
	char *str;
	int rc;
	int priority;
	cJSON *j_group, *j_groups, *jtmp;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "username", &username, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "modifyClient", "Invalid/missing username", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(username, (int)strlen(username)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "modifyClient", "Username not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	client = dynsec_clients__find(username);
	if(client == NULL){
		dynsec__command_reply(j_responses, context, "modifyClient", "Client not found", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "clientid", &clientid, false) == MOSQ_ERR_SUCCESS){
		if(clientid && strlen(clientid) > 0){
			str = mosquitto_strdup(clientid);
			if(str == NULL){
				dynsec__command_reply(j_responses, context, "modifyClient", "Internal error", correlation_data);
				return MOSQ_ERR_NOMEM;
			}
		}else{
			str = NULL;
		}
		mosquitto_free(client->clientid);
		client->clientid = str;
	}

	if(json_get_string(command, "password", &password, false) == MOSQ_ERR_SUCCESS){
		if(strlen(password) > 0){
			/* If password == "", we just ignore it */
			rc = client__set_password(client, password);
			if(rc != MOSQ_ERR_SUCCESS){
				dynsec__command_reply(j_responses, context, "modifyClient", "Internal error", correlation_data);
				mosquitto_kick_client_by_username(username, false);
				return MOSQ_ERR_NOMEM;
			}
		}
	}

	if(json_get_string(command, "textname", &text_name, false) == MOSQ_ERR_SUCCESS){
		str = mosquitto_strdup(text_name);
		if(str == NULL){
			dynsec__command_reply(j_responses, context, "modifyClient", "Internal error", correlation_data);
			mosquitto_kick_client_by_username(username, false);
			return MOSQ_ERR_NOMEM;
		}
		mosquitto_free(client->text_name);
		client->text_name = str;
	}

	if(json_get_string(command, "textdescription", &text_description, false) == MOSQ_ERR_SUCCESS){
		str = mosquitto_strdup(text_description);
		if(str == NULL){
			dynsec__command_reply(j_responses, context, "modifyClient", "Internal error", correlation_data);
			mosquitto_kick_client_by_username(username, false);
			return MOSQ_ERR_NOMEM;
		}
		mosquitto_free(client->text_description);
		client->text_description = str;
	}

	rc = dynsec_rolelist__load_from_json(command, &rolelist);
	if(rc == MOSQ_ERR_SUCCESS){
		client__remove_all_roles(client);
		client__add_new_roles(client, rolelist);
		dynsec_rolelist__cleanup(&rolelist);
	}else if(rc == ERR_LIST_NOT_FOUND){
		/* There was no list in the JSON, so no modification */
	}else if(rc == MOSQ_ERR_NOT_FOUND){
		dynsec__command_reply(j_responses, context, "modifyClient", "Role not found", correlation_data);
		dynsec_rolelist__cleanup(&rolelist);
		mosquitto_kick_client_by_username(username, false);
		return MOSQ_ERR_INVAL;
	}else{
		if(rc == MOSQ_ERR_INVAL){
			dynsec__command_reply(j_responses, context, "modifyClient", "'roles' not an array or missing/invalid rolename", correlation_data);
		}else{
			dynsec__command_reply(j_responses, context, "modifyClient", "Internal error", correlation_data);
		}
		dynsec_rolelist__cleanup(&rolelist);
		mosquitto_kick_client_by_username(username, false);
		return MOSQ_ERR_INVAL;
	}

	j_groups = cJSON_GetObjectItem(command, "groups");
	if(j_groups && cJSON_IsArray(j_groups)){
		dynsec__remove_client_from_all_groups(username);

		cJSON_ArrayForEach(j_group, j_groups){
			if(cJSON_IsObject(j_group)){
				jtmp = cJSON_GetObjectItem(j_group, "groupname");
				if(jtmp && cJSON_IsString(jtmp)){
					json_get_int(j_group, "priority", &priority, true, -1);
					dynsec_groups__add_client(username, jtmp->valuestring, priority, false);
				}
			}
		}
	}

	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "modifyClient", NULL, correlation_data);

	/* Enforce any changes */
	mosquitto_kick_client_by_username(username, false);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | modifyClient | username=%s",
			admin_clientid, admin_username, username);
	return MOSQ_ERR_SUCCESS;
}


static int dynsec__remove_client_from_all_groups(const char *username)
{
	struct dynsec__grouplist *grouplist, *grouplist_tmp;
	struct dynsec__client *client;

	client = dynsec_clients__find(username);
	if(client){
		HASH_ITER(hh, client->grouplist, grouplist, grouplist_tmp){
			dynsec_groups__remove_client(username, grouplist->group->groupname, false);
		}
	}

	return MOSQ_ERR_SUCCESS;
}


static cJSON *add_client_to_json(struct dynsec__client *client, bool verbose)
{
	cJSON *j_client = NULL, *j_groups, *j_roles;

	if(verbose){
		j_client = cJSON_CreateObject();
		if(j_client == NULL){
			return NULL;
		}

		if(cJSON_AddStringToObject(j_client, "username", client->username) == NULL
				|| (client->clientid && cJSON_AddStringToObject(j_client, "clientid", client->clientid) == NULL)
				|| (client->text_name && cJSON_AddStringToObject(j_client, "textname", client->text_name) == NULL)
				|| (client->text_description && cJSON_AddStringToObject(j_client, "textdescription", client->text_description) == NULL)
				|| (client->disabled && cJSON_AddBoolToObject(j_client, "disabled", client->disabled) == NULL)
				){

			cJSON_Delete(j_client);
			return NULL;
		}

		j_roles = dynsec_rolelist__all_to_json(client->rolelist);
		if(j_roles == NULL){
			cJSON_Delete(j_client);
			return NULL;
		}
		cJSON_AddItemToObject(j_client, "roles", j_roles);

		j_groups = dynsec_grouplist__all_to_json(client->grouplist);
		if(j_groups == NULL){
			cJSON_Delete(j_client);
			return NULL;
		}
		cJSON_AddItemToObject(j_client, "groups", j_groups);
	}else{
		j_client = cJSON_CreateString(client->username);
		if(j_client == NULL){
			return NULL;
		}
	}
	return j_client;
}


int dynsec_clients__process_get(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *username;
	struct dynsec__client *client;
	cJSON *tree, *j_client, *j_data;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "username", &username, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "getClient", "Invalid/missing username", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(username, (int)strlen(username)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "getClient", "Username not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	client = dynsec_clients__find(username);
	if(client == NULL){
		dynsec__command_reply(j_responses, context, "getClient", "Client not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	tree = cJSON_CreateObject();
	if(tree == NULL){
		dynsec__command_reply(j_responses, context, "getClient", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	if(cJSON_AddStringToObject(tree, "command", "getClient") == NULL
			|| (j_data = cJSON_AddObjectToObject(tree, "data")) == NULL
			|| (correlation_data && cJSON_AddStringToObject(tree, "correlationData", correlation_data) == NULL)
			){

		cJSON_Delete(tree);
		dynsec__command_reply(j_responses, context, "getClient", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	j_client = add_client_to_json(client, true);
	if(j_client == NULL){
		cJSON_Delete(tree);
		dynsec__command_reply(j_responses, context, "getClient", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToObject(j_data, "client", j_client);
	cJSON_AddItemToArray(j_responses, tree);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | getClient | username=%s",
			admin_clientid, admin_username, username);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_clients__process_list(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	bool verbose;
	struct dynsec__client *client, *client_tmp;
	cJSON *tree, *j_clients, *j_client, *j_data;
	int i, count, offset;
	const char *admin_clientid, *admin_username;

	json_get_bool(command, "verbose", &verbose, true, false);
	json_get_int(command, "count", &count, true, -1);
	json_get_int(command, "offset", &offset, true, 0);

	tree = cJSON_CreateObject();
	if(tree == NULL){
		dynsec__command_reply(j_responses, context, "listClients", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	if(cJSON_AddStringToObject(tree, "command", "listClients") == NULL
			|| (j_data = cJSON_AddObjectToObject(tree, "data")) == NULL
			|| cJSON_AddIntToObject(j_data, "totalCount", (int)HASH_CNT(hh, local_clients)) == NULL
			|| (j_clients = cJSON_AddArrayToObject(j_data, "clients")) == NULL
			|| (correlation_data && cJSON_AddStringToObject(tree, "correlationData", correlation_data) == NULL)
			){

		cJSON_Delete(tree);
		dynsec__command_reply(j_responses, context, "listClients", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	i = 0;
	HASH_ITER(hh, local_clients, client, client_tmp){
		if(i>=offset){
			j_client = add_client_to_json(client, verbose);
			if(j_client == NULL){
				cJSON_Delete(tree);
				dynsec__command_reply(j_responses, context, "listClients", "Internal error", correlation_data);
				return MOSQ_ERR_NOMEM;
			}
			cJSON_AddItemToArray(j_clients, j_client);

			if(count >= 0){
				count--;
				if(count <= 0){
					break;
				}
			}
		}
		i++;
	}
	cJSON_AddItemToArray(j_responses, tree);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | listClients | verbose=%s | count=%d | offset=%d",
			admin_clientid, admin_username, verbose?"true":"false", count, offset);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_clients__process_add_role(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *username, *rolename;
	struct dynsec__client *client;
	struct dynsec__role *role;
	int priority;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "username", &username, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addClientRole", "Invalid/missing username", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(username, (int)strlen(username)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addClientRole", "Username not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addClientRole", "Invalid/missing rolename", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addClientRole", "Role name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	json_get_int(command, "priority", &priority, true, -1);

	client = dynsec_clients__find(username);
	if(client == NULL){
		dynsec__command_reply(j_responses, context, "addClientRole", "Client not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	role = dynsec_roles__find(rolename);
	if(role == NULL){
		dynsec__command_reply(j_responses, context, "addClientRole", "Role not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	if(dynsec_rolelist__client_add(client, role, priority) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addClientRole", "Internal error", correlation_data);
		return MOSQ_ERR_UNKNOWN;
	}
	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "addClientRole", NULL, correlation_data);

	/* Enforce any changes */
	mosquitto_kick_client_by_username(username, false);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | addClientRole | username=%s | rolename=%s | priority=%d",
			admin_clientid, admin_username, username, rolename, priority);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_clients__process_remove_role(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *username, *rolename;
	struct dynsec__client *client;
	struct dynsec__role *role;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "username", &username, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeClientRole", "Invalid/missing username", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(username, (int)strlen(username)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeClientRole", "Username not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeClientRole", "Invalid/missing rolename", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeClientRole", "Role name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}


	client = dynsec_clients__find(username);
	if(client == NULL){
		dynsec__command_reply(j_responses, context, "removeClientRole", "Client not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	role = dynsec_roles__find(rolename);
	if(role == NULL){
		dynsec__command_reply(j_responses, context, "removeClientRole", "Role not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	dynsec_rolelist__client_remove(client, role);
	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "removeClientRole", NULL, correlation_data);

	/* Enforce any changes */
	mosquitto_kick_client_by_username(username, false);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | removeClientRole | username=%s | rolename=%s",
			admin_clientid, admin_username, username, rolename);

	return MOSQ_ERR_SUCCESS;
}
