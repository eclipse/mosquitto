/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "json_help.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"

#include "dynamic_security.h"

static mosquitto_plugin_id_t *plg_id = NULL;
static char *config_file = NULL;
struct dynsec__acl_default_access default_access = {false, false, false, false};

void dynsec__command_reply(cJSON *j_responses, struct mosquitto *context, const char *command, const char *error, const char *correlation_data)
{
	cJSON *j_response;

	j_response = cJSON_CreateObject();
	if(j_response == NULL) return;

	if(cJSON_AddStringToObject(j_response, "command", command) == NULL
			|| (error && cJSON_AddStringToObject(j_response, "error", error) == NULL)
			|| (correlation_data && cJSON_AddStringToObject(j_response, "correlationData", correlation_data) == NULL)
			){

		cJSON_Delete(j_response);
		return;
	}

	cJSON_AddItemToArray(j_responses, j_response);
}


static void send_response(cJSON *tree)
{
	char *payload;

	payload = cJSON_PrintUnformatted(tree);
	cJSON_Delete(tree);
	if(payload == NULL) return;

	mosquitto_broker_publish(NULL, "$CONTROL/dynamic-security/v1/response",
			strlen(payload), payload, 0, 0, NULL);
}


static int dynsec_control_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_control *ed = event_data;
	cJSON *tree, *commands;
	cJSON *j_response_tree, *j_responses;

	/* Create object for responses */
	j_response_tree = cJSON_CreateObject();
	if(j_response_tree == NULL){
		return MOSQ_ERR_NOMEM;
	}
	j_responses = cJSON_CreateArray();
	if(j_responses == NULL){
		cJSON_Delete(j_response_tree);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToObject(j_response_tree, "responses", j_responses);


	/* Parse cJSON tree */
	tree = cJSON_ParseWithLength(ed->payload, ed->payloadlen);
	if(tree == NULL){
		dynsec__command_reply(j_responses, ed->client, "Unknown command", "Payload not valid JSON", NULL);
		send_response(j_response_tree);
		return MOSQ_ERR_SUCCESS;
	}
	commands = cJSON_GetObjectItem(tree, "commands");
	if(commands == NULL || !cJSON_IsArray(commands)){
		cJSON_Delete(tree);
		dynsec__command_reply(j_responses, ed->client, "Unknown command", "Invalid/missing commands", NULL);
		send_response(j_response_tree);
		return MOSQ_ERR_SUCCESS;
	}

	/* Handle commands */
	dynsec__handle_control(j_responses, ed->client, commands);
	cJSON_Delete(tree);

	send_response(j_response_tree);

	return MOSQ_ERR_SUCCESS;
}

int dynsec__process_default_acl_access(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	cJSON *j_actions, *j_action, *j_acltype, *j_allow;
	bool allow;

	j_actions = cJSON_GetObjectItem(command, "acls");
	if(j_actions == NULL || !cJSON_IsArray(j_actions)){
		dynsec__command_reply(j_responses, context, "setDefaultACLAccess", "Missing/invalid actions array", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	cJSON_ArrayForEach(j_action, j_actions){
		j_acltype = cJSON_GetObjectItem(j_action, "acltype");
		j_allow = cJSON_GetObjectItem(j_action, "allow");
		if(j_acltype && cJSON_IsString(j_acltype)
					&& j_allow && cJSON_IsBool(j_allow)){

			allow = cJSON_IsTrue(j_allow);

			if(!strcasecmp(j_acltype->valuestring, "publishClientToBroker")){
				default_access.publish_c2b = allow;
			}else if(!strcasecmp(j_acltype->valuestring, "publishBrokerToClient")){
				default_access.publish_b2c = allow;
			}else if(!strcasecmp(j_acltype->valuestring, "subscribe")){
				default_access.subscribe = allow;
			}else if(!strcasecmp(j_acltype->valuestring, "unsubscribe")){
				default_access.unsubscribe = allow;
			}
		}
	}

	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "setDefaultACLAccess", NULL, correlation_data);
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)
{
	int i;

	for(i=0; i<supported_version_count; i++){
		if(supported_versions[i] == 5){
			return 5;
		}
	}
	return -1;
}

static int dynsec__general_config_load(cJSON *tree)
{
	cJSON *j_default_access, *jtmp;

	j_default_access = cJSON_GetObjectItem(tree, "defaultACLAccess");
	if(j_default_access && cJSON_IsObject(j_default_access)){
		jtmp = cJSON_GetObjectItem(j_default_access, "publishClientToBroker");
		if(jtmp && cJSON_IsBool(jtmp)){
			default_access.publish_c2b = cJSON_IsTrue(jtmp);
		}else{
			default_access.publish_c2b = false;
		}

		jtmp = cJSON_GetObjectItem(j_default_access, "publishBrokerToClient");
		if(jtmp && cJSON_IsBool(jtmp)){
			default_access.publish_b2c = cJSON_IsTrue(jtmp);
		}else{
			default_access.publish_b2c = false;
		}

		jtmp = cJSON_GetObjectItem(j_default_access, "subscribe");
		if(jtmp && cJSON_IsBool(jtmp)){
			default_access.subscribe = cJSON_IsTrue(jtmp);
		}else{
			default_access.subscribe = false;
		}

		jtmp = cJSON_GetObjectItem(j_default_access, "unsubscribe");
		if(jtmp && cJSON_IsBool(jtmp)){
			default_access.unsubscribe = cJSON_IsTrue(jtmp);
		}else{
			default_access.unsubscribe = false;
		}
	}
	return MOSQ_ERR_SUCCESS;
}

static int dynsec__general_config_save(cJSON *tree)
{
	cJSON *j_default_access;

	j_default_access = cJSON_CreateObject();
	if(j_default_access == NULL){
		return 1;
	}
	cJSON_AddItemToObject(tree, "defaultACLAccess", j_default_access);

	if(cJSON_AddBoolToObject(j_default_access, "publishClientToBroker", default_access.publish_c2b) == NULL
			|| cJSON_AddBoolToObject(j_default_access, "publishBrokerToClient", default_access.publish_b2c) == NULL
			|| cJSON_AddBoolToObject(j_default_access, "subscribe", default_access.subscribe) == NULL
			|| cJSON_AddBoolToObject(j_default_access, "unsubscribe", default_access.unsubscribe) == NULL
			){

		return 1;
	}

	return MOSQ_ERR_SUCCESS;
}

static int dynsec__config_load(void)
{
	FILE *fptr;
	long flen;
	char *json_str;
	cJSON *tree;

	/* Save to file */
	fptr = fopen(config_file, "rt");
	if(fptr == NULL){
		return 1;
	}

	fseek(fptr, 0, SEEK_END);
	flen = ftell(fptr);
	fseek(fptr, 0, SEEK_SET);
	json_str = mosquitto_calloc(flen+1, sizeof(char));
	if(json_str == NULL){
		fclose(fptr);
		return 1;
	}
	if(fread(json_str, 1, flen, fptr) != flen){
		fclose(fptr);
		return 1;
	}
	fclose(fptr);

	tree = cJSON_Parse(json_str);
	mosquitto_free(json_str);
	if(tree == NULL){
		return 1;
	}

	if(dynsec__general_config_load(tree)){
		cJSON_Delete(tree);
		return 1;
	}

	if(dynsec_roles__config_load(tree)){
		cJSON_Delete(tree);
		return 1;
	}

	if(dynsec_clients__config_load(tree)){
		cJSON_Delete(tree);
		return 1;
	}

	if(dynsec_groups__config_load(tree)){
		cJSON_Delete(tree);
		return 1;
	}

	cJSON_Delete(tree);
	return 0;
}


void dynsec__config_save(void)
{
	cJSON *tree;
	int file_path_len;
	char *file_path;
	FILE *fptr;
	int json_str_len;
	char *json_str;

	tree = cJSON_CreateObject();
	if(tree == NULL) return;

	if(dynsec__general_config_save(tree)){
		cJSON_Delete(tree);
		return;
	}

	if(dynsec_clients__config_save(tree)){
		cJSON_Delete(tree);
		return;
	}

	if(dynsec_groups__config_save(tree)){
		cJSON_Delete(tree);
		return;
	}

	if(dynsec_roles__config_save(tree)){
		cJSON_Delete(tree);
		return;
	}

	/* Print json to string */
	json_str = cJSON_Print(tree);
	if(json_str == NULL){
		cJSON_Delete(tree);
		return;
	}
	cJSON_Delete(tree);
	json_str_len = strlen(json_str);

	/* Save to file */
	file_path_len = strlen(config_file) + 1;
	file_path = mosquitto_malloc(file_path_len);
	if(file_path == NULL){
		mosquitto_free(json_str);
		return;
	}
	snprintf(file_path, file_path_len, "%s.new", config_file);

	fptr = fopen(file_path, "wt");
	if(fptr == NULL){
		mosquitto_free(json_str);
		mosquitto_free(file_path);
		return;
	}
	fwrite(json_str, 1, json_str_len, fptr);
	mosquitto_free(json_str);
	fclose(fptr);

	/* Everything is ok, so move new file over proper file */
	rename(file_path, config_file);
	mosquitto_free(file_path);
}


int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *options, int option_count)
{
	int i;

	for(i=0; i<option_count; i++){
		if(!strcasecmp(options[i].key, "config_file")){
			config_file = mosquitto_strdup(options[i].value);
			if(config_file == NULL){
				return MOSQ_ERR_NOMEM;
			}
			break;
		}
	}
	if(config_file == NULL){
		mosquitto_log_printf(MOSQ_LOG_WARNING, "Warning: Dynamic security plugin has no plugin_opt_config_file defined. The plugin will not be activated.");
		return MOSQ_ERR_SUCCESS;
	}

	plg_id = identifier;

	dynsec__config_load();
	mosquitto_callback_register(plg_id, MOSQ_EVT_CONTROL, dynsec_control_callback, "$CONTROL/dynamic-security/v1", NULL);
	mosquitto_callback_register(plg_id, MOSQ_EVT_BASIC_AUTH, dynsec_auth__basic_auth_callback, NULL, NULL);
	mosquitto_callback_register(plg_id, MOSQ_EVT_ACL_CHECK, dynsec__acl_check_callback, NULL, NULL);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *options, int option_count)
{
	if(plg_id){
		mosquitto_callback_unregister(plg_id, MOSQ_EVT_CONTROL, dynsec_control_callback, "$CONTROL/dynamic-security/v1");
		mosquitto_callback_unregister(plg_id, MOSQ_EVT_BASIC_AUTH, dynsec_auth__basic_auth_callback, NULL);
		mosquitto_callback_unregister(plg_id, MOSQ_EVT_ACL_CHECK, dynsec__acl_check_callback, NULL);
	}
	dynsec_groups__cleanup();
	dynsec_clients__cleanup();
	dynsec_roles__cleanup();

	mosquitto_free(config_file);
	config_file = NULL;
	return MOSQ_ERR_SUCCESS;
}

/* ################################################################
 * #
 * # $CONTROL/dynamic-security/v1 handler
 * #
 * ################################################################ */

int dynsec__handle_control(cJSON *j_responses, struct mosquitto *context, cJSON *commands)
{
	int rc = MOSQ_ERR_SUCCESS;
	cJSON *aiter;
	char *command;
	char *correlation_data = NULL;

	cJSON_ArrayForEach(aiter, commands){
		if(cJSON_IsObject(aiter)){
			if(json_get_string(aiter, "command", &command, false) == MOSQ_ERR_SUCCESS){
				if(json_get_string(aiter, "correlationData", &correlation_data, true) != MOSQ_ERR_SUCCESS){
					dynsec__command_reply(j_responses, context, command, "Invalid correlationData data type.", NULL);
					return MOSQ_ERR_INVAL;
				}

				/* Plugin */
				if(!strcasecmp(command, "setDefaultACLAccess")){
					rc = dynsec__process_default_acl_access(j_responses, context, aiter, correlation_data);

				/* Clients */
				}else if(!strcasecmp(command, "createClient")){
					rc = dynsec_clients__process_create(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "deleteClient")){
					rc = dynsec_clients__process_delete(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "getClient")){
					rc = dynsec_clients__process_get(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "listClients")){
					rc = dynsec_clients__process_list(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "modifyClient")){
					rc = dynsec_clients__process_modify(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "setClientPassword")){
					rc = dynsec_clients__process_set_password(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "addClientRole")){
					rc = dynsec_clients__process_add_role(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "removeClientRole")){
					rc = dynsec_clients__process_remove_role(j_responses, context, aiter, correlation_data);

				/* Groups */
				}else if(!strcasecmp(command, "addGroupClient")){
					rc = dynsec_groups__process_add_client(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "createGroup")){
					rc = dynsec_groups__process_create(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "deleteGroup")){
					rc = dynsec_groups__process_delete(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "getGroup")){
					rc = dynsec_groups__process_get(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "listGroups")){
					rc = dynsec_groups__process_list(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "modifyGroup")){
					rc = dynsec_groups__process_modify(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "removeGroupClient")){
					rc = dynsec_groups__process_remove_client(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "addGroupRole")){
					rc = dynsec_groups__process_add_role(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "removeGroupRole")){
					rc = dynsec_groups__process_remove_role(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "setAnonymousGroup")){
					rc = dynsec_groups__process_set_anonymous_group(j_responses, context, aiter, correlation_data);

				/* Roles */
				}else if(!strcasecmp(command, "createRole")){
					rc = dynsec_roles__process_create(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "getRole")){
					rc = dynsec_roles__process_get(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "listRoles")){
					rc = dynsec_roles__process_list(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "modifyRole")){
					rc = dynsec_roles__process_modify(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "deleteRole")){
					rc = dynsec_roles__process_delete(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "addRoleACL")){
					rc = dynsec_roles__process_add_acl(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "removeRoleACL")){
					rc = dynsec_roles__process_remove_acl(j_responses, context, aiter, correlation_data);

				/* Unknown */
				}else{
					dynsec__command_reply(j_responses, context, command, "Unknown command", correlation_data);
					rc = MOSQ_ERR_INVAL;
				}
			}else{
				dynsec__command_reply(j_responses, context, "Unknown command", "Missing command", correlation_data);
				rc = MOSQ_ERR_INVAL;
			}
		}else{
			dynsec__command_reply(j_responses, context, "Unknown command", "Command not an object", correlation_data);
			rc = MOSQ_ERR_INVAL;
		}
	}

	return rc;
}
