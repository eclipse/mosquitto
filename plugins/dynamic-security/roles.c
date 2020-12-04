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
#include <string.h>
#include <uthash.h>
#include <utlist.h>

#include "dynamic_security.h"
#include "json_help.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"


static cJSON *add_role_to_json(struct dynsec__role *role, bool verbose);
static void role__remove_all_clients(struct dynsec__role *role);

/* ################################################################
 * #
 * # Local variables
 * #
 * ################################################################ */

static struct dynsec__role *local_roles = NULL;


/* ################################################################
 * #
 * # Utility functions
 * #
 * ################################################################ */

static int role_cmp(void *a, void *b)
{
	struct dynsec__role *role_a = a;
	struct dynsec__role *role_b = b;

	return strcmp(role_a->rolename, role_b->rolename);
}


static void role__free_acl(struct dynsec__acl **acl, struct dynsec__acl *item)
{
	HASH_DELETE(hh, *acl, item);
	mosquitto_free(item->topic);
	mosquitto_free(item);
}

static void role__free_all_acls(struct dynsec__acl **acl)
{
	struct dynsec__acl *iter, *tmp;

	HASH_ITER(hh, *acl, iter, tmp){
		role__free_acl(acl, iter);
	}
}

static void role__free_item(struct dynsec__role *role, bool remove_from_hash)
{
	if(remove_from_hash){
		HASH_DEL(local_roles, role);
	}
	dynsec_clientlist__cleanup(&role->clientlist);
	dynsec_grouplist__cleanup(&role->grouplist);
	mosquitto_free(role->text_name);
	mosquitto_free(role->text_description);
	mosquitto_free(role->rolename);
	role__free_all_acls(&role->acls.publish_c_send);
	role__free_all_acls(&role->acls.publish_c_recv);
	role__free_all_acls(&role->acls.subscribe_literal);
	role__free_all_acls(&role->acls.subscribe_pattern);
	role__free_all_acls(&role->acls.unsubscribe_literal);
	role__free_all_acls(&role->acls.unsubscribe_pattern);
	mosquitto_free(role);
}

struct dynsec__role *dynsec_roles__find(const char *rolename)
{
	struct dynsec__role *role = NULL;

	if(rolename){
		HASH_FIND(hh, local_roles, rolename, strlen(rolename), role);
	}
	return role;
}


void dynsec_roles__cleanup(void)
{
	struct dynsec__role *role, *role_tmp;

	HASH_ITER(hh, local_roles, role, role_tmp){
		role__free_item(role, true);
	}
}


static void role__kick_all(struct dynsec__role *role)
{
	struct dynsec__grouplist *grouplist, *grouplist_tmp;

	dynsec_clientlist__kick_all(role->clientlist);

	HASH_ITER(hh, role->grouplist, grouplist, grouplist_tmp){
		if(grouplist->group == dynsec_anonymous_group){
			mosquitto_kick_client_by_username(NULL, false);
		}
		dynsec_clientlist__kick_all(grouplist->group->clientlist);
	}
}


/* ################################################################
 * #
 * # Config file load and save
 * #
 * ################################################################ */


static int add_single_acl_to_json(cJSON *j_array, const char *acl_type, struct dynsec__acl *acl)
{
	struct dynsec__acl *iter, *tmp;
	cJSON *j_acl;

	HASH_ITER(hh, acl, iter, tmp){
		j_acl = cJSON_CreateObject();
		if(j_acl == NULL){
			return 1;
		}
		cJSON_AddItemToArray(j_array, j_acl);

		if(cJSON_AddStringToObject(j_acl, "acltype", acl_type) == NULL
				|| cJSON_AddStringToObject(j_acl, "topic", iter->topic) == NULL
				|| cJSON_AddIntToObject(j_acl, "priority", iter->priority) == NULL
				|| cJSON_AddBoolToObject(j_acl, "allow", iter->allow) == NULL
				){

			return 1;
		}
	}


	return 0;
}

static int add_acls_to_json(cJSON *j_role, struct dynsec__role *role)
{
	cJSON *j_acls;

	if((j_acls = cJSON_AddArrayToObject(j_role, "acls")) == NULL){
		return 1;
	}

	if(add_single_acl_to_json(j_acls, ACL_TYPE_PUB_C_SEND, role->acls.publish_c_send) != MOSQ_ERR_SUCCESS
			|| add_single_acl_to_json(j_acls, ACL_TYPE_PUB_C_RECV, role->acls.publish_c_recv) != MOSQ_ERR_SUCCESS
			|| add_single_acl_to_json(j_acls, ACL_TYPE_SUB_LITERAL, role->acls.subscribe_literal) != MOSQ_ERR_SUCCESS
			|| add_single_acl_to_json(j_acls, ACL_TYPE_SUB_PATTERN, role->acls.subscribe_pattern) != MOSQ_ERR_SUCCESS
			|| add_single_acl_to_json(j_acls, ACL_TYPE_UNSUB_LITERAL, role->acls.unsubscribe_literal) != MOSQ_ERR_SUCCESS
			|| add_single_acl_to_json(j_acls, ACL_TYPE_UNSUB_PATTERN, role->acls.unsubscribe_pattern) != MOSQ_ERR_SUCCESS
			){

		return 1;
	}
	return 0;
}

int dynsec_roles__config_save(cJSON *tree)
{
	cJSON *j_roles, *j_role;
	struct dynsec__role *role, *role_tmp;

	if((j_roles = cJSON_AddArrayToObject(tree, "roles")) == NULL){
		return 1;
	}

	HASH_ITER(hh, local_roles, role, role_tmp){
		j_role = add_role_to_json(role, true);
		if(j_role == NULL){
			return 1;
		}
		cJSON_AddItemToArray(j_roles, j_role);
	}

	return 0;
}


static int insert_acl_cmp(struct dynsec__acl *a, struct dynsec__acl *b)
{
	return b->priority - a->priority;
}


int dynsec_roles__acl_load(cJSON *j_acls, const char *key, struct dynsec__acl **acllist)
{
	cJSON *j_acl, *j_type, *jtmp;
	struct dynsec__acl *acl;

	cJSON_ArrayForEach(j_acl, j_acls){
		j_type = cJSON_GetObjectItem(j_acl, "acltype");
		if(j_type == NULL || !cJSON_IsString(j_type) || strcasecmp(j_type->valuestring, key) != 0){
			continue;
		}
		acl = mosquitto_calloc(1, sizeof(struct dynsec__acl));
		if(acl == NULL){
			return 1;
		}

		json_get_int(j_acl, "priority", &acl->priority, true, 0);
		json_get_bool(j_acl, "allow", &acl->allow, true, false);

		jtmp = cJSON_GetObjectItem(j_acl, "allow");
		if(jtmp && cJSON_IsBool(jtmp)){
			acl->allow = cJSON_IsTrue(jtmp);
		}

		jtmp = cJSON_GetObjectItem(j_acl, "topic");
		if(jtmp && cJSON_IsString(jtmp)){
			acl->topic = mosquitto_strdup(jtmp->valuestring);
		}

		if(acl->topic == NULL){
			mosquitto_free(acl);
			continue;
		}

		HASH_ADD_KEYPTR_INORDER(hh, *acllist, acl->topic, strlen(acl->topic), acl, insert_acl_cmp);
	}

	return 0;
}


int dynsec_roles__config_load(cJSON *tree)
{
	cJSON *j_roles, *j_role, *jtmp, *j_acls;
	struct dynsec__role *role;

	j_roles = cJSON_GetObjectItem(tree, "roles");
	if(j_roles == NULL){
		return 0;
	}

	if(cJSON_IsArray(j_roles) == false){
		return 1;
	}

	cJSON_ArrayForEach(j_role, j_roles){
		if(cJSON_IsObject(j_role) == true){
			role = mosquitto_calloc(1, sizeof(struct dynsec__role));
			if(role == NULL){
				return MOSQ_ERR_NOMEM;
			}

			/* Role name */
			jtmp = cJSON_GetObjectItem(j_role, "rolename");
			if(jtmp == NULL){
				mosquitto_free(role);
				continue;
			}
			role->rolename = mosquitto_strdup(jtmp->valuestring);
			if(role->rolename == NULL){
				mosquitto_free(role);
				continue;
			}

			/* Text name */
			jtmp = cJSON_GetObjectItem(j_role, "textname");
			if(jtmp != NULL){
				role->text_name = mosquitto_strdup(jtmp->valuestring);
				if(role->text_name == NULL){
					mosquitto_free(role->rolename);
					mosquitto_free(role);
					continue;
				}
			}

			/* Text description */
			jtmp = cJSON_GetObjectItem(j_role, "textdescription");
			if(jtmp != NULL){
				role->text_description = mosquitto_strdup(jtmp->valuestring);
				if(role->text_description == NULL){
					mosquitto_free(role->text_name);
					mosquitto_free(role->rolename);
					mosquitto_free(role);
					continue;
				}
			}

			/* ACLs */
			j_acls = cJSON_GetObjectItem(j_role, "acls");
			if(j_acls && cJSON_IsArray(j_acls)){
				if(dynsec_roles__acl_load(j_acls, ACL_TYPE_PUB_C_SEND, &role->acls.publish_c_send) != 0
						|| dynsec_roles__acl_load(j_acls, ACL_TYPE_PUB_C_RECV, &role->acls.publish_c_recv) != 0
						|| dynsec_roles__acl_load(j_acls, ACL_TYPE_SUB_LITERAL, &role->acls.subscribe_literal) != 0
						|| dynsec_roles__acl_load(j_acls, ACL_TYPE_SUB_PATTERN, &role->acls.subscribe_pattern) != 0
						|| dynsec_roles__acl_load(j_acls, ACL_TYPE_UNSUB_LITERAL, &role->acls.unsubscribe_literal) != 0
						|| dynsec_roles__acl_load(j_acls, ACL_TYPE_UNSUB_PATTERN, &role->acls.unsubscribe_pattern) != 0
						){

					mosquitto_free(role->rolename);
					mosquitto_free(role);
					continue;
				}
			}

			HASH_ADD_KEYPTR(hh, local_roles, role->rolename, strlen(role->rolename), role);
		}
	}
	HASH_SORT(local_roles, role_cmp);

	return 0;
}


int dynsec_roles__process_create(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *rolename;
	char *text_name, *text_description;
	struct dynsec__role *role;
	int rc = MOSQ_ERR_SUCCESS;
	cJSON *j_acls;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createRole", "Invalid/missing rolename", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createRole", "Role name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "textname", &text_name, true) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createRole", "Invalid/missing textname", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "textdescription", &text_description, true) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createRole", "Invalid/missing textdescription", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	role = dynsec_roles__find(rolename);
	if(role){
		dynsec__command_reply(j_responses, context, "createRole", "Role already exists", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	role = mosquitto_calloc(1, sizeof(struct dynsec__role));
	if(role == NULL){
		dynsec__command_reply(j_responses, context, "createRole", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}
	role->rolename = mosquitto_strdup(rolename);
	if(role->rolename == NULL){
		dynsec__command_reply(j_responses, context, "createRole", "Internal error", correlation_data);
		rc = MOSQ_ERR_NOMEM;
		goto error;
	}
	if(text_name){
		role->text_name = mosquitto_strdup(text_name);
		if(role->text_name == NULL){
			dynsec__command_reply(j_responses, context, "createRole", "Internal error", correlation_data);
			rc = MOSQ_ERR_NOMEM;
			goto error;
		}
	}
	if(text_description){
		role->text_description = mosquitto_strdup(text_description);
		if(role->text_description == NULL){
			dynsec__command_reply(j_responses, context, "createRole", "Internal error", correlation_data);
			rc = MOSQ_ERR_NOMEM;
			goto error;
		}
	}

	/* ACLs */
	j_acls = cJSON_GetObjectItem(command, "acls");
	if(j_acls && cJSON_IsArray(j_acls)){
		if(dynsec_roles__acl_load(j_acls, ACL_TYPE_PUB_C_SEND, &role->acls.publish_c_send) != 0
				|| dynsec_roles__acl_load(j_acls, ACL_TYPE_PUB_C_RECV, &role->acls.publish_c_recv) != 0
				|| dynsec_roles__acl_load(j_acls, ACL_TYPE_SUB_LITERAL, &role->acls.subscribe_literal) != 0
				|| dynsec_roles__acl_load(j_acls, ACL_TYPE_SUB_PATTERN, &role->acls.subscribe_pattern) != 0
				|| dynsec_roles__acl_load(j_acls, ACL_TYPE_UNSUB_LITERAL, &role->acls.unsubscribe_literal) != 0
				|| dynsec_roles__acl_load(j_acls, ACL_TYPE_UNSUB_PATTERN, &role->acls.unsubscribe_pattern) != 0
				){

			dynsec__command_reply(j_responses, context, "createRole", "Internal error", correlation_data);
			rc = MOSQ_ERR_NOMEM;
			goto error;
		}
	}


	HASH_ADD_KEYPTR_INORDER(hh, local_roles, role->rolename, strlen(role->rolename), role, role_cmp);

	dynsec__config_save();

	dynsec__command_reply(j_responses, context, "createRole", NULL, correlation_data);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | createRole | rolename=%s",
			admin_clientid, admin_username, rolename);

	return MOSQ_ERR_SUCCESS;
error:
	if(role){
		role__free_item(role, false);
	}
	return rc;
}


static void role__remove_all_clients(struct dynsec__role *role)
{
	struct dynsec__clientlist *clientlist, *clientlist_tmp;

	HASH_ITER(hh, role->clientlist, clientlist, clientlist_tmp){
		mosquitto_kick_client_by_username(clientlist->client->username, false);

		dynsec_rolelist__client_remove(clientlist->client, role);
	}
}

static void role__remove_all_groups(struct dynsec__role *role)
{
	struct dynsec__grouplist *grouplist, *grouplist_tmp;

	HASH_ITER(hh, role->grouplist, grouplist, grouplist_tmp){
		if(grouplist->group == dynsec_anonymous_group){
			mosquitto_kick_client_by_username(NULL, false);
		}
		dynsec_clientlist__kick_all(grouplist->group->clientlist);

		dynsec_rolelist__group_remove(grouplist->group, role);
	}
}

int dynsec_roles__process_delete(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *rolename;
	struct dynsec__role *role;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "deleteRole", "Invalid/missing rolename", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "deleteRole", "Role name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	role = dynsec_roles__find(rolename);
	if(role){
		role__remove_all_clients(role);
		role__remove_all_groups(role);
		role__free_item(role, true);
		dynsec__config_save();
		dynsec__command_reply(j_responses, context, "deleteRole", NULL, correlation_data);

		admin_clientid = mosquitto_client_id(context);
		admin_username = mosquitto_client_username(context);
		mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | deleteRole | rolename=%s",
				admin_clientid, admin_username, rolename);

		return MOSQ_ERR_SUCCESS;
	}else{
		dynsec__command_reply(j_responses, context, "deleteRole", "Role not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}
}


static cJSON *add_role_to_json(struct dynsec__role *role, bool verbose)
{
	cJSON *j_role = NULL;

	if(verbose){
		j_role = cJSON_CreateObject();
		if(j_role == NULL){
			return NULL;
		}

		if(cJSON_AddStringToObject(j_role, "rolename", role->rolename) == NULL
				|| (role->text_name && cJSON_AddStringToObject(j_role, "textname", role->text_name) == NULL)
				|| (role->text_description && cJSON_AddStringToObject(j_role, "textdescription", role->text_description) == NULL)
				){

			cJSON_Delete(j_role);
			return NULL;
		}
		if(add_acls_to_json(j_role, role)){
			cJSON_Delete(j_role);
			return NULL;
		}
	}else{
		j_role = cJSON_CreateString(role->rolename);
		if(j_role == NULL){
			return NULL;
		}
	}
	return j_role;
}

int dynsec_roles__process_list(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	bool verbose;
	struct dynsec__role *role, *role_tmp;
	cJSON *tree, *j_roles, *j_role, *j_data;
	int i, count, offset;
	const char *admin_clientid, *admin_username;

	json_get_bool(command, "verbose", &verbose, true, false);
	json_get_int(command, "count", &count, true, -1);
	json_get_int(command, "offset", &offset, true, 0);

	tree = cJSON_CreateObject();
	if(tree == NULL){
		dynsec__command_reply(j_responses, context, "listRoles", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	if(cJSON_AddStringToObject(tree, "command", "listRoles") == NULL
			|| (j_data = cJSON_AddObjectToObject(tree, "data")) == NULL
			|| cJSON_AddIntToObject(j_data, "totalCount", (int)HASH_CNT(hh, local_roles)) == NULL
			|| (j_roles = cJSON_AddArrayToObject(j_data, "roles")) == NULL
			|| (correlation_data && cJSON_AddStringToObject(tree, "correlationData", correlation_data) == NULL)
			){

		cJSON_Delete(tree);
		dynsec__command_reply(j_responses, context, "listRoles", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	i = 0;
	HASH_ITER(hh, local_roles, role, role_tmp){
		if(i>=offset){
			j_role = add_role_to_json(role, verbose);
			if(j_role == NULL){
				cJSON_Delete(tree);
				dynsec__command_reply(j_responses, context, "listRoles", "Internal error", correlation_data);
				return MOSQ_ERR_NOMEM;
			}
			cJSON_AddItemToArray(j_roles, j_role);

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
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | listRoles | verbose=%s | count=%d | offset=%d",
			admin_clientid, admin_username, verbose?"true":"false", count, offset);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_roles__process_add_acl(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *rolename;
	char *topic;
	struct dynsec__role *role;
	cJSON *jtmp, *j_acltype;
	struct dynsec__acl **acllist, *acl;
	int rc;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addRoleACL", "Invalid/missing rolename", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addRoleACL", "Role name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	role = dynsec_roles__find(rolename);
	if(role == NULL){
		dynsec__command_reply(j_responses, context, "addRoleACL", "Role not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	j_acltype = cJSON_GetObjectItem(command, "acltype");
	if(j_acltype == NULL || !cJSON_IsString(j_acltype)){
		dynsec__command_reply(j_responses, context, "addRoleACL", "Invalid/missing acltype", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}
	if(!strcasecmp(j_acltype->valuestring, ACL_TYPE_PUB_C_SEND)){
		acllist = &role->acls.publish_c_send;
	}else if(!strcasecmp(j_acltype->valuestring, ACL_TYPE_PUB_C_RECV)){
		acllist = &role->acls.publish_c_recv;
	}else if(!strcasecmp(j_acltype->valuestring, ACL_TYPE_SUB_LITERAL)){
		acllist = &role->acls.subscribe_literal;
	}else if(!strcasecmp(j_acltype->valuestring, ACL_TYPE_SUB_PATTERN)){
		acllist = &role->acls.subscribe_pattern;
	}else if(!strcasecmp(j_acltype->valuestring, ACL_TYPE_UNSUB_LITERAL)){
		acllist = &role->acls.unsubscribe_literal;
	}else if(!strcasecmp(j_acltype->valuestring, ACL_TYPE_UNSUB_PATTERN)){
		acllist = &role->acls.unsubscribe_pattern;
	}else{
		dynsec__command_reply(j_responses, context, "addRoleACL", "Unknown acltype", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	jtmp = cJSON_GetObjectItem(command, "topic");
	if(jtmp && cJSON_IsString(jtmp)){
		if(mosquitto_validate_utf8(jtmp->valuestring, (int)strlen(jtmp->valuestring)) != MOSQ_ERR_SUCCESS){
			dynsec__command_reply(j_responses, context, "addRoleACL", "Topic not valid UTF-8", correlation_data);
			return MOSQ_ERR_INVAL;
		}
		rc = mosquitto_sub_topic_check(jtmp->valuestring);
		if(rc != MOSQ_ERR_SUCCESS){
			dynsec__command_reply(j_responses, context, "addRoleACL", "Invalid ACL topic", correlation_data);
			return MOSQ_ERR_INVAL;
		}
		topic = mosquitto_strdup(jtmp->valuestring);
		if(topic == NULL){
			dynsec__command_reply(j_responses, context, "addRoleACL", "Internal error", correlation_data);
			return MOSQ_ERR_SUCCESS;
		}
	}else{
		dynsec__command_reply(j_responses, context, "addRoleACL", "Invalid/missing topic", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	HASH_FIND(hh, *acllist, topic, strlen(topic), acl);
	if(acl){
		mosquitto_free(topic);
		dynsec__command_reply(j_responses, context, "addRoleACL", "ACL with this topic already exists", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	acl = mosquitto_calloc(1, sizeof(struct dynsec__acl));
	if(acl == NULL){
		mosquitto_free(topic);
		dynsec__command_reply(j_responses, context, "addRoleACL", "Internal error", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}
	acl->topic = topic;

	json_get_int(command, "priority", &acl->priority, true, 0);
	json_get_bool(command, "allow", &acl->allow, true, false);

	HASH_ADD_KEYPTR_INORDER(hh, *acllist, acl->topic, strlen(acl->topic), acl, insert_acl_cmp);
	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "addRoleACL", NULL, correlation_data);

	role__kick_all(role);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | addRoleACL | rolename=%s | acltype=%s | topic=%s | priority=%d | allow=%s",
			admin_clientid, admin_username, rolename, j_acltype->valuestring, topic, acl->priority, acl->allow?"true":"false");

	return MOSQ_ERR_SUCCESS;
}


int dynsec_roles__process_remove_acl(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *rolename;
	struct dynsec__role *role;
	struct dynsec__acl **acllist, *acl;
	char *topic;
	cJSON *j_acltype;
	int rc;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeRoleACL", "Invalid/missing rolename", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeRoleACL", "Role name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	role = dynsec_roles__find(rolename);
	if(role == NULL){
		dynsec__command_reply(j_responses, context, "removeRoleACL", "Role not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	j_acltype = cJSON_GetObjectItem(command, "acltype");
	if(j_acltype == NULL || !cJSON_IsString(j_acltype)){
		dynsec__command_reply(j_responses, context, "removeRoleACL", "Invalid/missing acltype", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}
	if(!strcasecmp(j_acltype->valuestring, ACL_TYPE_PUB_C_SEND)){
		acllist = &role->acls.publish_c_send;
	}else if(!strcasecmp(j_acltype->valuestring, ACL_TYPE_PUB_C_RECV)){
		acllist = &role->acls.publish_c_recv;
	}else if(!strcasecmp(j_acltype->valuestring, ACL_TYPE_SUB_LITERAL)){
		acllist = &role->acls.subscribe_literal;
	}else if(!strcasecmp(j_acltype->valuestring, ACL_TYPE_SUB_PATTERN)){
		acllist = &role->acls.subscribe_pattern;
	}else if(!strcasecmp(j_acltype->valuestring, ACL_TYPE_UNSUB_LITERAL)){
		acllist = &role->acls.unsubscribe_literal;
	}else if(!strcasecmp(j_acltype->valuestring, ACL_TYPE_UNSUB_PATTERN)){
		acllist = &role->acls.unsubscribe_pattern;
	}else{
		dynsec__command_reply(j_responses, context, "removeRoleACL", "Unknown acltype", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	if(json_get_string(command, "topic", &topic, false)){
		dynsec__command_reply(j_responses, context, "removeRoleACL", "Invalid/missing topic", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}
	if(mosquitto_validate_utf8(topic, (int)strlen(topic)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeRoleACL", "Topic not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	rc = mosquitto_sub_topic_check(topic);
	if(rc != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeRoleACL", "Invalid ACL topic", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	HASH_FIND(hh, *acllist, topic, strlen(topic), acl);
	if(acl){
		role__free_acl(acllist, acl);
		dynsec__config_save();
		dynsec__command_reply(j_responses, context, "removeRoleACL", NULL, correlation_data);

		role__kick_all(role);

		admin_clientid = mosquitto_client_id(context);
		admin_username = mosquitto_client_username(context);
		mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | removeRoleACL | rolename=%s | acltype=%s | topic=%s",
				admin_clientid, admin_username, rolename, j_acltype->valuestring, topic);

	}else{
		dynsec__command_reply(j_responses, context, "removeRoleACL", "ACL not found", correlation_data);
	}

	return MOSQ_ERR_SUCCESS;
}


int dynsec_roles__process_get(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *rolename;
	struct dynsec__role *role;
	cJSON *tree, *j_role, *j_data;

	if(json_get_string(command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "getRole", "Invalid/missing rolename", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "getRole", "Role name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	role = dynsec_roles__find(rolename);
	if(role == NULL){
		dynsec__command_reply(j_responses, context, "getRole", "Role not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	tree = cJSON_CreateObject();
	if(tree == NULL){
		dynsec__command_reply(j_responses, context, "getRole", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	if(cJSON_AddStringToObject(tree, "command", "getRole") == NULL
			|| (j_data = cJSON_AddObjectToObject(tree, "data")) == NULL
			|| (correlation_data && cJSON_AddStringToObject(tree, "correlationData", correlation_data) == NULL)
			){

		cJSON_Delete(tree);
		dynsec__command_reply(j_responses, context, "getRole", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	j_role = add_role_to_json(role, true);
	if(j_role == NULL){
		cJSON_Delete(tree);
		dynsec__command_reply(j_responses, context, "getRole", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToObject(j_data, "role", j_role);
	cJSON_AddItemToArray(j_responses, tree);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_roles__process_modify(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *rolename;
	char *text_name, *text_description;
	struct dynsec__role *role;
	char *str;
	cJSON *j_acls;
	struct dynsec__acl *tmp_publish_c_send = NULL, *tmp_publish_c_recv = NULL;
	struct dynsec__acl *tmp_subscribe_literal = NULL, *tmp_subscribe_pattern = NULL;
	struct dynsec__acl *tmp_unsubscribe_literal = NULL, *tmp_unsubscribe_pattern = NULL;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "modifyRole", "Invalid/missing rolename", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "modifyRole", "Role name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	role = dynsec_roles__find(rolename);
	if(role == NULL){
		dynsec__command_reply(j_responses, context, "modifyRole", "Role does not exist", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "textname", &text_name, false) == MOSQ_ERR_SUCCESS){
		str = mosquitto_strdup(text_name);
		if(str == NULL){
			dynsec__command_reply(j_responses, context, "modifyRole", "Internal error", correlation_data);
			return MOSQ_ERR_NOMEM;
		}
		mosquitto_free(role->text_name);
		role->text_name = str;
	}

	if(json_get_string(command, "textdescription", &text_description, false) == MOSQ_ERR_SUCCESS){
		str = mosquitto_strdup(text_description);
		if(str == NULL){
			dynsec__command_reply(j_responses, context, "modifyRole", "Internal error", correlation_data);
			return MOSQ_ERR_NOMEM;
		}
		mosquitto_free(role->text_description);
		role->text_description = str;
	}

	j_acls = cJSON_GetObjectItem(command, "acls");
	if(j_acls && cJSON_IsArray(j_acls)){
		if(dynsec_roles__acl_load(j_acls, ACL_TYPE_PUB_C_SEND, &tmp_publish_c_send) != 0
				|| dynsec_roles__acl_load(j_acls, ACL_TYPE_PUB_C_RECV, &tmp_publish_c_recv) != 0
				|| dynsec_roles__acl_load(j_acls, ACL_TYPE_SUB_LITERAL, &tmp_subscribe_literal) != 0
				|| dynsec_roles__acl_load(j_acls, ACL_TYPE_SUB_PATTERN, &tmp_subscribe_pattern) != 0
				|| dynsec_roles__acl_load(j_acls, ACL_TYPE_UNSUB_LITERAL, &tmp_unsubscribe_literal) != 0
				|| dynsec_roles__acl_load(j_acls, ACL_TYPE_UNSUB_PATTERN, &tmp_unsubscribe_pattern) != 0
				){

			/* Free any that were successful */
			role__free_all_acls(&tmp_publish_c_send);
			role__free_all_acls(&tmp_publish_c_recv);
			role__free_all_acls(&tmp_subscribe_literal);
			role__free_all_acls(&tmp_subscribe_pattern);
			role__free_all_acls(&tmp_unsubscribe_literal);
			role__free_all_acls(&tmp_unsubscribe_pattern);

			dynsec__command_reply(j_responses, context, "modifyRole", "Internal error", correlation_data);
			return MOSQ_ERR_NOMEM;
		}

		role__free_all_acls(&role->acls.publish_c_send);
		role__free_all_acls(&role->acls.publish_c_recv);
		role__free_all_acls(&role->acls.subscribe_literal);
		role__free_all_acls(&role->acls.subscribe_pattern);
		role__free_all_acls(&role->acls.unsubscribe_literal);
		role__free_all_acls(&role->acls.unsubscribe_pattern);

		role->acls.publish_c_send = tmp_publish_c_send;
		role->acls.publish_c_recv = tmp_publish_c_recv;
		role->acls.subscribe_literal = tmp_subscribe_literal;
		role->acls.subscribe_pattern = tmp_subscribe_pattern;
		role->acls.unsubscribe_literal = tmp_unsubscribe_literal;
		role->acls.unsubscribe_pattern = tmp_unsubscribe_pattern;
	}

	dynsec__config_save();

	dynsec__command_reply(j_responses, context, "modifyRole", NULL, correlation_data);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | modifyRole | rolename=%s",
			admin_clientid, admin_username, rolename);

	return MOSQ_ERR_SUCCESS;
}
