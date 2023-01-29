/*
Copyright (c) 2020-2021 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <string.h>
#include <uthash.h>
#include <utlist.h>

#ifndef WIN32
#  include <strings.h>
#endif

#include "dynamic_security.h"
#include "json_help.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"

cJSON *add_role_to_json(struct dynsec__role *role, bool verbose);
int dynsec_roles__acl_load(cJSON *j_acls, const char *key, struct dynsec__acl **acllist);
static void role__remove_all_clients(struct dynsec__data *data, struct dynsec__role *role);

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
	mosquitto_free(item);
}

static void role__free_all_acls(struct dynsec__acl **acl)
{
	struct dynsec__acl *iter, *tmp = NULL;

	HASH_ITER(hh, *acl, iter, tmp){
		role__free_acl(acl, iter);
	}
}

static void role__free_item(struct dynsec__data *data, struct dynsec__role *role, bool remove_from_hash)
{
	if(remove_from_hash){
		HASH_DEL(data->roles, role);
	}
	dynsec_clientlist__cleanup(&role->clientlist);
	dynsec_grouplist__cleanup(&role->grouplist);
	mosquitto_free(role->text_name);
	mosquitto_free(role->text_description);
	role__free_all_acls(&role->acls.publish_c_send);
	role__free_all_acls(&role->acls.publish_c_recv);
	role__free_all_acls(&role->acls.subscribe_literal);
	role__free_all_acls(&role->acls.subscribe_pattern);
	role__free_all_acls(&role->acls.unsubscribe_literal);
	role__free_all_acls(&role->acls.unsubscribe_pattern);
	mosquitto_free(role);
}

struct dynsec__role *dynsec_roles__find(struct dynsec__data *data, const char *rolename)
{
    if (!rolename) return NULL;

	struct dynsec__role *role = NULL;

    HASH_FIND(hh, data->roles, rolename, strlen(rolename), role);

	return role;
}

struct dynsec__role *dynsec_roles__find_or_create(struct dynsec__data *data, const char *rolename)
{
    if (!rolename) return NULL;

    struct dynsec__role *role = dynsec_roles__find(data, rolename);

    if(!role){
        size_t rolename_len = strlen(rolename);
        role = mosquitto_calloc(1, sizeof(struct dynsec__role) + rolename_len + 1);
        if(!role) return NULL;

        memcpy(role->rolename, rolename, rolename_len);

        HASH_ADD_KEYPTR_INORDER(hh, data->roles, role->rolename, strlen(role->rolename), role, role_cmp);
    }

    return role;
}


void dynsec_roles__cleanup(struct dynsec__data *data)
{
	struct dynsec__role *role, *role_tmp = NULL;

	HASH_ITER(hh, data->roles, role, role_tmp){
		role__free_item(data, role, true);
	}
}


static void role__kick_all(struct dynsec__data *data, struct dynsec__role *role)
{
	struct dynsec__grouplist *grouplist, *grouplist_tmp = NULL;

	dynsec_clientlist__kick_all(data, role->clientlist);

	HASH_ITER(hh, role->grouplist, grouplist, grouplist_tmp){
		if(grouplist->group == data->anonymous_group){
			dynsec_kicklist__add(data, NULL);
		}
		dynsec_clientlist__kick_all(data, grouplist->group->clientlist);
	}
}


/* ################################################################
 * #
 * # Config file load and save
 * #
 * ################################################################ */

static int insert_acl_cmp(struct dynsec__acl *a, struct dynsec__acl *b)
{
	return b->priority - a->priority;
}

int dynsec_roles__process_create(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	char *rolename;
	char *text_name, *text_description;
	bool allow_wildcard_subs;
	struct dynsec__role *role;
	int rc = MOSQ_ERR_SUCCESS;
	cJSON *j_acls;
	const char *admin_clientid, *admin_username;
	size_t rolename_len;

	if(json_get_string(cmd->j_command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing rolename");
		return MOSQ_ERR_INVAL;
	}
	rolename_len = strlen(rolename);
	if(rolename_len == 0){
		control__command_reply(cmd, "Empty rolename");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)rolename_len) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Role name not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(cmd->j_command, "textname", &text_name, true) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing textname");
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(cmd->j_command, "textdescription", &text_description, true) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing textdescription");
		return MOSQ_ERR_INVAL;
	}

	if(json_get_bool(cmd->j_command, "allowwildcardsubs", &allow_wildcard_subs, true, true) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid allowwildcardsubs");
		return MOSQ_ERR_INVAL;
	}

	role = dynsec_roles__find(data, rolename);
	if(role){
		control__command_reply(cmd, "Role already exists");
		return MOSQ_ERR_SUCCESS;
	}

	role = mosquitto_calloc(1, sizeof(struct dynsec__role) + rolename_len + 1);
	if(role == NULL){
		control__command_reply(cmd, "Internal error");
		return MOSQ_ERR_NOMEM;
	}
	strncpy(role->rolename, rolename, rolename_len+1);
	if(text_name){
		role->text_name = mosquitto_strdup(text_name);
		if(role->text_name == NULL){
			control__command_reply(cmd, "Internal error");
			rc = MOSQ_ERR_NOMEM;
			goto error;
		}
	}
	if(text_description){
		role->text_description = mosquitto_strdup(text_description);
		if(role->text_description == NULL){
			control__command_reply(cmd, "Internal error");
			rc = MOSQ_ERR_NOMEM;
			goto error;
		}
	}
	role->allow_wildcard_subs = allow_wildcard_subs;

	/* ACLs */
	j_acls = cJSON_GetObjectItem(cmd->j_command, "acls");
	if(j_acls && cJSON_IsArray(j_acls)){
		if(dynsec_roles__acl_load(j_acls, ACL_TYPE_PUB_C_SEND, &role->acls.publish_c_send) != 0
				|| dynsec_roles__acl_load(j_acls, ACL_TYPE_PUB_C_RECV, &role->acls.publish_c_recv) != 0
				|| dynsec_roles__acl_load(j_acls, ACL_TYPE_SUB_LITERAL, &role->acls.subscribe_literal) != 0
				|| dynsec_roles__acl_load(j_acls, ACL_TYPE_SUB_PATTERN, &role->acls.subscribe_pattern) != 0
				|| dynsec_roles__acl_load(j_acls, ACL_TYPE_UNSUB_LITERAL, &role->acls.unsubscribe_literal) != 0
				|| dynsec_roles__acl_load(j_acls, ACL_TYPE_UNSUB_PATTERN, &role->acls.unsubscribe_pattern) != 0
				){

			control__command_reply(cmd, "Internal error");
			rc = MOSQ_ERR_NOMEM;
			goto error;
		}
	}

	HASH_ADD_INORDER(hh, data->roles, rolename, rolename_len, role, role_cmp);

	dynsec__config_batch_save(data);

	control__command_reply(cmd, NULL);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | createRole | rolename=%s",
			admin_clientid, admin_username, rolename);

	return MOSQ_ERR_SUCCESS;
error:
	if(role){
		role__free_item(data, role, false);
	}
	return rc;
}

static void role__remove_all_clients(struct dynsec__data *data, struct dynsec__role *role)
{
	struct dynsec__clientlist *clientlist, *clientlist_tmp = NULL;

	HASH_ITER(hh, role->clientlist, clientlist, clientlist_tmp){
		dynsec_kicklist__add(data, clientlist->client->username);

		dynsec_rolelist__client_remove(clientlist->client, role);
	}
}

static void role__remove_all_groups(struct dynsec__data *data, struct dynsec__role *role)
{
	struct dynsec__grouplist *grouplist, *grouplist_tmp = NULL;

	HASH_ITER(hh, role->grouplist, grouplist, grouplist_tmp){
		if(grouplist->group == data->anonymous_group){
			dynsec_kicklist__add(data, NULL);
		}
		dynsec_clientlist__kick_all(data, grouplist->group->clientlist);

		dynsec_rolelist__group_remove(grouplist->group, role);
	}
}

int dynsec_roles__process_delete(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	char *rolename;
	struct dynsec__role *role;
	const char *admin_clientid, *admin_username;

	if(json_get_string(cmd->j_command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing rolename");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Role name not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}

	role = dynsec_roles__find(data, rolename);
	if(role){
		role__remove_all_clients(data, role);
		role__remove_all_groups(data, role);
		role__free_item(data, role, true);
		dynsec__config_batch_save(data);
		control__command_reply(cmd, NULL);

		admin_clientid = mosquitto_client_id(context);
		admin_username = mosquitto_client_username(context);
		mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | deleteRole | rolename=%s",
				admin_clientid, admin_username, rolename);

		return MOSQ_ERR_SUCCESS;
	}else{
		control__command_reply(cmd, "Role not found");
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_roles__process_list(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	bool verbose;
	struct dynsec__role *role, *role_tmp = NULL;
	cJSON *tree, *j_roles, *j_role, *j_data;
	int i, count, offset;
	const char *admin_clientid, *admin_username;

	json_get_bool(cmd->j_command, "verbose", &verbose, true, false);
	json_get_int(cmd->j_command, "count", &count, true, -1);
	json_get_int(cmd->j_command, "offset", &offset, true, 0);

	tree = cJSON_CreateObject();
	if(tree == NULL){
		control__command_reply(cmd, "Internal error");
		return MOSQ_ERR_NOMEM;
	}

	if(cJSON_AddStringToObject(tree, "command", "listRoles") == NULL
			|| (j_data = cJSON_AddObjectToObject(tree, "data")) == NULL
			|| cJSON_AddIntToObject(j_data, "totalCount", (int)HASH_CNT(hh, data->roles)) == NULL
			|| (j_roles = cJSON_AddArrayToObject(j_data, "roles")) == NULL
			|| (cmd->correlation_data && cJSON_AddStringToObject(tree, "correlationData", cmd->correlation_data) == NULL)
			){

		cJSON_Delete(tree);
		control__command_reply(cmd, "Internal error");
		return MOSQ_ERR_NOMEM;
	}

	i = 0;
	HASH_ITER(hh, data->roles, role, role_tmp){
		if(i>=offset){
			j_role = add_role_to_json(role, verbose);
			if(j_role == NULL){
				cJSON_Delete(tree);
				control__command_reply(cmd, "Internal error");
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

	cJSON_AddItemToArray(cmd->j_responses, tree);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | listRoles | verbose=%s | count=%d | offset=%d",
			admin_clientid, admin_username, verbose?"true":"false", count, offset);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_roles__process_add_acl(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	char *rolename;
	struct dynsec__role *role;
	cJSON *j_acltype, *j_topic;
	struct dynsec__acl **acllist, *acl;
	int rc;
	const char *admin_clientid, *admin_username;
	size_t topic_len;

	if(json_get_string(cmd->j_command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing rolename");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Role name not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}

	role = dynsec_roles__find(data, rolename);
	if(role == NULL){
		control__command_reply(cmd, "Role not found");
		return MOSQ_ERR_SUCCESS;
	}

	j_acltype = cJSON_GetObjectItem(cmd->j_command, "acltype");
	if(j_acltype == NULL || !cJSON_IsString(j_acltype)){
		control__command_reply(cmd, "Invalid/missing acltype");
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
		control__command_reply(cmd, "Unknown acltype");
		return MOSQ_ERR_SUCCESS;
	}

	j_topic = cJSON_GetObjectItem(cmd->j_command, "topic");
	if(j_topic && cJSON_IsString(j_topic)){
		topic_len = strlen(j_topic->valuestring);
		if(mosquitto_validate_utf8(j_topic->valuestring, (int)topic_len) != MOSQ_ERR_SUCCESS){
			control__command_reply(cmd, "Topic not valid UTF-8");
			return MOSQ_ERR_INVAL;
		}
		rc = mosquitto_sub_topic_check(j_topic->valuestring);
		if(rc != MOSQ_ERR_SUCCESS){
			control__command_reply(cmd, "Invalid ACL topic");
			return MOSQ_ERR_INVAL;
		}
	}else{
		control__command_reply(cmd, "Invalid/missing topic");
		return MOSQ_ERR_SUCCESS;
	}

	HASH_FIND(hh, *acllist, j_topic->valuestring, topic_len, acl);
	if(acl){
		control__command_reply(cmd, "ACL with this topic already exists");
		return MOSQ_ERR_SUCCESS;
	}

	acl = mosquitto_calloc(1, sizeof(struct dynsec__acl) + topic_len + 1);
	if(acl == NULL){
		control__command_reply(cmd, "Internal error");
		return MOSQ_ERR_SUCCESS;
	}
	strncpy(acl->topic, j_topic->valuestring, topic_len+1);

	json_get_int(cmd->j_command, "priority", &acl->priority, true, 0);
	json_get_bool(cmd->j_command, "allow", &acl->allow, true, false);

	HASH_ADD_INORDER(hh, *acllist, topic, topic_len, acl, insert_acl_cmp);
	dynsec__config_batch_save(data);
	control__command_reply(cmd, NULL);

	role__kick_all(data, role);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | addRoleACL | rolename=%s | acltype=%s | topic=%s | priority=%d | allow=%s",
			admin_clientid, admin_username, rolename, j_acltype->valuestring, j_topic->valuestring, acl->priority, acl->allow?"true":"false");

	return MOSQ_ERR_SUCCESS;
}


int dynsec_roles__process_remove_acl(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	char *rolename;
	struct dynsec__role *role;
	struct dynsec__acl **acllist, *acl;
	char *topic;
	cJSON *j_acltype;
	int rc;
	const char *admin_clientid, *admin_username;

	if(json_get_string(cmd->j_command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing rolename");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Role name not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}

	role = dynsec_roles__find(data, rolename);
	if(role == NULL){
		control__command_reply(cmd, "Role not found");
		return MOSQ_ERR_SUCCESS;
	}

	j_acltype = cJSON_GetObjectItem(cmd->j_command, "acltype");
	if(j_acltype == NULL || !cJSON_IsString(j_acltype)){
		control__command_reply(cmd, "Invalid/missing acltype");
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
		control__command_reply(cmd, "Unknown acltype");
		return MOSQ_ERR_SUCCESS;
	}

	if(json_get_string(cmd->j_command, "topic", &topic, false)){
		control__command_reply(cmd, "Invalid/missing topic");
		return MOSQ_ERR_SUCCESS;
	}
	if(mosquitto_validate_utf8(topic, (int)strlen(topic)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Topic not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}
	rc = mosquitto_sub_topic_check(topic);
	if(rc != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid ACL topic");
		return MOSQ_ERR_INVAL;
	}

	HASH_FIND(hh, *acllist, topic, strlen(topic), acl);
	if(acl){
		role__free_acl(acllist, acl);
		dynsec__config_batch_save(data);
		control__command_reply(cmd, NULL);

		role__kick_all(data, role);

		admin_clientid = mosquitto_client_id(context);
		admin_username = mosquitto_client_username(context);
		mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | removeRoleACL | rolename=%s | acltype=%s | topic=%s",
				admin_clientid, admin_username, rolename, j_acltype->valuestring, topic);

	}else{
		control__command_reply(cmd, "ACL not found");
	}

	return MOSQ_ERR_SUCCESS;
}


int dynsec_roles__process_get(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	char *rolename;
	struct dynsec__role *role;
	cJSON *tree, *j_role, *j_data;
	const char *admin_clientid, *admin_username;

	if(json_get_string(cmd->j_command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing rolename");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Role name not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}

	role = dynsec_roles__find(data, rolename);
	if(role == NULL){
		control__command_reply(cmd, "Role not found");
		return MOSQ_ERR_SUCCESS;
	}

	tree = cJSON_CreateObject();
	if(tree == NULL){
		control__command_reply(cmd, "Internal error");
		return MOSQ_ERR_NOMEM;
	}

	if(cJSON_AddStringToObject(tree, "command", "getRole") == NULL
			|| (j_data = cJSON_AddObjectToObject(tree, "data")) == NULL
			|| (cmd->correlation_data && cJSON_AddStringToObject(tree, "correlationData", cmd->correlation_data) == NULL)
			){

		cJSON_Delete(tree);
		control__command_reply(cmd, "Internal error");
		return MOSQ_ERR_NOMEM;
	}

	j_role = add_role_to_json(role, true);
	if(j_role == NULL){
		cJSON_Delete(tree);
		control__command_reply(cmd, "Internal error");
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToObject(j_data, "role", j_role);
	cJSON_AddItemToArray(cmd->j_responses, tree);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | getRole | rolename=%s",
			admin_clientid, admin_username, rolename);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_roles__process_modify(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	char *rolename;
	char *text_name, *text_description;
	struct dynsec__role *role;
	char *str;
	cJSON *j_acls;
	bool allow_wildcard_subs;
	bool do_kick = false;
	struct dynsec__acl *tmp_publish_c_send = NULL, *tmp_publish_c_recv = NULL;
	struct dynsec__acl *tmp_subscribe_literal = NULL, *tmp_subscribe_pattern = NULL;
	struct dynsec__acl *tmp_unsubscribe_literal = NULL, *tmp_unsubscribe_pattern = NULL;
	const char *admin_clientid, *admin_username;

	if(json_get_string(cmd->j_command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing rolename");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Role name not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}

	role = dynsec_roles__find(data, rolename);
	if(role == NULL){
		control__command_reply(cmd, "Role does not exist");
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(cmd->j_command, "textname", &text_name, false) == MOSQ_ERR_SUCCESS){
		str = mosquitto_strdup(text_name);
		if(str == NULL){
			control__command_reply(cmd, "Internal error");
			return MOSQ_ERR_NOMEM;
		}
		mosquitto_free(role->text_name);
		role->text_name = str;
	}

	if(json_get_string(cmd->j_command, "textdescription", &text_description, false) == MOSQ_ERR_SUCCESS){
		str = mosquitto_strdup(text_description);
		if(str == NULL){
			control__command_reply(cmd, "Internal error");
			return MOSQ_ERR_NOMEM;
		}
		mosquitto_free(role->text_description);
		role->text_description = str;
	}

	if(json_get_bool(cmd->j_command, "allowwildcardsubs", &allow_wildcard_subs, false, true) == MOSQ_ERR_SUCCESS){
		if(role->allow_wildcard_subs != allow_wildcard_subs){
			role->allow_wildcard_subs = allow_wildcard_subs;
			do_kick = true;
		}
	}

	j_acls = cJSON_GetObjectItem(cmd->j_command, "acls");
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

			control__command_reply(cmd, "Internal error");
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
		do_kick = true;
	}

	if(do_kick){
		role__kick_all(data, role);
	}
	dynsec__config_batch_save(data);

	control__command_reply(cmd, NULL);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | modifyRole | rolename=%s",
			admin_clientid, admin_username, rolename);

	return MOSQ_ERR_SUCCESS;
}
