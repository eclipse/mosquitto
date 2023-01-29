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
#include <uthash.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "json_help.h"

#include "dynamic_security.h"

/* ################################################################
 * #
 * # Plugin global variables
 * #
 * ################################################################ */

/* ################################################################
 * #
 * # Function declarations
 * #
 * ################################################################ */

static int dynsec__remove_all_clients_from_group(struct dynsec__group *group);
static int dynsec__remove_all_roles_from_group(struct dynsec__group *group);


/* ################################################################
 * #
 * # Local variables
 * #
 * ################################################################ */

/* ################################################################
 * #
 * # Utility functions
 * #
 * ################################################################ */

static void group__kick_all(struct dynsec__data *data, struct dynsec__group *group)
{
	if(group == data->anonymous_group){
		dynsec_kicklist__add(data, NULL);
	}
	dynsec_clientlist__kick_all(data, group->clientlist);
}


static int group_cmp(void *a, void *b)
{
	struct dynsec__group *group_a = a;
	struct dynsec__group *group_b = b;

	return strcmp(group_a->groupname, group_b->groupname);
}


struct dynsec__group *dynsec_groups__find(struct dynsec__data *data, const char *groupname)
{
    if (!groupname) return NULL;

	struct dynsec__group *group = NULL;

    HASH_FIND(hh, data->groups, groupname, strlen(groupname), group);
	return group;
}

struct dynsec__group *dynsec_groups__create(const char *groupname)
{
    size_t groupname_len = strlen(groupname);
    struct dynsec__group *group = mosquitto_calloc(1, sizeof(struct dynsec__group) + groupname_len + 1);
    if(!group) return NULL;

    memcpy(group->groupname, groupname, groupname_len);

    return group;
}

bool dynsec_groups__insert(struct dynsec__data *data, struct dynsec__group *group)
{
    if (dynsec_groups__find(data, group->groupname) == NULL) {
        HASH_ADD_KEYPTR_INORDER(hh, data->groups, group->groupname, strlen(group->groupname), group, group_cmp);
        return true;
    } else {
        return false;
    }
}


static void group__free_item(struct dynsec__data *data, struct dynsec__group *group)
{
	struct dynsec__group *found_group = NULL;

	if(group == NULL) return;

	found_group = dynsec_groups__find(data, group->groupname);
	if(found_group){
		HASH_DEL(data->groups, found_group);
	}
	dynsec__remove_all_clients_from_group(group);
	mosquitto_free(group->text_name);
	mosquitto_free(group->text_description);
	dynsec_rolelist__cleanup(&group->rolelist);
	mosquitto_free(group);
}

int dynsec_groups__process_add_role(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	char *groupname, *rolename;
	struct dynsec__group *group;
	struct dynsec__role *role;
	int priority;
	const char *admin_clientid, *admin_username;
	int rc;

	if(json_get_string(cmd->j_command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing groupname");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)strlen(groupname)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Group name not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(cmd->j_command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing rolename");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Role name not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}
	json_get_int(cmd->j_command, "priority", &priority, true, -1);

	group = dynsec_groups__find(data, groupname);
	if(group == NULL){
		control__command_reply(cmd, "Group not found");
		return MOSQ_ERR_SUCCESS;
	}

	role = dynsec_roles__find(data, rolename);
	if(role == NULL){
		control__command_reply(cmd, "Role not found");
		return MOSQ_ERR_SUCCESS;
	}

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);

	rc = dynsec_rolelist__group_add(group, role, priority);
	if(rc == MOSQ_ERR_SUCCESS){
		/* Continue */
	}else if(rc == MOSQ_ERR_ALREADY_EXISTS){
		control__command_reply(cmd, "Group is already in this role");
		return MOSQ_ERR_ALREADY_EXISTS;
	}else{
		control__command_reply(cmd, "Internal error");
		return MOSQ_ERR_UNKNOWN;
	}

	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | addGroupRole | groupname=%s | rolename=%s | priority=%d",
			admin_clientid, admin_username, groupname, rolename, priority);

	dynsec__config_batch_save(data);
	control__command_reply(cmd, NULL);

	/* Enforce any changes */
	group__kick_all(data, group);

	return MOSQ_ERR_SUCCESS;
}


void dynsec_groups__cleanup(struct dynsec__data *data)
{
	struct dynsec__group *group, *group_tmp = NULL;

	HASH_ITER(hh, data->groups, group, group_tmp){
		group__free_item(data, group);
	}
	data->anonymous_group = NULL;
}

/* ################################################################
 * #
 * # Command processing
 * #
 * ################################################################ */

int dynsec_groups__process_create(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	char *groupname, *text_name, *text_description;
	struct dynsec__group *group = NULL;
	int rc = MOSQ_ERR_SUCCESS;
	const char *admin_clientid, *admin_username;
	size_t groupname_len;

	if(json_get_string(cmd->j_command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing groupname");
		return MOSQ_ERR_INVAL;
	}
	groupname_len = strlen(groupname);
	if(groupname_len == 0){
		control__command_reply(cmd, "Empty groupname");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)groupname_len) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Group name not valid UTF-8");
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

	group = dynsec_groups__find(data, groupname);
	if(group){
		control__command_reply(cmd, "Group already exists");
		return MOSQ_ERR_SUCCESS;
	}

	group = mosquitto_calloc(1, sizeof(struct dynsec__group) + groupname_len + 1);
	if(group == NULL){
		control__command_reply(cmd, "Internal error");
		return MOSQ_ERR_NOMEM;
	}
	strncpy(group->groupname, groupname, groupname_len+1);
	if(text_name){
		group->text_name = strdup(text_name);
		if(group->text_name == NULL){
			control__command_reply(cmd, "Internal error");
			group__free_item(data, group);
			return MOSQ_ERR_NOMEM;
		}
	}
	if(text_description){
		group->text_description = strdup(text_description);
		if(group->text_description == NULL){
			control__command_reply(cmd, "Internal error");
			group__free_item(data, group);
			return MOSQ_ERR_NOMEM;
		}
	}

	rc = dynsec_rolelist__load_from_json(data, cmd->j_command, &group->rolelist);
	if(rc == MOSQ_ERR_SUCCESS || rc == ERR_LIST_NOT_FOUND){
	}else if(rc == MOSQ_ERR_NOT_FOUND){
		control__command_reply(cmd, "Role not found");
		group__free_item(data, group);
		return MOSQ_ERR_INVAL;
	}else{
		control__command_reply(cmd, "Internal error");
		group__free_item(data, group);
		return MOSQ_ERR_INVAL;
	}

	HASH_ADD_INORDER(hh, data->groups, groupname, groupname_len, group, group_cmp);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | createGroup | groupname=%s",
			admin_clientid, admin_username, groupname);

	dynsec__config_batch_save(data);
	control__command_reply(cmd, NULL);
	return MOSQ_ERR_SUCCESS;
}


int dynsec_groups__process_delete(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	char *groupname;
	struct dynsec__group *group;
	const char *admin_clientid, *admin_username;

	if(json_get_string(cmd->j_command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing groupname");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)strlen(groupname)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Group name not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}

	group = dynsec_groups__find(data, groupname);
	if(group){
		if(group == data->anonymous_group){
			control__command_reply(cmd, "Deleting the anonymous group is forbidden");
			return MOSQ_ERR_INVAL;
		}

		/* Enforce any changes */
		group__kick_all(data, group);

		dynsec__remove_all_roles_from_group(group);
		group__free_item(data, group);
		dynsec__config_batch_save(data);
		control__command_reply(cmd, NULL);

		admin_clientid = mosquitto_client_id(context);
		admin_username = mosquitto_client_username(context);
		mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | deleteGroup | groupname=%s",
				admin_clientid, admin_username, groupname);

		return MOSQ_ERR_SUCCESS;
	}else{
		control__command_reply(cmd, "Group not found");
		return MOSQ_ERR_SUCCESS;
	}
}


int dynsec_groups__add_client(struct dynsec__data *data, const char *username, const char *groupname, int priority, bool update_config)
{
	struct dynsec__client *client;
	struct dynsec__clientlist *clientlist;
	struct dynsec__group *group;
	int rc;

	client = dynsec_clients__find(data, username);
	if(client == NULL){
		return ERR_USER_NOT_FOUND;
	}

	group = dynsec_groups__find(data, groupname);
	if(group == NULL){
		return ERR_GROUP_NOT_FOUND;
	}

	HASH_FIND(hh, group->clientlist, username, strlen(username), clientlist);
	if(clientlist != NULL){
		/* Client is already in the group */
		return MOSQ_ERR_ALREADY_EXISTS;
	}

	rc = dynsec_clientlist__add(&group->clientlist, client, priority);
	if(rc){
		return rc;
	}
	rc = dynsec_grouplist__add(&client->grouplist, group, priority);
	if(rc){
		dynsec_clientlist__remove(&group->clientlist, client);
		return rc;
	}

	if(update_config){
		dynsec__config_batch_save(data);
	}

	return MOSQ_ERR_SUCCESS;
}


int dynsec_groups__process_add_client(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	char *username, *groupname;
	int rc;
	int priority;
	const char *admin_clientid, *admin_username;

	if(json_get_string(cmd->j_command, "username", &username, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing username");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(username, (int)strlen(username)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Username not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(cmd->j_command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing groupname");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)strlen(groupname)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Group name not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}

	json_get_int(cmd->j_command, "priority", &priority, true, -1);

	rc = dynsec_groups__add_client(data, username, groupname, priority, true);
	if(rc == MOSQ_ERR_SUCCESS){
		admin_clientid = mosquitto_client_id(context);
		admin_username = mosquitto_client_username(context);
		mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | addGroupClient | groupname=%s | username=%s | priority=%d",
				admin_clientid, admin_username, groupname, username, priority);

		control__command_reply(cmd, NULL);
	}else if(rc == ERR_USER_NOT_FOUND){
		control__command_reply(cmd, "Client not found");
	}else if(rc == ERR_GROUP_NOT_FOUND){
		control__command_reply(cmd, "Group not found");
	}else if(rc == MOSQ_ERR_ALREADY_EXISTS){
		control__command_reply(cmd, "Client is already in this group");
	}else{
		control__command_reply(cmd, "Internal error");
	}

	/* Enforce any changes */
	dynsec_kicklist__add(data, username);

	return rc;
}


static int dynsec__remove_all_clients_from_group(struct dynsec__group *group)
{
	struct dynsec__clientlist *clientlist, *clientlist_tmp = NULL;

	HASH_ITER(hh, group->clientlist, clientlist, clientlist_tmp){
		/* Remove client stored group reference */
		dynsec_grouplist__remove(&clientlist->client->grouplist, group);

		HASH_DELETE(hh, group->clientlist, clientlist);
		mosquitto_free(clientlist);
	}

	return MOSQ_ERR_SUCCESS;
}

static int dynsec__remove_all_roles_from_group(struct dynsec__group *group)
{
	struct dynsec__rolelist *rolelist, *rolelist_tmp = NULL;

	HASH_ITER(hh, group->rolelist, rolelist, rolelist_tmp){
		dynsec_rolelist__group_remove(group, rolelist->role);
	}

	return MOSQ_ERR_SUCCESS;
}

int dynsec_groups__remove_client(struct dynsec__data *data, const char *username, const char *groupname, bool update_config)
{
	struct dynsec__client *client;
	struct dynsec__group *group;

	client = dynsec_clients__find(data, username);
	if(client == NULL){
		return ERR_USER_NOT_FOUND;
	}

	group = dynsec_groups__find(data, groupname);
	if(group == NULL){
		return ERR_GROUP_NOT_FOUND;
	}

	dynsec_clientlist__remove(&group->clientlist, client);
	dynsec_grouplist__remove(&client->grouplist, group);

	if(update_config){
		dynsec__config_batch_save(data);
	}
	return MOSQ_ERR_SUCCESS;
}

int dynsec_groups__process_remove_client(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	char *username, *groupname;
	int rc;
	const char *admin_clientid, *admin_username;

	if(json_get_string(cmd->j_command, "username", &username, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing username");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(username, (int)strlen(username)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Username not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(cmd->j_command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing groupname");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)strlen(groupname)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Group name not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}

	rc = dynsec_groups__remove_client(data, username, groupname, true);
	if(rc == MOSQ_ERR_SUCCESS){
		admin_clientid = mosquitto_client_id(context);
		admin_username = mosquitto_client_username(context);
		mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | removeGroupClient | groupname=%s | username=%s",
				admin_clientid, admin_username, groupname, username);

		control__command_reply(cmd, NULL);
	}else if(rc == ERR_USER_NOT_FOUND){
		control__command_reply(cmd, "Client not found");
	}else if(rc == ERR_GROUP_NOT_FOUND){
		control__command_reply(cmd, "Group not found");
	}else{
		control__command_reply(cmd, "Internal error");
	}

	/* Enforce any changes */
	dynsec_kicklist__add(data, username);

	return rc;
}

static cJSON *add_group_to_json(struct dynsec__group *group)
{
    cJSON *j_group, *jtmp, *j_clientlist, *j_client, *j_rolelist;
    struct dynsec__clientlist *clientlist, *clientlist_tmp = NULL;

    j_group = cJSON_CreateObject();
    if(j_group == NULL){
        return NULL;
    }

    if(cJSON_AddStringToObject(j_group, "groupname", group->groupname) == NULL
       || (group->text_name && cJSON_AddStringToObject(j_group, "textname", group->text_name) == NULL)
       || (group->text_description && cJSON_AddStringToObject(j_group, "textdescription", group->text_description) == NULL)
       || (j_clientlist = cJSON_AddArrayToObject(j_group, "clients")) == NULL
            ){

        cJSON_Delete(j_group);
        return NULL;
    }

    HASH_ITER(hh, group->clientlist, clientlist, clientlist_tmp){
        j_client = cJSON_CreateObject();
        if(j_client == NULL){
            cJSON_Delete(j_group);
            return NULL;
        }
        cJSON_AddItemToArray(j_clientlist, j_client);

        jtmp = cJSON_CreateStringReference(clientlist->client->username);
        if(jtmp == NULL){
            cJSON_Delete(j_group);
            return NULL;
        }
        cJSON_AddItemToObject(j_client, "username", jtmp);
    }

    j_rolelist = dynsec_rolelist__all_to_json(group->rolelist);
    if(j_rolelist == NULL){
        cJSON_Delete(j_group);
        return NULL;
    }
    cJSON_AddItemToObject(j_group, "roles", j_rolelist);

    return j_group;
}

int dynsec_groups__process_list(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	bool verbose;
	cJSON *tree, *j_groups, *j_group, *j_data;
	struct dynsec__group *group, *group_tmp = NULL;
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

	if(cJSON_AddStringToObject(tree, "command", "listGroups") == NULL
			|| (j_data = cJSON_AddObjectToObject(tree, "data")) == NULL
			|| cJSON_AddIntToObject(j_data, "totalCount", (int)HASH_CNT(hh, data->groups)) == NULL
			|| (j_groups = cJSON_AddArrayToObject(j_data, "groups")) == NULL
			|| (cmd->correlation_data && cJSON_AddStringToObject(tree, "correlationData", cmd->correlation_data) == NULL)
			){

		cJSON_Delete(tree);
		control__command_reply(cmd, "Internal error");
		return MOSQ_ERR_NOMEM;
	}

	i = 0;
	HASH_ITER(hh, data->groups, group, group_tmp){
		if(i>=offset){
			if(verbose){
				j_group = add_group_to_json(group);
				if(j_group == NULL){
					cJSON_Delete(tree);
					control__command_reply(cmd, "Internal error");
					return MOSQ_ERR_NOMEM;
				}
				cJSON_AddItemToArray(j_groups, j_group);

			}else{
				j_group = cJSON_CreateString(group->groupname);
				if(j_group){
					cJSON_AddItemToArray(j_groups, j_group);
				}else{
					cJSON_Delete(tree);
					control__command_reply(cmd, "Internal error");
					return MOSQ_ERR_NOMEM;
				}
			}

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
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | listGroups | verbose=%s | count=%d | offset=%d",
			admin_clientid, admin_username, verbose?"true":"false", count, offset);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_groups__process_get(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	char *groupname;
	cJSON *tree, *j_group, *j_data;
	struct dynsec__group *group;
	const char *admin_clientid, *admin_username;

	if(json_get_string(cmd->j_command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing groupname");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)strlen(groupname)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Group name not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}

	tree = cJSON_CreateObject();
	if(tree == NULL){
		control__command_reply(cmd, "Internal error");
		return MOSQ_ERR_NOMEM;
	}

	if(cJSON_AddStringToObject(tree, "command", "getGroup") == NULL
			|| (j_data = cJSON_AddObjectToObject(tree, "data")) == NULL
			|| (cmd->correlation_data && cJSON_AddStringToObject(tree, "correlationData", cmd->correlation_data) == NULL)
			){

		cJSON_Delete(tree);
		control__command_reply(cmd, "Internal error");
		return MOSQ_ERR_NOMEM;
	}

	group = dynsec_groups__find(data, groupname);
	if(group){
		j_group = add_group_to_json(group);
		if(j_group == NULL){
			cJSON_Delete(tree);
			control__command_reply(cmd, "Internal error");
			return MOSQ_ERR_NOMEM;
		}
		cJSON_AddItemToObject(j_data, "group", j_group);
	}else{
		cJSON_Delete(tree);
		control__command_reply(cmd, "Group not found");
		return MOSQ_ERR_NOMEM;
	}

	cJSON_AddItemToArray(cmd->j_responses, tree);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | getGroup | groupname=%s",
			admin_clientid, admin_username, groupname);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_groups__process_remove_role(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	char *groupname, *rolename;
	struct dynsec__group *group;
	struct dynsec__role *role;
	const char *admin_clientid, *admin_username;

	if(json_get_string(cmd->j_command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing groupname");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)strlen(groupname)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Group name not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(cmd->j_command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing rolename");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Role name not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}

	group = dynsec_groups__find(data, groupname);
	if(group == NULL){
		control__command_reply(cmd, "Group not found");
		return MOSQ_ERR_SUCCESS;
	}

	role = dynsec_roles__find(data, rolename);
	if(role == NULL){
		control__command_reply(cmd, "Role not found");
		return MOSQ_ERR_SUCCESS;
	}

	dynsec_rolelist__group_remove(group, role);
	dynsec__config_batch_save(data);
	control__command_reply(cmd, NULL);

	/* Enforce any changes */
	group__kick_all(data, group);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | removeGroupRole | groupname=%s | rolename=%s",
			admin_clientid, admin_username, groupname, rolename);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_groups__process_modify(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	char *groupname = NULL;
	char *text_name = NULL, *text_description = NULL;
	struct dynsec__client *client = NULL;
	struct dynsec__group *group = NULL;
	struct dynsec__rolelist *rolelist = NULL;
	bool have_text_name = false, have_text_description = false, have_rolelist = false;
	char *str;
	int rc;
	int priority;
	cJSON *j_client, *j_clients, *jtmp;
	const char *admin_clientid, *admin_username;

	if(json_get_string(cmd->j_command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing groupname");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)strlen(groupname)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Group name not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}

	group = dynsec_groups__find(data, groupname);
	if(group == NULL){
		control__command_reply(cmd, "Group not found");
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(cmd->j_command, "textname", &str, false) == MOSQ_ERR_SUCCESS){
		have_text_name = true;
		text_name = mosquitto_strdup(str);
		if(text_name == NULL){
			control__command_reply(cmd, "Internal error");
			rc = MOSQ_ERR_NOMEM;
			goto error;
		}
	}

	if(json_get_string(cmd->j_command, "textdescription", &str, false) == MOSQ_ERR_SUCCESS){
		have_text_description = true;
		text_description = mosquitto_strdup(str);
		if(text_description == NULL){
			control__command_reply(cmd, "Internal error");
			rc = MOSQ_ERR_NOMEM;
			goto error;
		}
	}

	rc = dynsec_rolelist__load_from_json(data, cmd->j_command, &rolelist);
	if(rc == MOSQ_ERR_SUCCESS){
		/* Apply changes below */
		have_rolelist = true;
	}else if(rc == ERR_LIST_NOT_FOUND){
		/* There was no list in the JSON, so no modification */
		rolelist = NULL;
	}else if(rc == MOSQ_ERR_NOT_FOUND){
		control__command_reply(cmd, "Role not found");
		rc = MOSQ_ERR_INVAL;
		goto error;
	}else{
		if(rc == MOSQ_ERR_INVAL){
			control__command_reply(cmd, "'roles' not an array or missing/invalid rolename");
		}else{
			control__command_reply(cmd, "Internal error");
		}
		rc = MOSQ_ERR_INVAL;
		goto error;
	}

	j_clients = cJSON_GetObjectItem(cmd->j_command, "clients");
	if(j_clients && cJSON_IsArray(j_clients)){
		/* Iterate over array to check clients are valid before proceeding */
		cJSON_ArrayForEach(j_client, j_clients){
			if(cJSON_IsObject(j_client)){
				jtmp = cJSON_GetObjectItem(j_client, "username");
				if(jtmp && cJSON_IsString(jtmp)){
					client = dynsec_clients__find(data, jtmp->valuestring);
					if(client == NULL){
						control__command_reply(cmd, "'clients' contains an object with a 'username' that does not exist");
						rc = MOSQ_ERR_INVAL;
						goto error;
					}
				}else{
					control__command_reply(cmd, "'clients' contains an object with an invalid 'username'");
					rc = MOSQ_ERR_INVAL;
					goto error;
				}
			}
		}

		/* Kick all clients in the *current* group */
		group__kick_all(data, group);
		dynsec__remove_all_clients_from_group(group);

		/* Now we can add the new clients to the group */
		cJSON_ArrayForEach(j_client, j_clients){
			if(cJSON_IsObject(j_client)){
				jtmp = cJSON_GetObjectItem(j_client, "username");
				if(jtmp && cJSON_IsString(jtmp)){
					json_get_int(j_client, "priority", &priority, true, -1);
					dynsec_groups__add_client(data, jtmp->valuestring, groupname, priority, false);
				}
			}
		}
	}

	/* Apply remaining changes to group, note that user changes are already applied */
	if(have_text_name){
		mosquitto_free(group->text_name);
		group->text_name = text_name;
	}

	if(have_text_description){
		mosquitto_free(group->text_description);
		group->text_description = text_description;
	}

	if(have_rolelist){
		dynsec_rolelist__cleanup(&group->rolelist);
		group->rolelist = rolelist;
	}

	/* And save */
	dynsec__config_batch_save(data);

	control__command_reply(cmd, NULL);

	/* Enforce any changes - kick any clients in the *new* group */
	group__kick_all(data, group);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | modifyGroup | groupname=%s",
			admin_clientid, admin_username, groupname);

	return MOSQ_ERR_SUCCESS;
error:
	mosquitto_free(text_name);
	mosquitto_free(text_description);
	dynsec_rolelist__cleanup(&rolelist);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | modifyGroup | groupname=%s",
			admin_clientid, admin_username, groupname);

	return rc;
}


int dynsec_groups__process_set_anonymous_group(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	char *groupname;
	struct dynsec__group *group = NULL;
	const char *admin_clientid, *admin_username;

	if(json_get_string(cmd->j_command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Invalid/missing groupname");
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)strlen(groupname)) != MOSQ_ERR_SUCCESS){
		control__command_reply(cmd, "Group name not valid UTF-8");
		return MOSQ_ERR_INVAL;
	}

	group = dynsec_groups__find(data, groupname);
	if(group == NULL){
		control__command_reply(cmd, "Group not found");
		return MOSQ_ERR_SUCCESS;
	}

	data->anonymous_group = group;

	dynsec__config_batch_save(data);
	control__command_reply(cmd, NULL);

	/* Enforce any changes */
	dynsec_kicklist__add(data, NULL);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | setAnonymousGroup | groupname=%s",
			admin_clientid, admin_username, groupname);

	return MOSQ_ERR_SUCCESS;
}

int dynsec_groups__process_get_anonymous_group(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context)
{
	cJSON *tree, *j_data, *j_group;
	const char *groupname;
	const char *admin_clientid, *admin_username;

	tree = cJSON_CreateObject();
	if(tree == NULL){
		control__command_reply(cmd, "Internal error");
		return MOSQ_ERR_NOMEM;
	}

	if(data->anonymous_group){
		groupname = data->anonymous_group->groupname;
	}else{
		groupname = "";
	}

	if(cJSON_AddStringToObject(tree, "command", "getAnonymousGroup") == NULL
			|| (j_data = cJSON_AddObjectToObject(tree, "data")) == NULL
			|| (j_group = cJSON_AddObjectToObject(j_data, "group")) == NULL
			|| cJSON_AddStringToObject(j_group, "groupname", groupname) == NULL
			|| (cmd->correlation_data && cJSON_AddStringToObject(tree, "correlationData", cmd->correlation_data) == NULL)
			){

		cJSON_Delete(tree);
		control__command_reply(cmd, "Internal error");
		return MOSQ_ERR_NOMEM;
	}

	cJSON_AddItemToArray(cmd->j_responses, tree);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | getAnonymousGroup",
			admin_clientid, admin_username);

	return MOSQ_ERR_SUCCESS;
}
