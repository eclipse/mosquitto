/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>

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
#include "yaml.h"
#include "yaml_help.h"

/* ################################################################
 * #
 * # Plugin global variables
 * #
 * ################################################################ */

struct dynsec__group *dynsec_anonymous_group = NULL;


/* ################################################################
 * #
 * # Function declarations
 * #
 * ################################################################ */

static int dynsec__remove_all_clients_from_group(struct dynsec__group *group);
static int dynsec__remove_all_roles_from_group(struct dynsec__group *group);
static cJSON *add_group_to_json(struct dynsec__group *group);


/* ################################################################
 * #
 * # Local variables
 * #
 * ################################################################ */

static struct dynsec__group *local_groups = NULL;


/* ################################################################
 * #
 * # Utility functions
 * #
 * ################################################################ */

static void group__kick_all(struct dynsec__group *group)
{
	if(group == dynsec_anonymous_group){
		mosquitto_kick_client_by_username(NULL, false);
	}
	dynsec_clientlist__kick_all(group->clientlist);
}


static int group_cmp(void *a, void *b)
{
	struct dynsec__group *group_a = a;
	struct dynsec__group *group_b = b;

	return strcmp(group_a->groupname, group_b->groupname);
}


struct dynsec__group *dynsec_groups__find(const char *groupname)
{
    if (!groupname) return NULL;

	struct dynsec__group *group = NULL;

    HASH_FIND(hh, local_groups, groupname, strlen(groupname), group);
	return group;
}

struct dynsec__group *dynsec_groups__find_or_create(const char *groupname)
{
    if (!groupname) return NULL;

    struct dynsec__group *group = dynsec_groups__find(groupname);

    if(!group) {
        group = mosquitto_calloc(sizeof(struct dynsec__group), 1);
        if(!group) return NULL;

        group->groupname = mosquitto_strdup(groupname);

        HASH_ADD_KEYPTR_INORDER(hh, local_groups, group->groupname, strlen(group->groupname), group, group_cmp);
    }

    return group;
}

static void group__free_item(struct dynsec__group *group)
{
	struct dynsec__group *found_group = NULL;

	if(group == NULL) return;

	found_group = dynsec_groups__find(group->groupname);
	if(found_group){
		HASH_DEL(local_groups, found_group);
	}
	dynsec__remove_all_clients_from_group(group);
	mosquitto_free(group->text_name);
	mosquitto_free(group->text_description);
	mosquitto_free(group->groupname);
	dynsec_rolelist__cleanup(&group->rolelist);
	mosquitto_free(group);
}

int dynsec_groups__process_add_role(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *groupname, *rolename;
	struct dynsec__group *group;
	struct dynsec__role *role;
	int priority;
	const char *admin_clientid, *admin_username;
	int rc;

	if(json_get_string(command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addGroupRole", "Invalid/missing groupname", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)strlen(groupname)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addGroupRole", "Group name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addGroupRole", "Invalid/missing rolename", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addGroupRole", "Role name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	json_get_int(command, "priority", &priority, true, -1);

	group = dynsec_groups__find(groupname);
	if(group == NULL){
		dynsec__command_reply(j_responses, context, "addGroupRole", "Group not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	role = dynsec_roles__find(rolename);
	if(role == NULL){
		dynsec__command_reply(j_responses, context, "addGroupRole", "Role not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);

	rc = dynsec_rolelist__group_add(group, role, priority);
	if(rc == MOSQ_ERR_SUCCESS){
		/* Continue */
	}else if(rc == MOSQ_ERR_ALREADY_EXISTS){
		dynsec__command_reply(j_responses, context, "addGroupRole", "Group is already in this role", correlation_data);
		return MOSQ_ERR_ALREADY_EXISTS;
	}else{
		dynsec__command_reply(j_responses, context, "addGroupRole", "Internal error", correlation_data);
		return MOSQ_ERR_UNKNOWN;
	}

	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | addGroupRole | groupname=%s | rolename=%s | priority=%d",
			admin_clientid, admin_username, groupname, rolename, priority);

	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "addGroupRole", NULL, correlation_data);

	/* Enforce any changes */
	group__kick_all(group);

	return MOSQ_ERR_SUCCESS;
}


void dynsec_groups__cleanup(void)
{
	struct dynsec__group *group, *group_tmp = NULL;

	HASH_ITER(hh, local_groups, group, group_tmp){
		group__free_item(group);
	}
}


/* ################################################################
 * #
 * # Config file load
 * #
 * ################################################################ */

int dynsec_groups__config_load_yaml(yaml_parser_t *parser, yaml_event_t *event)
{
    struct dynsec__group *group;
    char *textname, *textdescription;

    struct dynsec__rolelist *rolelist;
    struct dynsec__clientlist *clientlist;

    printf("%s:%d\n", __FILE__, __LINE__);
    YAML_PARSER_SEQUENCE_FOR_ALL(parser, event, { goto error; }, {
        group = NULL;
        textname = textdescription = NULL;
        rolelist = NULL;
        clientlist = NULL;

        YAML_PARSER_MAPPING_FOR_ALL(parser, event, key, { goto error; }, {
                if (strcmp(key, "groupname") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    char *groupname;
                    YAML_EVENT_INTO_SCALAR_STRING(event, &groupname, { goto error; });
                    group = dynsec_groups__find_or_create(groupname);
                    mosquitto_free(groupname);
                } else if (strcmp(key, "textname") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_STRING(event, &textname, { goto error; });
                } else if (strcmp(key, "textdescription") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_STRING(event, &textdescription, { goto error; });
                } else if (strcmp(key, "roles") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    if (!dynsec_rolelist__load_from_yaml(parser, event, &rolelist)) goto error;
                } else if (strcmp(key, "clients") == 0) {
                    if (!dynsec_clientlist__load_from_yaml(parser, event, &clientlist)) goto error;
                } else {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    mosquitto_log_printf(MOSQ_LOG_ERR, "Unexpected key for group config %s \n", key);
                    yaml_dump_block(parser, event);
                }
                printf("%s:%d\n", __FILE__, __LINE__);


        });

        if (group) {
            group->text_description = textdescription;
            group->text_name = textname;

            if (clientlist) {
                struct dynsec__clientlist *iter;
                struct dynsec__clientlist *tmp;

                printf("%s:%d\n", __FILE__, __LINE__);
                HASH_ITER(hh, clientlist, iter, tmp){
                    printf("%s:%d\n", __FILE__, __LINE__);
                    dynsec_clientlist__add(&group->clientlist, iter->client, iter->priority);
                    dynsec_grouplist__add(&iter->client->grouplist, group, iter->priority);
                    iter->client = NULL;
                    printf("%s:%d\n", __FILE__, __LINE__);
                }
                dynsec_clientlist__cleanup(&clientlist);
                printf("%s:%d\n", __FILE__, __LINE__);
            }

            if (rolelist) {
                struct dynsec__rolelist *iter;
                struct dynsec__rolelist *tmp;

                printf("%s:%d\n", __FILE__, __LINE__);
                HASH_ITER(hh, rolelist, iter, tmp){
                    printf("%s:%d\n", __FILE__, __LINE__);

                    dynsec_rolelist__add(&group->rolelist, iter->role, iter->priority);
                    dynsec_grouplist__add(&iter->role->grouplist, group, iter->priority);
                    iter->role = NULL;
                    printf("%s:%d\n", __FILE__, __LINE__);
                }
                dynsec_rolelist__cleanup(&rolelist);
                printf("%s:%d\n", __FILE__, __LINE__);
            }
        } else {
            mosquitto_free(textname);
            mosquitto_free(textdescription);

            dynsec_rolelist__cleanup(&rolelist);
            dynsec_clientlist__cleanup(&clientlist);
        }

        printf("%s:%d\n", __FILE__, __LINE__);
    });

    printf("%s:%d\n", __FILE__, __LINE__);
    return 1;
error:
    mosquitto_free(textname);
    mosquitto_free(textdescription);
    dynsec_rolelist__cleanup(&rolelist);
    dynsec_clientlist__cleanup(&clientlist);
    return 0;
}

int dynsec_groups__config_load(cJSON *tree)
{
	cJSON *j_groups, *j_group;
	cJSON *j_clientlist, *j_client, *j_username;
	cJSON *j_roles, *j_role, *j_rolename;

	struct dynsec__group *group;
	struct dynsec__role *role;
	char *str;
	int priority;

	j_groups = cJSON_GetObjectItem(tree, "groups");
	if(j_groups == NULL){
		return 0;
	}

	if(cJSON_IsArray(j_groups) == false){
		return 1;
	}

	cJSON_ArrayForEach(j_group, j_groups){
		if(cJSON_IsObject(j_group) == true){
			group = mosquitto_calloc(1, sizeof(struct dynsec__group));
			if(group == NULL){
				return MOSQ_ERR_NOMEM;
			}

			/* Group name */
			if(json_get_string(j_group, "groupname", &str, false) != MOSQ_ERR_SUCCESS){
				mosquitto_free(group);
				continue;
			}
			group->groupname = strdup(str);
			if(group->groupname == NULL){
				mosquitto_free(group);
				continue;
			}

			/* Text name */
			if(json_get_string(j_group, "textname", &str, false) == MOSQ_ERR_SUCCESS){
				if(str){
					group->text_name = strdup(str);
					if(group->text_name == NULL){
						mosquitto_free(group->groupname);
						mosquitto_free(group);
						continue;
					}
				}
			}

			/* Text description */
			if(json_get_string(j_group, "textdescription", &str, false) == MOSQ_ERR_SUCCESS){
				if(str){
					group->text_description = strdup(str);
					if(group->text_description == NULL){
						mosquitto_free(group->text_name);
						mosquitto_free(group->groupname);
						mosquitto_free(group);
						continue;
					}
				}
			}

			/* Roles */
			j_roles = cJSON_GetObjectItem(j_group, "roles");
			if(j_roles && cJSON_IsArray(j_roles)){
				cJSON_ArrayForEach(j_role, j_roles){
					if(cJSON_IsObject(j_role)){
						j_rolename = cJSON_GetObjectItem(j_role, "rolename");
						if(j_rolename && cJSON_IsString(j_rolename)){
							json_get_int(j_role, "priority", &priority, true, -1);
							role = dynsec_roles__find(j_rolename->valuestring);
							dynsec_rolelist__group_add(group, role, priority);
						}
					}
				}
			}

			/* This must go before clients are loaded, otherwise the group won't be found */
			HASH_ADD_KEYPTR(hh, local_groups, group->groupname, strlen(group->groupname), group);

			/* Clients */
			j_clientlist = cJSON_GetObjectItem(j_group, "clients");
			if(j_clientlist && cJSON_IsArray(j_clientlist)){
				cJSON_ArrayForEach(j_client, j_clientlist){
					if(cJSON_IsObject(j_client)){
						j_username = cJSON_GetObjectItem(j_client, "username");
						if(j_username && cJSON_IsString(j_username)){
							json_get_int(j_client, "priority", &priority, true, -1);
							dynsec_groups__add_client(j_username->valuestring, group->groupname, priority, false);
						}
					}
				}
			}
		}
	}
	HASH_SORT(local_groups, group_cmp);

	j_group = cJSON_GetObjectItem(tree, "anonymousGroup");
	if(j_group && cJSON_IsString(j_group)){
		dynsec_anonymous_group = dynsec_groups__find(j_group->valuestring);
	}

	return 0;
}


/* ################################################################
 * #
 * # Config load and save
 * #
 * ################################################################ */


static int dynsec__config_add_groups(cJSON *j_groups)
{
	struct dynsec__group *group, *group_tmp = NULL;
	cJSON *j_group, *j_clients, *j_roles;

	HASH_ITER(hh, local_groups, group, group_tmp){
		j_group = cJSON_CreateObject();
		if(j_group == NULL) return 1;
		cJSON_AddItemToArray(j_groups, j_group);

		if(cJSON_AddStringToObject(j_group, "groupname", group->groupname) == NULL
				|| (group->text_name && cJSON_AddStringToObject(j_group, "textname", group->text_name) == NULL)
				|| (group->text_description && cJSON_AddStringToObject(j_group, "textdescription", group->text_description) == NULL)
				){

			return 1;
		}

		j_roles = dynsec_rolelist__all_to_json(group->rolelist);
		if(j_roles == NULL){
			return 1;
		}
		cJSON_AddItemToObject(j_group, "roles", j_roles);

		j_clients = dynsec_clientlist__all_to_json(group->clientlist);
		if(j_clients == NULL){
			return 1;
		}
		cJSON_AddItemToObject(j_group, "clients", j_clients);
	}

	return 0;
}

static int dynsec__config_add_groups_yaml(yaml_emitter_t *emitter, yaml_event_t *event)
{
    struct dynsec__group *group, *group_tmp = NULL;


    printf("%s:%d\n", __FILE__, __LINE__);

    yaml_sequence_start_event_initialize(event, NULL, (yaml_char_t *)YAML_SEQ_TAG,
                                         1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 0;

    printf("%s:%d\n", __FILE__, __LINE__);

    HASH_ITER(hh, local_groups, group, group_tmp){

        printf("%s:%d\n", __FILE__, __LINE__);

        yaml_mapping_start_event_initialize(event, NULL, (yaml_char_t *)YAML_MAP_TAG,
                                            1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, event)) return 0;

        if (!yaml_emit_string_field(emitter, event, "groupname", group->groupname)) return 0;
        if (group->text_name && !yaml_emit_string_field(emitter, event, "textname", group->text_name)) return 0;
        if (group->text_description && !yaml_emit_string_field(emitter, event, "textdescription", group->text_description)) return 0;


        printf("%s:%d\n", __FILE__, __LINE__);
        yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,
                                     (yaml_char_t *)"roles", strlen("roles"), 1, 0, YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, event)) return 0;

        printf("%s:%d\n", __FILE__, __LINE__);
        if (!dynsec_rolelist__all_to_yaml(group->rolelist, emitter, event)) return 0;

        yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,
                                     (yaml_char_t *)"clients", strlen("clients"), 1, 0, YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, event)) return 0;
        printf("%s:%d\n", __FILE__, __LINE__);

        if (!dynsec_clientlist__all_to_yaml(group->clientlist, emitter, event)) return 0;

        yaml_mapping_end_event_initialize(event);
        if (!yaml_emitter_emit(emitter, event)) return 0;
    }

    printf("%s:%d\n", __FILE__, __LINE__);
    yaml_sequence_end_event_initialize(event);
    if (!yaml_emitter_emit(emitter, event)) return 0;

    printf("%s:%d\n", __FILE__, __LINE__);

    return 1;
}

int dynsec_groups__config_save_yaml(yaml_emitter_t *emitter, yaml_event_t *event)
{
    yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,
                                 (yaml_char_t *)"groups", strlen("groups"), 1, 0, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 0;
    if (!dynsec__config_add_groups_yaml(emitter, event)) return 0;

    if (dynsec_anonymous_group && !yaml_emit_string_field(emitter, event, "anonymousGroup", dynsec_anonymous_group->groupname)) return 0;

    return 1;
}

int dynsec_groups__config_save(cJSON *tree)
{
	cJSON *j_groups;

	j_groups = cJSON_CreateArray();
	if(j_groups == NULL){
		return 1;
	}
	cJSON_AddItemToObject(tree, "groups", j_groups);
	if(dynsec__config_add_groups(j_groups)){
		return 1;
	}

	if(dynsec_anonymous_group
			&& cJSON_AddStringToObject(tree, "anonymousGroup", dynsec_anonymous_group->groupname) == NULL){

		return 1;
	}

	return 0;
}


int dynsec_groups__process_create(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *groupname, *text_name, *text_description;
	struct dynsec__group *group = NULL;
	int rc = MOSQ_ERR_SUCCESS;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createGroup", "Invalid/missing groupname", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)strlen(groupname)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createGroup", "Group name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "textname", &text_name, true) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createGroup", "Invalid/missing textname", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "textdescription", &text_description, true) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createGroup", "Invalid/missing textdescription", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	group = dynsec_groups__find(groupname);
	if(group){
		dynsec__command_reply(j_responses, context, "createGroup", "Group already exists", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	group = mosquitto_calloc(1, sizeof(struct dynsec__group));
	if(group == NULL){
		dynsec__command_reply(j_responses, context, "createGroup", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}
	group->groupname = strdup(groupname);
	if(group->groupname == NULL){
		dynsec__command_reply(j_responses, context, "createGroup", "Internal error", correlation_data);
		group__free_item(group);
		return MOSQ_ERR_NOMEM;
	}
	if(text_name){
		group->text_name = strdup(text_name);
		if(group->text_name == NULL){
			dynsec__command_reply(j_responses, context, "createGroup", "Internal error", correlation_data);
			group__free_item(group);
			return MOSQ_ERR_NOMEM;
		}
	}
	if(text_description){
		group->text_description = strdup(text_description);
		if(group->text_description == NULL){
			dynsec__command_reply(j_responses, context, "createGroup", "Internal error", correlation_data);
			group__free_item(group);
			return MOSQ_ERR_NOMEM;
		}
	}

	rc = dynsec_rolelist__load_from_json(command, &group->rolelist);
	if(rc == MOSQ_ERR_SUCCESS || rc == ERR_LIST_NOT_FOUND){
	}else if(rc == MOSQ_ERR_NOT_FOUND){
		dynsec__command_reply(j_responses, context, "createGroup", "Role not found", correlation_data);
		group__free_item(group);
		return MOSQ_ERR_INVAL;
	}else{
		dynsec__command_reply(j_responses, context, "createGroup", "Internal error", correlation_data);
		group__free_item(group);
		return MOSQ_ERR_INVAL;
	}

	HASH_ADD_KEYPTR_INORDER(hh, local_groups, group->groupname, strlen(group->groupname), group, group_cmp);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | createGroup | groupname=%s",
			admin_clientid, admin_username, groupname);

	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "createGroup", NULL, correlation_data);
	return MOSQ_ERR_SUCCESS;
}


int dynsec_groups__process_delete(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *groupname;
	struct dynsec__group *group;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "deleteGroup", "Invalid/missing groupname", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)strlen(groupname)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "deleteGroup", "Group name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	group = dynsec_groups__find(groupname);
	if(group){
		if(group == dynsec_anonymous_group){
			dynsec__command_reply(j_responses, context, "deleteGroup", "Deleting the anonymous group is forbidden", correlation_data);
			return MOSQ_ERR_INVAL;
		}

		/* Enforce any changes */
		group__kick_all(group);

		dynsec__remove_all_roles_from_group(group);
		group__free_item(group);
		dynsec__config_save();
		dynsec__command_reply(j_responses, context, "deleteGroup", NULL, correlation_data);

		admin_clientid = mosquitto_client_id(context);
		admin_username = mosquitto_client_username(context);
		mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | deleteGroup | groupname=%s",
				admin_clientid, admin_username, groupname);

		return MOSQ_ERR_SUCCESS;
	}else{
		dynsec__command_reply(j_responses, context, "deleteGroup", "Group not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}
}


int dynsec_groups__add_client(const char *username, const char *groupname, int priority, bool update_config)
{
	struct dynsec__client *client;
	struct dynsec__clientlist *clientlist;
	struct dynsec__group *group;
	int rc;

	client = dynsec_clients__find(username);
	if(client == NULL){
		return ERR_USER_NOT_FOUND;
	}

	group = dynsec_groups__find(groupname);
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
		dynsec__config_save();
	}

	return MOSQ_ERR_SUCCESS;
}


int dynsec_groups__process_add_client(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *username, *groupname;
	int rc;
	int priority;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "username", &username, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addGroupClient", "Invalid/missing username", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(username, (int)strlen(username)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addGroupClient", "Username not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addGroupClient", "Invalid/missing groupname", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)strlen(groupname)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addGroupClient", "Group name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	json_get_int(command, "priority", &priority, true, -1);

	rc = dynsec_groups__add_client(username, groupname, priority, true);
	if(rc == MOSQ_ERR_SUCCESS){
		admin_clientid = mosquitto_client_id(context);
		admin_username = mosquitto_client_username(context);
		mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | addGroupClient | groupname=%s | username=%s | priority=%d",
				admin_clientid, admin_username, groupname, username, priority);

		dynsec__command_reply(j_responses, context, "addGroupClient", NULL, correlation_data);
	}else if(rc == ERR_USER_NOT_FOUND){
		dynsec__command_reply(j_responses, context, "addGroupClient", "Client not found", correlation_data);
	}else if(rc == ERR_GROUP_NOT_FOUND){
		dynsec__command_reply(j_responses, context, "addGroupClient", "Group not found", correlation_data);
	}else if(rc == MOSQ_ERR_ALREADY_EXISTS){
		dynsec__command_reply(j_responses, context, "addGroupClient", "Client is already in this group", correlation_data);
	}else{
		dynsec__command_reply(j_responses, context, "addGroupClient", "Internal error", correlation_data);
	}

	/* Enforce any changes */
	mosquitto_kick_client_by_username(username, false);

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

int dynsec_groups__remove_client(const char *username, const char *groupname, bool update_config)
{
	struct dynsec__client *client;
	struct dynsec__group *group;

	client = dynsec_clients__find(username);
	if(client == NULL){
		return ERR_USER_NOT_FOUND;
	}

	group = dynsec_groups__find(groupname);
	if(group == NULL){
		return ERR_GROUP_NOT_FOUND;
	}

	dynsec_clientlist__remove(&group->clientlist, client);
	dynsec_grouplist__remove(&client->grouplist, group);

	if(update_config){
		dynsec__config_save();
	}
	return MOSQ_ERR_SUCCESS;
}

int dynsec_groups__process_remove_client(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *username, *groupname;
	int rc;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "username", &username, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeGroupClient", "Invalid/missing username", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(username, (int)strlen(username)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeGroupClient", "Username not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeGroupClient", "Invalid/missing groupname", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)strlen(groupname)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeGroupClient", "Group name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	rc = dynsec_groups__remove_client(username, groupname, true);
	if(rc == MOSQ_ERR_SUCCESS){
		admin_clientid = mosquitto_client_id(context);
		admin_username = mosquitto_client_username(context);
		mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | removeGroupClient | groupname=%s | username=%s",
				admin_clientid, admin_username, groupname, username);

		dynsec__command_reply(j_responses, context, "removeGroupClient", NULL, correlation_data);
	}else if(rc == ERR_USER_NOT_FOUND){
		dynsec__command_reply(j_responses, context, "removeGroupClient", "Client not found", correlation_data);
	}else if(rc == ERR_GROUP_NOT_FOUND){
		dynsec__command_reply(j_responses, context, "removeGroupClient", "Group not found", correlation_data);
	}else{
		dynsec__command_reply(j_responses, context, "removeGroupClient", "Internal error", correlation_data);
	}

	/* Enforce any changes */
	mosquitto_kick_client_by_username(username, false);

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


int dynsec_groups__process_list(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	bool verbose;
	cJSON *tree, *j_groups, *j_group, *j_data;
	struct dynsec__group *group, *group_tmp = NULL;
	int i, count, offset;
	const char *admin_clientid, *admin_username;

	json_get_bool(command, "verbose", &verbose, true, false);
	json_get_int(command, "count", &count, true, -1);
	json_get_int(command, "offset", &offset, true, 0);

	tree = cJSON_CreateObject();
	if(tree == NULL){
		dynsec__command_reply(j_responses, context, "listGroups", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	if(cJSON_AddStringToObject(tree, "command", "listGroups") == NULL
			|| (j_data = cJSON_AddObjectToObject(tree, "data")) == NULL
			|| cJSON_AddIntToObject(j_data, "totalCount", (int)HASH_CNT(hh, local_groups)) == NULL
			|| (j_groups = cJSON_AddArrayToObject(j_data, "groups")) == NULL
			|| (correlation_data && cJSON_AddStringToObject(tree, "correlationData", correlation_data) == NULL)
			){

		cJSON_Delete(tree);
		dynsec__command_reply(j_responses, context, "listGroups", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	i = 0;
	HASH_ITER(hh, local_groups, group, group_tmp){
		if(i>=offset){
			if(verbose){
				j_group = add_group_to_json(group);
				if(j_group == NULL){
					cJSON_Delete(tree);
					dynsec__command_reply(j_responses, context, "listGroups", "Internal error", correlation_data);
					return MOSQ_ERR_NOMEM;
				}
				cJSON_AddItemToArray(j_groups, j_group);

			}else{
				j_group = cJSON_CreateString(group->groupname);
				if(j_group){
					cJSON_AddItemToArray(j_groups, j_group);
				}else{
					cJSON_Delete(tree);
					dynsec__command_reply(j_responses, context, "listGroups", "Internal error", correlation_data);
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

	cJSON_AddItemToArray(j_responses, tree);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | listGroups | verbose=%s | count=%d | offset=%d",
			admin_clientid, admin_username, verbose?"true":"false", count, offset);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_groups__process_get(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *groupname;
	cJSON *tree, *j_group, *j_data;
	struct dynsec__group *group;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "getGroup", "Invalid/missing groupname", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)strlen(groupname)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "getGroup", "Group name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	tree = cJSON_CreateObject();
	if(tree == NULL){
		dynsec__command_reply(j_responses, context, "getGroup", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	if(cJSON_AddStringToObject(tree, "command", "getGroup") == NULL
			|| (j_data = cJSON_AddObjectToObject(tree, "data")) == NULL
			|| (correlation_data && cJSON_AddStringToObject(tree, "correlationData", correlation_data) == NULL)
			){

		cJSON_Delete(tree);
		dynsec__command_reply(j_responses, context, "getGroup", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	group = dynsec_groups__find(groupname);
	if(group){
		j_group = add_group_to_json(group);
		if(j_group == NULL){
			cJSON_Delete(tree);
			dynsec__command_reply(j_responses, context, "getGroup", "Internal error", correlation_data);
			return MOSQ_ERR_NOMEM;
		}
		cJSON_AddItemToObject(j_data, "group", j_group);
	}else{
		cJSON_Delete(tree);
		dynsec__command_reply(j_responses, context, "getGroup", "Group not found", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	cJSON_AddItemToArray(j_responses, tree);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | getGroup | groupname=%s",
			admin_clientid, admin_username, groupname);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_groups__process_remove_role(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *groupname, *rolename;
	struct dynsec__group *group;
	struct dynsec__role *role;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeGroupRole", "Invalid/missing groupname", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)strlen(groupname)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeGroupRole", "Group name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeGroupRole", "Invalid/missing rolename", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeGroupRole", "Role name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	group = dynsec_groups__find(groupname);
	if(group == NULL){
		dynsec__command_reply(j_responses, context, "removeGroupRole", "Group not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	role = dynsec_roles__find(rolename);
	if(role == NULL){
		dynsec__command_reply(j_responses, context, "removeGroupRole", "Role not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	dynsec_rolelist__group_remove(group, role);
	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "removeGroupRole", NULL, correlation_data);

	/* Enforce any changes */
	group__kick_all(group);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | removeGroupRole | groupname=%s | rolename=%s",
			admin_clientid, admin_username, groupname, rolename);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_groups__process_modify(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
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

	if(json_get_string(command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "modifyGroup", "Invalid/missing groupname", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)strlen(groupname)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "modifyGroup", "Group name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	group = dynsec_groups__find(groupname);
	if(group == NULL){
		dynsec__command_reply(j_responses, context, "modifyGroup", "Group not found", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "textname", &str, false) == MOSQ_ERR_SUCCESS){
		have_text_name = true;
		text_name = mosquitto_strdup(str);
		if(text_name == NULL){
			dynsec__command_reply(j_responses, context, "modifyGroup", "Internal error", correlation_data);
			rc = MOSQ_ERR_NOMEM;
			goto error;
		}
	}

	if(json_get_string(command, "textdescription", &str, false) == MOSQ_ERR_SUCCESS){
		have_text_description = true;
		text_description = mosquitto_strdup(str);
		if(text_description == NULL){
			dynsec__command_reply(j_responses, context, "modifyGroup", "Internal error", correlation_data);
			rc = MOSQ_ERR_NOMEM;
			goto error;
		}
	}

	rc = dynsec_rolelist__load_from_json(command, &rolelist);
	if(rc == MOSQ_ERR_SUCCESS){
		/* Apply changes below */
		have_rolelist = true;
	}else if(rc == ERR_LIST_NOT_FOUND){
		/* There was no list in the JSON, so no modification */
		rolelist = NULL;
	}else if(rc == MOSQ_ERR_NOT_FOUND){
		dynsec__command_reply(j_responses, context, "modifyGroup", "Role not found", correlation_data);
		rc = MOSQ_ERR_INVAL;
		goto error;
	}else{
		if(rc == MOSQ_ERR_INVAL){
			dynsec__command_reply(j_responses, context, "modifyGroup", "'roles' not an array or missing/invalid rolename", correlation_data);
		}else{
			dynsec__command_reply(j_responses, context, "modifyGroup", "Internal error", correlation_data);
		}
		rc = MOSQ_ERR_INVAL;
		goto error;
	}

	j_clients = cJSON_GetObjectItem(command, "clients");
	if(j_clients && cJSON_IsArray(j_clients)){
		/* Iterate over array to check clients are valid before proceeding */
		cJSON_ArrayForEach(j_client, j_clients){
			if(cJSON_IsObject(j_client)){
				jtmp = cJSON_GetObjectItem(j_client, "username");
				if(jtmp && cJSON_IsString(jtmp)){
					client = dynsec_clients__find(jtmp->valuestring);
					if(client == NULL){
						dynsec__command_reply(j_responses, context, "modifyGroup", "'clients' contains an object with a 'username' that does not exist", correlation_data);
						rc = MOSQ_ERR_INVAL;
						goto error;
					}
				}else{
					dynsec__command_reply(j_responses, context, "modifyGroup", "'clients' contains an object with an invalid 'username'", correlation_data);
					rc = MOSQ_ERR_INVAL;
					goto error;
				}
			}
		}

		/* Kick all clients in the *current* group */
		group__kick_all(group);
		dynsec__remove_all_clients_from_group(group);

		/* Now we can add the new clients to the group */
		cJSON_ArrayForEach(j_client, j_clients){
			if(cJSON_IsObject(j_client)){
				jtmp = cJSON_GetObjectItem(j_client, "username");
				if(jtmp && cJSON_IsString(jtmp)){
					json_get_int(j_client, "priority", &priority, true, -1);
					dynsec_groups__add_client(jtmp->valuestring, groupname, priority, false);
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
	dynsec__config_save();

	dynsec__command_reply(j_responses, context, "modifyGroup", NULL, correlation_data);

	/* Enforce any changes - kick any clients in the *new* group */
	group__kick_all(group);

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


int dynsec_groups__process_set_anonymous_group(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *groupname;
	struct dynsec__group *group = NULL;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "setAnonymousGroup", "Invalid/missing groupname", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(groupname, (int)strlen(groupname)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "setAnonymousGroup", "Group name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	group = dynsec_groups__find(groupname);
	if(group == NULL){
		dynsec__command_reply(j_responses, context, "setAnonymousGroup", "Group not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	dynsec_anonymous_group = group;

	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "setAnonymousGroup", NULL, correlation_data);

	/* Enforce any changes */
	mosquitto_kick_client_by_username(NULL, false);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | setAnonymousGroup | groupname=%s",
			admin_clientid, admin_username, groupname);

	return MOSQ_ERR_SUCCESS;
}

int dynsec_groups__process_get_anonymous_group(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	cJSON *tree, *j_data, *j_group;
	const char *groupname;
	const char *admin_clientid, *admin_username;

	UNUSED(command);

	tree = cJSON_CreateObject();
	if(tree == NULL){
		dynsec__command_reply(j_responses, context, "getAnonymousGroup", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	if(dynsec_anonymous_group){
		groupname = dynsec_anonymous_group->groupname;
	}else{
		groupname = "";
	}

	if(cJSON_AddStringToObject(tree, "command", "getAnonymousGroup") == NULL
			|| (j_data = cJSON_AddObjectToObject(tree, "data")) == NULL
			|| (j_group = cJSON_AddObjectToObject(j_data, "group")) == NULL
			|| cJSON_AddStringToObject(j_group, "groupname", groupname) == NULL
			|| (correlation_data && cJSON_AddStringToObject(tree, "correlationData", correlation_data) == NULL)
			){

		cJSON_Delete(tree);
		dynsec__command_reply(j_responses, context, "getAnonymousGroup", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	cJSON_AddItemToArray(j_responses, tree);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | getAnonymousGroup",
			admin_clientid, admin_username);

	return MOSQ_ERR_SUCCESS;
}
