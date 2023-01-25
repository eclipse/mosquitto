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
#include <yaml.h>

#include "dynamic_security.h"
#include "json_help.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "yaml_help.h"


/* ################################################################
 * #
 * # Utility functions
 * #
 * ################################################################ */

static int rolelist_cmp(void *a, void *b)
{
	int prio;
	struct dynsec__rolelist *rolelist_a = a;
	struct dynsec__rolelist *rolelist_b = b;

	prio = rolelist_b->priority - rolelist_a->priority;
	if(prio == 0){
		return strcmp(rolelist_a->rolename, rolelist_b->rolename);
	}else{
		return prio;
	}
}


static void dynsec_rolelist__free_item(struct dynsec__rolelist **base_rolelist, struct dynsec__rolelist *rolelist)
{
	HASH_DELETE(hh, *base_rolelist, rolelist);
	mosquitto_free(rolelist);
}

void dynsec_rolelist__cleanup(struct dynsec__rolelist **base_rolelist)
{
	struct dynsec__rolelist *rolelist, *rolelist_tmp;

	HASH_ITER(hh, *base_rolelist, rolelist, rolelist_tmp){
		dynsec_rolelist__free_item(base_rolelist, rolelist);
	}
}

int dynsec_rolelist__remove_role(struct dynsec__rolelist **base_rolelist, const struct dynsec__role *role)
{
	struct dynsec__rolelist *found_rolelist;

	HASH_FIND(hh, *base_rolelist, role->rolename, strlen(role->rolename), found_rolelist);
	if(found_rolelist){
		dynsec_rolelist__free_item(base_rolelist, found_rolelist);
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_NOT_FOUND;
	}
}


int dynsec_rolelist__client_remove(struct dynsec__client *client, struct dynsec__role *role)
{
	int rc;
	struct dynsec__clientlist *found_clientlist;

	rc = dynsec_rolelist__remove_role(&client->rolelist, role);
	if(rc) return rc;

	HASH_FIND(hh, role->clientlist, client->username, strlen(client->username), found_clientlist);
	if(found_clientlist){
		HASH_DELETE(hh, role->clientlist, found_clientlist);
		mosquitto_free(found_clientlist);
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_NOT_FOUND;
	}
}


void dynsec_rolelist__group_remove(struct dynsec__group *group, struct dynsec__role *role)
{
	dynsec_rolelist__remove_role(&group->rolelist, role);
	dynsec_grouplist__remove(&role->grouplist, group);
}


int dynsec_rolelist__add(struct dynsec__rolelist **base_rolelist, struct dynsec__role *role, int priority)
{
	struct dynsec__rolelist *rolelist;
	size_t rolename_len;

	if(role == NULL) return MOSQ_ERR_INVAL;
	rolename_len = strlen(role->rolename);
	if(rolename_len == 0) return MOSQ_ERR_INVAL;

	HASH_FIND(hh, *base_rolelist, role->rolename, rolename_len, rolelist);
	if(rolelist){
		return MOSQ_ERR_ALREADY_EXISTS;
	}else{
		rolelist = mosquitto_calloc(1, sizeof(struct dynsec__rolelist) + rolename_len + 1);
		if(rolelist == NULL) return MOSQ_ERR_NOMEM;

		rolelist->role = role;
		rolelist->priority = priority;
		strncpy(rolelist->rolename, role->rolename, rolename_len+1);
		HASH_ADD_INORDER(hh, *base_rolelist, rolename, rolename_len, rolelist, rolelist_cmp);
		return MOSQ_ERR_SUCCESS;
	}
}


int dynsec_rolelist__client_add(struct dynsec__client *client, struct dynsec__role *role, int priority)
{
	struct dynsec__rolelist *rolelist;
	int rc;

	rc = dynsec_rolelist__add(&client->rolelist, role, priority);
	if(rc) return rc;

	HASH_FIND(hh, client->rolelist, role->rolename, strlen(role->rolename), rolelist);
	if(rolelist == NULL){
		/* This should never happen because the above add_role succeeded. */
		return MOSQ_ERR_UNKNOWN;
	}

	rc = dynsec_clientlist__add(&role->clientlist, client, priority);
	if(rc){
		dynsec_rolelist__remove_role(&client->rolelist, role);
	}

	return rc;
}


int dynsec_rolelist__group_add(struct dynsec__group *group, struct dynsec__role *role, int priority)
{
	int rc;

	rc = dynsec_rolelist__add(&group->rolelist, role, priority);
	if(rc) return rc;

	rc = dynsec_grouplist__add(&role->grouplist, group, priority);
	if(rc){
		dynsec_rolelist__remove_role(&group->rolelist, role);
	}
	return rc;
}


int dynsec_rolelist__load_from_json(struct dynsec__data *data, cJSON *command, struct dynsec__rolelist **rolelist)
{
	cJSON *j_roles, *j_role, *j_rolename;
	int priority;
	struct dynsec__role *role;

	j_roles = cJSON_GetObjectItem(command, "roles");
	if(j_roles){
		if(cJSON_IsArray(j_roles)){
			cJSON_ArrayForEach(j_role, j_roles){
				j_rolename = cJSON_GetObjectItem(j_role, "rolename");
				if(j_rolename && cJSON_IsString(j_rolename)){
					json_get_int(j_role, "priority", &priority, true, -1);
					role = dynsec_roles__find(data, j_rolename->valuestring);
					if(role){
						dynsec_rolelist__add(rolelist, role, priority);
					}else{
						dynsec_rolelist__cleanup(rolelist);
						return MOSQ_ERR_NOT_FOUND;
					}
				}else{
					return MOSQ_ERR_INVAL;
				}
			}
			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_INVAL;
		}
	}else{
		return ERR_LIST_NOT_FOUND;
	}
}

int dynsec_rolelist__load_from_yaml(yaml_parser_t *parser, yaml_event_t *event, struct dynsec__data *data, struct dynsec__rolelist **rolelist)
{

    YAML_PARSER_SEQUENCE_FOR_ALL(parser, event, { goto error; }, {
        printf("%s:%d\n", __FILE__, __LINE__);
        char* rolename = NULL;
        long int priority = -1;

        printf("%s:%d\n", __FILE__, __LINE__);
        YAML_PARSER_MAPPING_FOR_ALL(parser, event, key, { goto error; }, {
                printf("%s:%d\n", __FILE__, __LINE__);
                if (strcmp(key, "rolename") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_STRING(event, &rolename, { goto error; });
                } else if (strcmp(key, "priority") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_LONG_INT(event, &priority, { goto error; });
                } else {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    mosquitto_log_printf(MOSQ_LOG_ERR, "Unexpected key for role config %s \n", key);
                    yaml_dump_block(parser, event);
                }
        });

        printf("%s:%d\n", __FILE__, __LINE__);

        if (rolename) {
            printf("rn = %s\n", rolename);
            struct dynsec__role *role = dynsec_roles__find_or_create(data, rolename);
            if (role) {
                printf("%s:%d\n", __FILE__, __LINE__);
                dynsec_rolelist__add(rolelist, role, (int)priority);
            } else {
                printf("OUT OF MEMORY %s:%d\n", __FILE__, __LINE__);
                free(rolename);
                goto error;
            }
        }

        printf("%s:%d\n", __FILE__, __LINE__);
    });

    printf("%s:%d\n", __FILE__, __LINE__);

    return 0;
error:
    dynsec_rolelist__cleanup(rolelist);
    return 1;
}


int dynsec_rolelist__all_to_yaml(struct dynsec__rolelist *base_rolelist, yaml_emitter_t *emitter, yaml_event_t *event)
{
    struct dynsec__rolelist *rolelist, *rolelist_tmp;

    yaml_sequence_start_event_initialize(event, NULL, (yaml_char_t *)YAML_SEQ_TAG,
                                         1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 1;


    HASH_ITER(hh, base_rolelist, rolelist, rolelist_tmp){

        yaml_mapping_start_event_initialize(event, NULL, (yaml_char_t *)YAML_MAP_TAG,
                                            1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, event)) return 1;

        if (!yaml_emit_string_field(emitter, event, "rolename", rolelist->role->rolename)) return 1;
        if (rolelist->priority != -1 && !yaml_emit_int_field(emitter, event, "priority", rolelist->priority)) return 1;

        yaml_mapping_end_event_initialize(event);
        if (!yaml_emitter_emit(emitter, event)) return 1;
    }

    yaml_sequence_end_event_initialize(event);
    if (!yaml_emitter_emit(emitter, event)) return 1;

    return 0;
}


cJSON *dynsec_rolelist__all_to_json(struct dynsec__rolelist *base_rolelist)
{
	struct dynsec__rolelist *rolelist, *rolelist_tmp;
	cJSON *j_roles, *j_role;

	j_roles = cJSON_CreateArray();
	if(j_roles == NULL) return NULL;

	HASH_ITER(hh, base_rolelist, rolelist, rolelist_tmp){
		j_role = cJSON_CreateObject();
		if(j_role == NULL){
			cJSON_Delete(j_roles);
			return NULL;
		}
		cJSON_AddItemToArray(j_roles, j_role);

		if(cJSON_AddStringToObject(j_role, "rolename", rolelist->role->rolename) == NULL
				|| (rolelist->priority != -1 && cJSON_AddIntToObject(j_role, "priority", rolelist->priority) == NULL)
				){

			cJSON_Delete(j_roles);
			return NULL;
		}
	}
	return j_roles;
}
