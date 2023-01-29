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
   Akos Vandra-Meyer - addition of YAML file format
*/

#include "config.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <uthash.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "json_help.h"

#include "dynamic_security.h"

int dynsec_groups__config_load_json(struct dynsec__data *data, cJSON *tree)
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
            /* Group name */
            if(json_get_string(j_group, "groupname", &str, false) != MOSQ_ERR_SUCCESS){
                continue;
            }

            group = dynsec_groups__find(data, str);

            /* Text name */
            if(json_get_string(j_group, "textname", &str, false) == MOSQ_ERR_SUCCESS){
                if(str){
                    group->text_name = strdup(str);
                    if(group->text_name == NULL){
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
                            role = dynsec_roles__find(data, j_rolename->valuestring);
                            dynsec_rolelist__group_add(group, role, priority);
                        }
                    }
                }
            }

            /* Clients */
            j_clientlist = cJSON_GetObjectItem(j_group, "clients");
            if(j_clientlist && cJSON_IsArray(j_clientlist)){
                cJSON_ArrayForEach(j_client, j_clientlist){
                    if(cJSON_IsObject(j_client)){
                        j_username = cJSON_GetObjectItem(j_client, "username");
                        if(j_username && cJSON_IsString(j_username)){
                            json_get_int(j_client, "priority", &priority, true, -1);
                            dynsec_groups__add_client(data, j_username->valuestring, group->groupname, priority, false);
                        }
                    }
                }
            }
        }
    }

    j_group = cJSON_GetObjectItem(tree, "anonymousGroup");
    if(j_group && cJSON_IsString(j_group)){
        data->anonymous_group = dynsec_groups__find(data, j_group->valuestring);
    }

    return 0;
}

static int dynsec__config_add_groups(struct dynsec__data *data, cJSON *j_groups)
{
    struct dynsec__group *group, *group_tmp = NULL;
    cJSON *j_group, *j_clients, *j_roles;

    HASH_ITER(hh, data->groups, group, group_tmp){
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

int dynsec_groups__config_save_json(struct dynsec__data *data, cJSON *tree)
{
    cJSON *j_groups;

    j_groups = cJSON_CreateArray();
    if(j_groups == NULL){
        return 1;
    }
    cJSON_AddItemToObject(tree, "groups", j_groups);
    if(dynsec__config_add_groups(data, j_groups)){
        return 1;
    }

    if(data->anonymous_group
       && cJSON_AddStringToObject(tree, "anonymousGroup", data->anonymous_group->groupname) == NULL){

        return 1;
    }

    return 0;
}
