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
