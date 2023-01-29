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

cJSON *add_role_to_json(struct dynsec__role *role, bool verbose);

int dynsec_roles__config_save_json(struct dynsec__data *data, cJSON *tree)
{
    cJSON *j_roles, *j_role;
    struct dynsec__role *role, *role_tmp = NULL;

    if((j_roles = cJSON_AddArrayToObject(tree, "roles")) == NULL){
        return 1;
    }

    HASH_ITER(hh, data->roles, role, role_tmp){
        j_role = add_role_to_json(role, true);
        if(j_role == NULL){
            return 1;
        }
        cJSON_AddItemToArray(j_roles, j_role);
    }

    return 0;
}

int dynsec_roles__config_load_json(struct dynsec__data *data, cJSON *tree)
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
            /* Role name */
            jtmp = cJSON_GetObjectItem(j_role, "rolename");
            if(jtmp == NULL){
                continue;
            }

            role = dynsec_roles__create(jtmp->valuestring);

            /* Text name */
            jtmp = cJSON_GetObjectItem(j_role, "textname");
            if(jtmp != NULL){
                role->text_name = mosquitto_strdup(jtmp->valuestring);
                if(role->text_name == NULL){
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
                    mosquitto_free(role);
                    continue;
                }
            }

            /* ACLs */
            j_acls = cJSON_GetObjectItem(j_role, "acls");
            if(j_acls && cJSON_IsArray(j_acls)){
                if(dynsec_acls__load_json(j_acls, ACL_TYPE_PUB_C_SEND, &role->acls.publish_c_send) != 0
                   || dynsec_acls__load_json(j_acls, ACL_TYPE_PUB_C_RECV, &role->acls.publish_c_recv) != 0
                   || dynsec_acls__load_json(j_acls, ACL_TYPE_SUB_LITERAL, &role->acls.subscribe_literal) != 0
                   || dynsec_acls__load_json(j_acls, ACL_TYPE_SUB_PATTERN, &role->acls.subscribe_pattern) != 0
                   || dynsec_acls__load_json(j_acls, ACL_TYPE_UNSUB_LITERAL, &role->acls.unsubscribe_literal) != 0
                   || dynsec_acls__load_json(j_acls, ACL_TYPE_UNSUB_PATTERN, &role->acls.unsubscribe_pattern) != 0
                        ){

                    mosquitto_free(role);
                    continue;
                }
            }

            dynsec_roles__insert(data, role);
        }
    }

    return 0;
}

cJSON *add_role_to_json(struct dynsec__role *role, bool verbose)
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
           || cJSON_AddBoolToObject(j_role, "allowwildcardsubs", role->allow_wildcard_subs) == NULL
                ){

            cJSON_Delete(j_role);
            return NULL;
        }
        if(dynsec_acls__to_json(j_role, role)){
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

