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

static cJSON *add_role_to_json(struct dynsec__role *role);

static int add_single_acl_to_json(cJSON *j_array, const char *acl_type, struct dynsec__acl *acl)
{
    struct dynsec__acl *iter, *tmp = NULL;
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

int dynsec_roles__config_save_json(struct dynsec__data *data, cJSON *tree)
{
    cJSON *j_roles, *j_role;
    struct dynsec__role *role, *role_tmp = NULL;

    if((j_roles = cJSON_AddArrayToObject(tree, "roles")) == NULL){
        return 1;
    }

    HASH_ITER(hh, data->roles, role, role_tmp){
        j_role = add_role_to_json(role);
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


static int dynsec_roles__acl_load(cJSON *j_acls, const char *key, struct dynsec__acl **acllist)
{
    cJSON *j_acl, *j_type, *jtmp;
    struct dynsec__acl *acl;
    size_t topic_len;

    cJSON_ArrayForEach(j_acl, j_acls){
        j_type = cJSON_GetObjectItem(j_acl, "acltype");
        if(j_type == NULL || !cJSON_IsString(j_type) || strcasecmp(j_type->valuestring, key) != 0){
            continue;
        }
        jtmp = cJSON_GetObjectItem(j_acl, "topic");
        if(!jtmp || !cJSON_IsString(jtmp)){
            continue;
        }

        topic_len = strlen(jtmp->valuestring);
        if(topic_len == 0){
            continue;
        }

        acl = mosquitto_calloc(1, sizeof(struct dynsec__acl) + topic_len + 1);
        if(acl == NULL){
            return 1;
        }
        strncpy(acl->topic, jtmp->valuestring, topic_len+1);

        json_get_int(j_acl, "priority", &acl->priority, true, 0);
        json_get_bool(j_acl, "allow", &acl->allow, true, false);

        jtmp = cJSON_GetObjectItem(j_acl, "allow");
        if(jtmp && cJSON_IsBool(jtmp)){
            acl->allow = cJSON_IsTrue(jtmp);
        }

        HASH_ADD_INORDER(hh, *acllist, topic, topic_len, acl, insert_acl_cmp);
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

            role = dynsec_roles__find_or_create(data, jtmp->valuestring);

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
                if(dynsec_roles__acl_load(j_acls, ACL_TYPE_PUB_C_SEND, &role->acls.publish_c_send) != 0
                   || dynsec_roles__acl_load(j_acls, ACL_TYPE_PUB_C_RECV, &role->acls.publish_c_recv) != 0
                   || dynsec_roles__acl_load(j_acls, ACL_TYPE_SUB_LITERAL, &role->acls.subscribe_literal) != 0
                   || dynsec_roles__acl_load(j_acls, ACL_TYPE_SUB_PATTERN, &role->acls.subscribe_pattern) != 0
                   || dynsec_roles__acl_load(j_acls, ACL_TYPE_UNSUB_LITERAL, &role->acls.unsubscribe_literal) != 0
                   || dynsec_roles__acl_load(j_acls, ACL_TYPE_UNSUB_PATTERN, &role->acls.unsubscribe_pattern) != 0
                        ){

                    mosquitto_free(role);
                    continue;
                }
            }
        }
    }

    return 0;
}

static cJSON *add_role_to_json(struct dynsec__role *role)
{
    cJSON *j_role = NULL;

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
    if(add_acls_to_json(j_role, role)){
        cJSON_Delete(j_role);
        return NULL;
    }

    return j_role;
}

