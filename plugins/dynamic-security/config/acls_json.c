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

int dynsec_acls__to_json(cJSON *j_role, struct dynsec__role *role)
{
    cJSON *j_acls;

    if((j_acls = cJSON_AddArrayToObject(j_role, "acls")) == NULL){
        return 1;
    }

    if(dynsec_acllist__to_json(j_acls, role->acls.publish_c_send, ACL_TYPE_PUB_C_SEND) != MOSQ_ERR_SUCCESS
       || dynsec_acllist__to_json(j_acls, role->acls.publish_c_recv, ACL_TYPE_PUB_C_RECV) != MOSQ_ERR_SUCCESS
       || dynsec_acllist__to_json(j_acls, role->acls.subscribe_literal, ACL_TYPE_SUB_LITERAL) != MOSQ_ERR_SUCCESS
       || dynsec_acllist__to_json(j_acls, role->acls.subscribe_pattern, ACL_TYPE_SUB_PATTERN) != MOSQ_ERR_SUCCESS
       || dynsec_acllist__to_json(j_acls, role->acls.unsubscribe_literal, ACL_TYPE_UNSUB_LITERAL) != MOSQ_ERR_SUCCESS
       || dynsec_acllist__to_json(j_acls, role->acls.unsubscribe_pattern, ACL_TYPE_UNSUB_PATTERN) != MOSQ_ERR_SUCCESS
            ){
        return 1;
    }
    return 0;
}

int dynsec_acls__load_json(cJSON *j_acls, const char *key, struct dynsec__acl **acllist)
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

        dynsec_acllist__add(acllist, acl);
    }

    return 0;
}
