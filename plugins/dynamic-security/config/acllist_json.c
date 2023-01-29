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

int dynsec_acllist__to_json(cJSON *j_array, struct dynsec__acl *acl, const char *acl_type)
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
