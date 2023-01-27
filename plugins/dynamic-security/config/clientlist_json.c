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

cJSON *dynsec_clientlist__all_to_json(struct dynsec__clientlist *base_clientlist)
{
    struct dynsec__clientlist *clientlist, *clientlist_tmp;
    cJSON *j_clients, *j_client;

    j_clients = cJSON_CreateArray();
    if(j_clients == NULL) return NULL;

    HASH_ITER(hh, base_clientlist, clientlist, clientlist_tmp){
        j_client = cJSON_CreateObject();
        if(j_client == NULL){
            cJSON_Delete(j_clients);
            return NULL;
        }
        cJSON_AddItemToArray(j_clients, j_client);

        if(cJSON_AddStringToObject(j_client, "username", clientlist->client->username) == NULL
           || (clientlist->priority != -1 && cJSON_AddIntToObject(j_client, "priority", clientlist->priority) == NULL)
                ){

            cJSON_Delete(j_clients);
            return NULL;
        }
    }
    return j_clients;
}
