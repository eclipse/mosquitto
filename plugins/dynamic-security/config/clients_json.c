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

int dynsec_clients__config_load_json(struct dynsec__data *data, cJSON *tree)
{
    cJSON *j_clients, *j_client, *jtmp, *j_roles, *j_role;
    cJSON *j_salt, *j_password, *j_iterations;
    struct dynsec__client *client;
    struct dynsec__role *role;
    unsigned char *buf;
    unsigned int buf_len;
    int priority;
    int iterations;

    j_clients = cJSON_GetObjectItem(tree, "clients");
    if(j_clients == NULL){
        return 0;
    }

    if(cJSON_IsArray(j_clients) == false){
        return 1;
    }

    cJSON_ArrayForEach(j_client, j_clients){
        if(cJSON_IsObject(j_client) == true){
            /* Username */
            jtmp = cJSON_GetObjectItem(j_client, "username");
            if(jtmp == NULL || !cJSON_IsString(jtmp)){
                continue;
            }

            client = dynsec_clients__create(jtmp->valuestring);

            jtmp = cJSON_GetObjectItem(j_client, "disabled");
            client->disabled = jtmp && cJSON_IsBool(jtmp) && cJSON_IsTrue(jtmp);

            /* Salt */
            j_salt = cJSON_GetObjectItem(j_client, "salt");
            j_password = cJSON_GetObjectItem(j_client, "password");
            j_iterations = cJSON_GetObjectItem(j_client, "iterations");

            if(j_salt && cJSON_IsString(j_salt)
               && j_password && cJSON_IsString(j_password)
               && j_iterations && cJSON_IsNumber(j_iterations)){

                iterations = (int)j_iterations->valuedouble;
                if(iterations < 1){
                    mosquitto_free(client);
                    continue;
                }else{
                    client->pw.iterations = iterations;
                }

                if(base64__decode(j_salt->valuestring, &buf, &buf_len) != MOSQ_ERR_SUCCESS
                   || buf_len > sizeof(client->pw.salt)){

                    mosquitto_free(buf);
                    mosquitto_free(client);
                    continue;
                }
                memcpy(client->pw.salt, buf, (size_t)buf_len);
                client->pw.salt_len = (size_t)buf_len;
                mosquitto_free(buf);

                if(base64__decode(j_password->valuestring, &buf, &buf_len) != MOSQ_ERR_SUCCESS
                   || buf_len != sizeof(client->pw.password_hash)){

                    mosquitto_free(buf);
                    mosquitto_free(client);
                    continue;
                }
                memcpy(client->pw.password_hash, buf, (size_t)buf_len);
                mosquitto_free(buf);
                client->pw.valid = true;
            }else{
                client->pw.valid = false;
            }

            /* Client id */
            jtmp = cJSON_GetObjectItem(j_client, "clientid");
            if(jtmp != NULL && cJSON_IsString(jtmp)){
                client->clientid = mosquitto_strdup(jtmp->valuestring);
                if(client->clientid == NULL){
                    mosquitto_free(client);
                    continue;
                }
            }

            /* Text name */
            jtmp = cJSON_GetObjectItem(j_client, "textname");
            if(jtmp != NULL && cJSON_IsString(jtmp)){
                client->text_name = mosquitto_strdup(jtmp->valuestring);
                if(client->text_name == NULL){
                    mosquitto_free(client->clientid);
                    mosquitto_free(client);
                    continue;
                }
            }

            /* Text description */
            jtmp = cJSON_GetObjectItem(j_client, "textdescription");
            if(jtmp != NULL && cJSON_IsString(jtmp)){
                client->text_description = mosquitto_strdup(jtmp->valuestring);
                if(client->text_description == NULL){
                    mosquitto_free(client->text_name);
                    mosquitto_free(client->clientid);
                    mosquitto_free(client);
                    continue;
                }
            }

            dynsec_clients__insert(data, client);
            /* Roles */
            j_roles = cJSON_GetObjectItem(j_client, "roles");
            if(j_roles && cJSON_IsArray(j_roles)){
                cJSON_ArrayForEach(j_role, j_roles){
                    if(cJSON_IsObject(j_role)){
                        jtmp = cJSON_GetObjectItem(j_role, "rolename");
                        if(jtmp && cJSON_IsString(jtmp)){
                            json_get_int(j_role, "priority", &priority, true, -1);
                            role = dynsec_roles__find(data, jtmp->valuestring);
                            dynsec_rolelist__client_add(client, role, priority);
                        }
                    }
                }
            }

        }
    }

    return 0;
}


static int dynsec__config_add_clients_json(struct dynsec__data *data, cJSON *j_clients)
{
    struct dynsec__client *client, *client_tmp;
    cJSON *j_client, *j_roles, *jtmp;
    char *buf;

    HASH_ITER(hh, data->clients, client, client_tmp){
        j_client = cJSON_CreateObject();
        if(j_client == NULL) return 1;
        cJSON_AddItemToArray(j_clients, j_client);

        if(cJSON_AddStringToObject(j_client, "username", client->username) == NULL
           || (client->clientid && cJSON_AddStringToObject(j_client, "clientid", client->clientid) == NULL)
           || (client->text_name && cJSON_AddStringToObject(j_client, "textname", client->text_name) == NULL)
           || (client->text_description && cJSON_AddStringToObject(j_client, "textdescription", client->text_description) == NULL)
           || (client->disabled && cJSON_AddBoolToObject(j_client, "disabled", true) == NULL)
                ){

            return 1;
        }

        j_roles = dynsec_rolelist__all_to_json(client->rolelist);
        if(j_roles == NULL){
            return 1;
        }
        cJSON_AddItemToObject(j_client, "roles", j_roles);

        if(client->pw.valid){
            if(base64__encode(client->pw.password_hash, sizeof(client->pw.password_hash), &buf) != MOSQ_ERR_SUCCESS){
                return 1;
            }
            jtmp = cJSON_CreateString(buf);
            mosquitto_free(buf);
            if(jtmp == NULL) return 1;
            cJSON_AddItemToObject(j_client, "password", jtmp);

            if(base64__encode(client->pw.salt, client->pw.salt_len, &buf) != MOSQ_ERR_SUCCESS){
                return 1;
            }

            jtmp = cJSON_CreateString(buf);
            mosquitto_free(buf);
            if(jtmp == NULL) return 1;
            cJSON_AddItemToObject(j_client, "salt", jtmp);

            if(cJSON_AddIntToObject(j_client, "iterations", client->pw.iterations) == NULL){
                return 1;
            }
        }
    }

    return 0;
}

int dynsec_clients__config_save_json(struct dynsec__data *data, cJSON *tree)
{
    cJSON *j_clients;

    if((j_clients = cJSON_AddArrayToObject(tree, "clients")) == NULL){
        return 1;
    }
    if(dynsec__config_add_clients_json(data, j_clients)){
        return 1;
    }

    return 0;
}
