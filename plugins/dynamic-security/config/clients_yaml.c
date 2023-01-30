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

#include <stdio.h>
#include <uthash.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"

#include "dynamic_security.h"

#include "yaml_help.h"
#include "yaml.h"

int dynsec_clients__config_load_yaml(yaml_parser_t *parser, yaml_event_t *event, struct dynsec__data *data)
{
    unsigned char *buf = NULL;
    unsigned int buf_len;

    struct dynsec__client *client = NULL;
    bool disabled = 1;
    char* clientid;
    char* textname;
    char* textdescription;
    char *salt;
    char *pw;
    long int iterations;
    struct dynsec__rolelist *rolelist;
    int ret = MOSQ_ERR_SUCCESS;

    YAML_PARSER_SEQUENCE_FOR_ALL(parser, event, { ret = MOSQ_ERR_INVAL; goto error; }, {
            client = NULL;
            disabled = 0;
            clientid = textname = textdescription = salt = pw = NULL;
            iterations = 0;
            rolelist = NULL;

            YAML_PARSER_MAPPING_FOR_ALL(parser, event, key, { ret = MOSQ_ERR_INVAL; goto error; }, {
                if (strcasecmp(key, "username") == 0) {
                    char *username;
                    YAML_EVENT_INTO_SCALAR_STRING(event, &username, { ret = MOSQ_ERR_INVAL; goto error; });
                    client = dynsec_clients__find(data, username);
                    if (!client) client = dynsec_clients__create(username); //TODO: Memory allocated for client is not freed if an error occurs later on.
                    if (!client) { ret = MOSQ_ERR_NOMEM; mosquitto_free(username); goto error; }
                    mosquitto_free(username);
                } else if (strcasecmp(key, "disabled") == 0) {
                    YAML_EVENT_INTO_SCALAR_BOOL(event, &disabled, { ret = MOSQ_ERR_INVAL; goto error; });
                } else if (strcasecmp(key, "clientid") == 0) {
                    YAML_EVENT_INTO_SCALAR_STRING(event, &clientid, { ret = MOSQ_ERR_INVAL; goto error; });
                } else if (strcasecmp(key, "textname") == 0) {
                    YAML_EVENT_INTO_SCALAR_STRING(event, &textname, { ret = MOSQ_ERR_INVAL; goto error; });
                } else if (strcasecmp(key, "textdescription") == 0) {
                    YAML_EVENT_INTO_SCALAR_STRING(event, &textdescription, { ret = MOSQ_ERR_INVAL; goto error; });
                } else if (strcasecmp(key, "salt") == 0) {
                    YAML_EVENT_INTO_SCALAR_STRING(event, &salt, { ret = MOSQ_ERR_INVAL; goto error; });
                } else if (strcasecmp(key, "password") == 0) {
                    YAML_EVENT_INTO_SCALAR_STRING(event, &pw, { ret = MOSQ_ERR_INVAL; goto error; });
                } else if (strcasecmp(key, "iterations") == 0) {
                    YAML_EVENT_INTO_SCALAR_LONG_INT(event, &iterations, { ret = MOSQ_ERR_INVAL; goto error; });
                } else if (strcasecmp(key, "roles") == 0) {
                    if (dynsec_rolelist__load_from_yaml(parser, event, data, &rolelist)) { ret = MOSQ_ERR_INVAL; goto error; };
                } else {
                    mosquitto_log_printf(MOSQ_LOG_ERR, "Unexpected key for client config %s \n", key);
                    yaml_dump_block(parser, event);
                }
            });


        if (client) {
                client->clientid = clientid;
                client->text_name = textname;
                client->text_description = textdescription;
                client->disabled = disabled;

                if (rolelist) {
                    struct dynsec__rolelist *iter;
                    struct dynsec__rolelist *tmp;

                    HASH_ITER(hh, rolelist, iter, tmp){
                        dynsec_rolelist__add(&client->rolelist, iter->role, iter->priority);
                        dynsec_clientlist__add(&iter->role->clientlist, client, iter->priority);
                        //Make sure not to clean up the actual role.
                        iter->role = NULL;
                    }

                    dynsec_rolelist__cleanup(&rolelist);
                }

                if (salt && pw && iterations > 0) {
                    client->pw.valid = 1;
                    client->pw.iterations = (int)iterations;

                    if(base64__decode(salt, &buf, &buf_len) == MOSQ_ERR_SUCCESS && buf_len <= sizeof(client->pw.salt)) {
                        memcpy(client->pw.salt, buf, (size_t)buf_len);
                        client->pw.salt_len = buf_len;
                        mosquitto_free(buf);
                        buf = NULL;
                    } else {
                        client->pw.valid = 0;
                        mosquitto_free(buf);
                        buf = NULL;
                    }

                    if(base64__decode(pw, &buf, &buf_len) == MOSQ_ERR_SUCCESS && buf_len == sizeof(client->pw.password_hash)) {
                        memcpy(client->pw.password_hash, buf, (size_t)buf_len);
                        mosquitto_free(buf);
                        buf = NULL;
                    } else {
                        mosquitto_free(buf);
                        buf = NULL;
                        client->pw.valid = 0;
                    }
                } else {
                    client->pw.valid = 0;
                }

                dynsec_clients__insert(data, client);

                mosquitto_free(salt);
                mosquitto_free(pw);
            } else {
                //No username specified
                ret = MOSQ_ERR_INVAL;
                goto error;
            }
    });

    return MOSQ_ERR_SUCCESS;
error:
    mosquitto_free(clientid);
    mosquitto_free(textname);
    mosquitto_free(textdescription);
    dynsec_rolelist__cleanup(&rolelist);
    mosquitto_free(salt);
    mosquitto_free(pw);
    return ret;
}


static int dynsec__config_add_clients_yaml(yaml_emitter_t* emitter, yaml_event_t* event, struct dynsec__data *data)
{
    struct dynsec__client *iter, *tmp;
    char *buf;

    yaml_sequence_start_event_initialize(event, NULL, (yaml_char_t *)YAML_SEQ_TAG,
                                         1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;

    HASH_ITER(hh, data->clients, iter, tmp){

        yaml_mapping_start_event_initialize(event, NULL, (yaml_char_t *)YAML_MAP_TAG,
                                            1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;

        if (!yaml_emit_string_field(emitter, event, "username", iter->username)) return MOSQ_ERR_UNKNOWN;
        if (iter->clientid && !yaml_emit_string_field(emitter, event, "clientid", iter->clientid)) return MOSQ_ERR_UNKNOWN;
        if (iter->text_name && !yaml_emit_string_field(emitter, event, "textname", iter->text_name)) return MOSQ_ERR_UNKNOWN;
        if (iter->text_description && !yaml_emit_string_field(emitter, event, "textdescription", iter->text_description)) return MOSQ_ERR_UNKNOWN;
        if (iter->disabled && !yaml_emit_string_field(emitter, event, "disabled", "true")) return MOSQ_ERR_UNKNOWN;

        yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,(yaml_char_t *)"roles", strlen("roles"), 1, 0, YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;

        if (dynsec_rolelist__all_to_yaml(iter->rolelist, emitter, event)) return MOSQ_ERR_UNKNOWN;

        if(iter->pw.valid){
            if(base64__encode(iter->pw.password_hash, sizeof(iter->pw.password_hash), &buf) != MOSQ_ERR_SUCCESS){
                mosquitto_log_printf(MOSQ_LOG_ERR, "dynsec: error encoding password hash to base64");
                return MOSQ_ERR_UNKNOWN;
            }

            if (!yaml_emit_string_field(emitter, event, "password", buf)) {
                mosquitto_free(buf);
                return MOSQ_ERR_UNKNOWN;
            }

            mosquitto_free(buf);

            if(base64__encode(iter->pw.salt, iter->pw.salt_len, &buf) != MOSQ_ERR_SUCCESS){
                mosquitto_log_printf(MOSQ_LOG_ERR, "dynsec: error encoding password salt to base64");
                return MOSQ_ERR_UNKNOWN;
            }

            if (!yaml_emit_string_field(emitter, event, "salt", buf)) {
                mosquitto_free(buf);
                return MOSQ_ERR_UNKNOWN;
            }

            mosquitto_free(buf);

            if (!yaml_emit_int_field(emitter, event, "iterations", iter->pw.iterations)) {
                return MOSQ_ERR_UNKNOWN;
            }
        }

        yaml_mapping_end_event_initialize(event);
        if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;
    }

    yaml_sequence_end_event_initialize(event);
    if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;

    return MOSQ_ERR_SUCCESS;
}

//Outputs a tuple of key and value
int dynsec_clients__config_save_yaml(yaml_emitter_t* emitter, yaml_event_t* event, struct dynsec__data *data)
{
    yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,(yaml_char_t *)"clients", strlen("clients"), 1, 1, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 1;

    if(dynsec__config_add_clients_yaml(emitter, event, data)) return 1;

    return 0;
}
