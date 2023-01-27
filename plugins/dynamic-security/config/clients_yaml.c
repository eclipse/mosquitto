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

    YAML_PARSER_SEQUENCE_FOR_ALL(parser, event, { goto error; }, {

            client = NULL;
            disabled = 0;
            clientid = textname = textdescription = salt = pw = NULL;
            iterations = 0;
            rolelist = NULL;

            YAML_PARSER_MAPPING_FOR_ALL(parser, event, key, { goto error; }, {
                if (strcmp(key, "username") == 0) {
                    char *username;
                    YAML_EVENT_INTO_SCALAR_STRING(event, &username, { goto error; });
                    client = dynsec_clients__find_or_create(data, username);
                    mosquitto_free(username);
                } else if (strcmp(key, "disabled") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_BOOL(event, &disabled, { goto error; });
                } else if (strcmp(key, "clientid") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_STRING(event, &clientid, { goto error; });
                } else if (strcmp(key, "textname") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_STRING(event, &textname, { goto error; });
                } else if (strcmp(key, "textdescription") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_STRING(event, &textdescription, { goto error; });
                } else if (strcmp(key, "salt") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_STRING(event, &salt, { goto error; });
                } else if (strcmp(key, "password") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_STRING(event, &pw, { goto error; });
                } else if (strcmp(key, "iterations") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_LONG_INT(event, &iterations, { goto error; });
                } else if (strcmp(key, "roles") == 0) {
                    if (dynsec_rolelist__load_from_yaml(parser, event, data, &rolelist)) goto error;

                    printf("%s:%d\n", __FILE__, __LINE__);
                } else {
                    yaml_dump_block(parser, event);
                    printf("%s:%d\n", __FILE__, __LINE__);
                    mosquitto_log_printf(MOSQ_LOG_ERR, "Unexpected key for client config %s \n", key);
                }
                printf("%s:%d\n", __FILE__, __LINE__);
            });

            if (client) {
                client->clientid = clientid;
                client->text_name = textname;
                client->text_description = textdescription;
                client->disabled = disabled;

                if (rolelist) {
                    struct dynsec__rolelist *iter;
                    struct dynsec__rolelist *tmp;

                    printf("%s:%d\n", __FILE__, __LINE__);
                    HASH_ITER(hh, rolelist, iter, tmp){
                        printf("%s:%d\n", __FILE__, __LINE__);
                        dynsec_rolelist__add(&client->rolelist, iter->role, iter->priority);
                        dynsec_clientlist__add(&iter->role->clientlist, client, iter->priority);
                        iter->role = NULL;
                        printf("%s:%d\n", __FILE__, __LINE__);
                    }

                    dynsec_rolelist__cleanup(&rolelist);
                }

                if (salt && pw && iterations > 0) {
                    printf("PW VALID FOR %s\n", client->username);
                    client->pw.valid = 1;
                    client->pw.iterations = (int)iterations;

                    if(base64__decode(salt, &buf, &buf_len) == MOSQ_ERR_SUCCESS && buf_len == sizeof(client->pw.salt)) {
                        memcpy(client->pw.salt, buf, (size_t)buf_len);
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
                    printf("PW NOT VALID FOR %s\n", client->username);
                    client->pw.valid = 0;
                }

                mosquitto_free(salt);
                mosquitto_free(pw);

            } else {
                mosquitto_free(clientid);
                mosquitto_free(textname);
                mosquitto_free(textdescription);
                dynsec_rolelist__cleanup(&rolelist);
            }

            printf("%s:%d\n", __FILE__, __LINE__);

    });

    printf("%s:%d\n", __FILE__, __LINE__);

    return 1;
    error:
    mosquitto_free(clientid);
    mosquitto_free(textname);
    mosquitto_free(textdescription);
    dynsec_rolelist__cleanup(&rolelist);
    mosquitto_free(salt);
    mosquitto_free(pw);
    return 0;
}


static int dynsec__config_add_clients_yaml(yaml_emitter_t* emitter, yaml_event_t* event, struct dynsec__data *data)
{


    struct dynsec__client *client, *client_tmp;
    char *buf;
    printf("%s:%d\n", __FILE__, __LINE__);

    yaml_sequence_start_event_initialize(event, NULL, (yaml_char_t *)YAML_SEQ_TAG,
                                         1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 1;
    printf("%s:%d\n", __FILE__, __LINE__);

    HASH_ITER(hh, data->clients, client, client_tmp){
        printf("%s:%d\n", __FILE__, __LINE__);
        yaml_mapping_start_event_initialize(event, NULL, (yaml_char_t *)YAML_MAP_TAG,
                                            1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, event)) return 1;

        if (!yaml_emit_string_field(emitter, event, "username", client->username)) return 1;

        printf("%s:%d\n", __FILE__, __LINE__);
        if (client->clientid && !yaml_emit_string_field(emitter, event, "clientid", client->clientid)) return 1;
        printf("%s:%d\n", __FILE__, __LINE__);
        if (client->text_name && !yaml_emit_string_field(emitter, event, "textname", client->text_name)) return 1;
        printf("%s:%d\n", __FILE__, __LINE__);
        if (client->text_description && !yaml_emit_string_field(emitter, event, "textdescription", client->text_description)) return 1;
        printf("%s:%d\n", __FILE__, __LINE__);
        if (client->disabled && !yaml_emit_string_field(emitter, event, "disabled", "true")) return 1;
        printf("%s:%d\n", __FILE__, __LINE__);


        yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,
                                     (yaml_char_t *)"roles", strlen("roles"), 1, 0, YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, event)) return 1;

        printf("%s:%d\n", __FILE__, __LINE__);
        if (dynsec_rolelist__all_to_yaml(client->rolelist, emitter, event)) return 1;
        printf("%s:%d\n", __FILE__, __LINE__);

        if(client->pw.valid){
            if(base64__encode(client->pw.password_hash, sizeof(client->pw.password_hash), &buf) != MOSQ_ERR_SUCCESS){
                mosquitto_log_printf(MOSQ_LOG_ERR, "dynsec: error encoding password hash to base64");
                return 1;
            }

            if (!yaml_emit_string_field(emitter, event, "password", buf)) {
                mosquitto_free(buf);
                return 1;
            }

            mosquitto_free(buf);

            if(base64__encode(client->pw.salt, sizeof(client->pw.salt), &buf) != MOSQ_ERR_SUCCESS){
                mosquitto_log_printf(MOSQ_LOG_ERR, "dynsec: error encoding password salt to base64");
                return 1;
            }

            if (!yaml_emit_string_field(emitter, event, "salt", buf)) {
                mosquitto_free(buf);
                return 1;
            }

            mosquitto_free(buf);

            if (!yaml_emit_int_field(emitter, event, "iterations", client->pw.iterations)) {
                return 1;
            }
        }

        yaml_mapping_end_event_initialize(event);
        if (!yaml_emitter_emit(emitter, event)) return 1;

    }

    printf("%s:%d\n", __FILE__, __LINE__);

    yaml_sequence_end_event_initialize(event);
    if (!yaml_emitter_emit(emitter, event)) return 1;


    return 0;
}

int dynsec_clients__config_save_yaml(yaml_emitter_t* emitter, yaml_event_t* event, struct dynsec__data *data)
{
    yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,
                                 (yaml_char_t *)"clients", strlen("clients"), 1, 0, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 1;

    if(dynsec__config_add_clients_yaml(emitter, event, data)) return 1;

    return 0;
}
