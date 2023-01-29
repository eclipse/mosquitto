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
#include "json_help.h"

#include "dynamic_security.h"
#include "yaml.h"
#include "yaml_help.h"


int dynsec_clientlist__all_to_yaml(struct dynsec__clientlist *base_clientlist, yaml_emitter_t* emitter, yaml_event_t *event)
{
    struct dynsec__clientlist *clientlist, *clientlist_tmp;

    yaml_sequence_start_event_initialize(event, NULL, (yaml_char_t *)YAML_SEQ_TAG,
                                         1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 0;

    printf("%s:%d\n", __FILE__, __LINE__);
    HASH_ITER(hh, base_clientlist, clientlist, clientlist_tmp){
        yaml_mapping_start_event_initialize(event, NULL, (yaml_char_t *)YAML_MAP_TAG,
                                            1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, event)) return 0;

        printf("%s:%d\n", __FILE__, __LINE__);

        if (!yaml_emit_string_field(emitter, event, "username", clientlist->client->username)) return 0;
        if (clientlist->priority != -1 && !yaml_emit_int_field(emitter, event, "priority", clientlist->priority)) return 0;

        yaml_mapping_end_event_initialize(event);
        if (!yaml_emitter_emit(emitter, event)) return 0;
        printf("%s:%d\n", __FILE__, __LINE__);

    }

    printf("%s:%d\n", __FILE__, __LINE__);
    yaml_sequence_end_event_initialize(event);
    if (!yaml_emitter_emit(emitter, event)) return 0;

    printf("%s:%d\n", __FILE__, __LINE__);
    return 1;
}

int dynsec_clientlist__load_from_yaml(yaml_parser_t *parser, yaml_event_t *event, struct dynsec__data *data, struct dynsec__clientlist **clientlist)
{
    YAML_PARSER_SEQUENCE_FOR_ALL(parser, event, { goto error; }, {
            printf("%s:%d\n", __FILE__, __LINE__);
            char* username = NULL;
            long int priority = -1;

            printf("%s:%d\n", __FILE__, __LINE__);
            YAML_PARSER_MAPPING_FOR_ALL(parser, event, key, { goto error; }, {
                printf("%s:%d\n", __FILE__, __LINE__);
                if (strcmp(key, "username") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_STRING(event, &username, { goto error; });
                } else if (strcmp(key, "priority") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_LONG_INT(event, &priority, { goto error; });
                } else {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    mosquitto_log_printf(MOSQ_LOG_ERR, "Unexpected key for role config %s \n", key);
                    yaml_dump_block(parser, event);
                }
            });

            printf("%s:%d\n", __FILE__, __LINE__);

            if (username) {
                printf("un = %s\n", username);
                struct dynsec__client *client = dynsec_clients__find_or_create(data, username);
                if (client) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    dynsec_clientlist__add(clientlist, client, (int)priority);
                } else {
                    printf("OUT OF MEMORY %s:%d\n", __FILE__, __LINE__);
                    free(username);
                    goto error;
                }
            }

            printf("%s:%d\n", __FILE__, __LINE__);
    });

    printf("%s:%d\n", __FILE__, __LINE__);

    return 0;
    error:
    dynsec_clientlist__cleanup(clientlist);
    return 1;
}