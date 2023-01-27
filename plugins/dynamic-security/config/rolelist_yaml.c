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

int dynsec_rolelist__load_from_yaml(yaml_parser_t *parser, yaml_event_t *event, struct dynsec__data *data, struct dynsec__rolelist **rolelist)
{

    YAML_PARSER_SEQUENCE_FOR_ALL(parser, event, { goto error; }, {
            printf("%s:%d\n", __FILE__, __LINE__);
            char* rolename = NULL;
            long int priority = -1;

            printf("%s:%d\n", __FILE__, __LINE__);
            YAML_PARSER_MAPPING_FOR_ALL(parser, event, key, { goto error; }, {
                printf("%s:%d\n", __FILE__, __LINE__);
                if (strcmp(key, "rolename") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_STRING(event, &rolename, { goto error; });
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

            if (rolename) {
                printf("rn = %s\n", rolename);
                struct dynsec__role *role = dynsec_roles__find_or_create(data, rolename);
                if (role) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    dynsec_rolelist__add(rolelist, role, (int)priority);
                } else {
                    printf("OUT OF MEMORY %s:%d\n", __FILE__, __LINE__);
                    free(rolename);
                    goto error;
                }
            }

            printf("%s:%d\n", __FILE__, __LINE__);
    });

    printf("%s:%d\n", __FILE__, __LINE__);

    return 0;
    error:
    dynsec_rolelist__cleanup(rolelist);
    return 1;
}


int dynsec_rolelist__all_to_yaml(struct dynsec__rolelist *base_rolelist, yaml_emitter_t *emitter, yaml_event_t *event)
{
    struct dynsec__rolelist *rolelist, *rolelist_tmp;

    yaml_sequence_start_event_initialize(event, NULL, (yaml_char_t *)YAML_SEQ_TAG,
                                         1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 1;


    HASH_ITER(hh, base_rolelist, rolelist, rolelist_tmp){

        yaml_mapping_start_event_initialize(event, NULL, (yaml_char_t *)YAML_MAP_TAG,
                                            1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, event)) return 1;

        if (!yaml_emit_string_field(emitter, event, "rolename", rolelist->role->rolename)) return 1;
        if (rolelist->priority != -1 && !yaml_emit_int_field(emitter, event, "priority", rolelist->priority)) return 1;

        yaml_mapping_end_event_initialize(event);
        if (!yaml_emitter_emit(emitter, event)) return 1;
    }

    yaml_sequence_end_event_initialize(event);
    if (!yaml_emitter_emit(emitter, event)) return 1;

    return 0;
}


