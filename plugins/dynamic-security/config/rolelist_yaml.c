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
    char* rolename;
    int ret;

    YAML_PARSER_SEQUENCE_FOR_ALL(parser, event, { ret = MOSQ_ERR_INVAL; goto error; }, {
            long int priority = -1;
            rolename = NULL;

            if (event->type == YAML_SCALAR_EVENT) {
                YAML_EVENT_INTO_SCALAR_STRING(event, &rolename, { ret = MOSQ_ERR_INVAL; goto error; });
            } else {
                YAML_PARSER_MAPPING_FOR_ALL(parser, event, key, { ret = MOSQ_ERR_INVAL; goto error; }, {
                        if (strcasecmp(key, "rolename") == 0) {
                            YAML_EVENT_INTO_SCALAR_STRING(event, &rolename, { ret = MOSQ_ERR_INVAL; goto error; });
                        } else if (strcasecmp(key, "priority") == 0) {
                            YAML_EVENT_INTO_SCALAR_LONG_INT(event, &priority, { ret = MOSQ_ERR_INVAL; goto error; });
                        } else {
                            mosquitto_log_printf(MOSQ_LOG_ERR, "Unexpected key for role config %s \n", key);
                            yaml_dump_block(parser, event);
                        }
                });
            }

            if (rolename) {
                struct dynsec__role *role = dynsec_roles__find(data, rolename);

                if (!role) {
                    role = dynsec_roles__create(rolename);
                    if (role) dynsec_roles__insert(data, role);
                }

                if (role) {
                    dynsec_rolelist__add(rolelist, role, (int)priority);
                } else {
                    printf("OUT OF MEMORY %s:%d\n", __FILE__, __LINE__);
                    ret = MOSQ_ERR_NOMEM;
                    goto error;
                }
            }
    });

    return MOSQ_ERR_SUCCESS;
error:
    mosquitto_free(rolename);
    dynsec_rolelist__cleanup(rolelist);
    return ret;
}


int dynsec_rolelist__all_to_yaml(struct dynsec__rolelist *rolelist, yaml_emitter_t *emitter, yaml_event_t *event)
{
    struct dynsec__rolelist *iter, *tmp;

    yaml_sequence_start_event_initialize(event, NULL, (yaml_char_t *)YAML_SEQ_TAG,
                                         1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;


    HASH_ITER(hh, rolelist, iter, tmp) {
        if (iter->priority == -1) {
            yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_INT_TAG,
                                         (yaml_char_t *)iter->rolename, (int)strlen(iter->rolename), 1, 1, YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;
        } else {
            yaml_mapping_start_event_initialize(event, NULL, (yaml_char_t *) YAML_MAP_TAG,
                                                1, YAML_FLOW_MAPPING_STYLE);
            if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;

            if (!yaml_emit_string_field(emitter, event, "rolename", iter->role->rolename)) return MOSQ_ERR_UNKNOWN;
            if (iter->priority != -1 && !yaml_emit_int_field(emitter, event, "priority", iter->priority))
                return MOSQ_ERR_UNKNOWN;

            yaml_mapping_end_event_initialize(event);
            if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;
        }
    }

    yaml_sequence_end_event_initialize(event);
    if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;

    return MOSQ_ERR_SUCCESS;
}


