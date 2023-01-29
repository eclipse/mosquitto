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

static int dynsec__general_config_load_yaml(yaml_parser_t *parser, yaml_event_t *event, struct dynsec__data *data)
{
    YAML_PARSER_MAPPING_FOR_ALL(parser, event, key, { return MOSQ_ERR_INVAL; }, {
        if (strcmp(key, ACL_TYPE_PUB_C_SEND) == 0) {
            YAML_EVENT_INTO_SCALAR_BOOL(event, &data->default_access.publish_c_send, { return MOSQ_ERR_INVAL; });
        } else if (strcmp(key, ACL_TYPE_PUB_C_RECV) == 0) {
            YAML_EVENT_INTO_SCALAR_BOOL(event, &data->default_access.publish_c_recv, { return MOSQ_ERR_INVAL; });
        } else if (strcmp(key, ACL_TYPE_SUB_GENERIC) == 0) {
            YAML_EVENT_INTO_SCALAR_BOOL(event, &data->default_access.subscribe, { return MOSQ_ERR_INVAL; });
        } else if (strcmp(key, ACL_TYPE_UNSUB_GENERIC) == 0) {
            YAML_EVENT_INTO_SCALAR_BOOL(event, &data->default_access.unsubscribe, { return MOSQ_ERR_INVAL; });
        } else {
            mosquitto_log_printf(MOSQ_LOG_ERR, "Error parsing Dynamic security plugin config. Unknown key %s found on line %d:%d at %s:%d, \n", key, event->start_mark.line, event->start_mark.column, __FILE__, __LINE__ );
            return MOSQ_ERR_INVAL;
        }
    });

    return MOSQ_ERR_SUCCESS;
}

static int dynsec__general_config_save_yaml(yaml_emitter_t* emitter, yaml_event_t* event, struct dynsec__data *data)
{
    yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,
                                 (yaml_char_t *)"defaultACLAccess", strlen("defaultACLAccess"), 1, 0, YAML_PLAIN_SCALAR_STYLE);

    if (!yaml_emitter_emit(emitter, event)) return 1;

    yaml_mapping_start_event_initialize(event, NULL, (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 1;

    if (!yaml_emit_bool_field(emitter, event, ACL_TYPE_PUB_C_SEND, data->default_access.publish_c_send)) return 1;
    if (!yaml_emit_bool_field(emitter, event, ACL_TYPE_PUB_C_RECV, data->default_access.publish_c_recv)) return 1;
    if (!yaml_emit_bool_field(emitter, event, ACL_TYPE_SUB_GENERIC, data->default_access.subscribe)) return 1;
    if (!yaml_emit_bool_field(emitter, event, ACL_TYPE_UNSUB_GENERIC, data->default_access.unsubscribe)) return 1;

    yaml_mapping_end_event_initialize(event);
    if (!yaml_emitter_emit(emitter, event)) return 1;

    return 0;
}

int dynsec__config_load_yaml(struct dynsec__data *data, FILE* fptr)
{
    yaml_parser_t parser;
    yaml_event_t event;

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, fptr);

    if (!yaml_parser_parse(&parser, &event)) { goto print_error; }
    PARSER_EXPECT_EVENT_TYPE(&event, YAML_STREAM_START_EVENT, { return 1; });
    yaml_event_delete(&event);

    if (!yaml_parser_parse(&parser, &event)) { goto print_error; }
    PARSER_EXPECT_EVENT_TYPE(&event, YAML_DOCUMENT_START_EVENT, { return 1; });
    yaml_event_delete(&event);


    if (!yaml_parser_parse(&parser, &event)) { goto print_error; }

    YAML_PARSER_MAPPING_FOR_ALL(&parser, &event, key, { goto print_error; }, {
            if (strcmp(key, "defaultACLAccess") == 0) {
                if (dynsec__general_config_load_yaml(&parser, &event, data)) goto print_error;
            } else if (strcmp(key, "clients") == 0) {
                if (dynsec_clients__config_load_yaml(&parser, &event, data)) goto print_error;
            } else if (strcmp(key, "groups") == 0) {
                if (dynsec_groups__config_load_yaml(&parser, &event, data)) goto print_error;
            } else  if (strcmp(key, "roles") == 0) {
                if (dynsec_roles__config_load_yaml(&parser, &event, data)) goto print_error;
            } else  if (strcmp(key, "anonymousGroup") == 0) {
                char* anonymousGroup = NULL;
                YAML_EVENT_INTO_SCALAR_STRING(&event, &anonymousGroup, { goto print_error; });
                data->anonymous_group = dynsec_groups__find(data, anonymousGroup);
                if (!data->anonymous_group) {
                    data->anonymous_group = dynsec_groups__create(anonymousGroup);
                    dynsec_groups__insert(data, data->anonymous_group);
                }

                mosquitto_free(anonymousGroup);
            } else {
                mosquitto_log_printf(MOSQ_LOG_ERR, "Error parsing Dynamic security plugin config. Unknown key %s found on line %d:%d at %s:%d, \n", key, event.start_mark.line, event.start_mark.column, __FILE__, __LINE__ );
                yaml_event_delete(&event);
                return 1;
            }
    });

    if (!yaml_parser_parse(&parser, &event)) { goto print_error; }
    PARSER_EXPECT_EVENT_TYPE(&event, YAML_DOCUMENT_END_EVENT, { return 1; });
    yaml_event_delete(&event);

    if (!yaml_parser_parse(&parser, &event)) { goto print_error; }
    PARSER_EXPECT_EVENT_TYPE(&event, YAML_STREAM_END_EVENT, { return 1; });
    yaml_event_delete(&event);

    dynsec__config_save(data);

    return 0;

    print_error:
    mosquitto_log_printf(MOSQ_LOG_ERR, "Error parsing Dynamic security plugin config on line %d:%d: %s, \n", parser.problem_mark.line, parser.problem_mark.column, parser.problem);
    return 1;
}

int dynsec__write_yaml_config(FILE* fptr, void *user_data)
{
    struct dynsec__data *data = (struct dynsec__data *)user_data;
    yaml_emitter_t emitter;
    yaml_event_t event;

    yaml_emitter_initialize(&emitter);
    yaml_emitter_set_output_file(&emitter, fptr);

    yaml_stream_start_event_initialize(&event, YAML_UTF8_ENCODING);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 1);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_mapping_start_event_initialize(&event, NULL, (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    if(dynsec__general_config_save_yaml(&emitter, &event, data)) goto error;
    if(dynsec_clients__config_save_yaml(&emitter, &event, data)) goto error;
    if(dynsec_groups__config_save_yaml(&emitter, &event, data)) goto error;
    if(dynsec_roles__config_save_yaml(&emitter, &event, data)) goto error;

    yaml_mapping_end_event_initialize(&event);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_document_end_event_initialize(&event, 1);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_stream_end_event_initialize(&event);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

/* Destroy the Emitter object. */
    yaml_emitter_delete(&emitter);

    return MOSQ_ERR_SUCCESS;

    error:
    printf("%s:%d\n", __FILE__, __LINE__);
    fprintf(stderr, "Failed to emit event %d: %s\n", event.type, emitter.problem);
    yaml_event_delete(&event);
    yaml_emitter_delete(&emitter);

    return MOSQ_ERR_UNKNOWN;
}
