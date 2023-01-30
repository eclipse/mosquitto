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

static int add_role_to_yaml(yaml_emitter_t *emitter, yaml_event_t *event, struct dynsec__role *role)
{
    yaml_mapping_start_event_initialize(event, NULL, (yaml_char_t *)YAML_MAP_TAG,
                                        1, YAML_ANY_MAPPING_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;

    if (!yaml_emit_string_field(emitter, event, "rolename", role->rolename)) return MOSQ_ERR_UNKNOWN;
    if (role->text_name && !yaml_emit_string_field(emitter, event, "textname", role->text_name)) return MOSQ_ERR_UNKNOWN;
    if (role->text_description && !yaml_emit_string_field(emitter, event, "textdescription", role->text_description)) return MOSQ_ERR_UNKNOWN;
    if (role->allow_wildcard_subs && !yaml_emit_bool_field(emitter, event, "allowwildcardsubs", role->allow_wildcard_subs)) return MOSQ_ERR_UNKNOWN;

    if(dynsec__acls__to_yaml(emitter, event, role)) return MOSQ_ERR_UNKNOWN;

    yaml_mapping_end_event_initialize(event);
    if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;

    return MOSQ_ERR_SUCCESS;
}

int dynsec_roles__config_save_yaml(yaml_emitter_t *emitter, yaml_event_t *event, struct dynsec__data *data)
{
    struct dynsec__role *role, *role_tmp = NULL;

    yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,
                                 (yaml_char_t *)"roles", strlen("roles"), 1, 0, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_SUCCESS;

    yaml_sequence_start_event_initialize(event, NULL, (yaml_char_t *)YAML_SEQ_TAG,
                                         1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;

    HASH_ITER(hh, data->roles, role, role_tmp){
        if (add_role_to_yaml(emitter, event, role)) return MOSQ_ERR_UNKNOWN;
    }

    yaml_sequence_end_event_initialize(event);
    if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;

    return MOSQ_ERR_SUCCESS;
}

int dynsec_roles__config_load_yaml(yaml_parser_t *parser, yaml_event_t *event, struct dynsec__data *data)
{
    struct dynsec__role *role = NULL;
    char* textname;
    char* textdescription;
    struct dynsec__acls acls;
    bool allowwildcardsubs;
    int ret = MOSQ_ERR_SUCCESS;

    YAML_PARSER_SEQUENCE_FOR_ALL(parser, event, { ret = MOSQ_ERR_INVAL; goto error; }, {
            memset(&acls, 0, sizeof(acls));
            role = NULL;
            textname = textdescription = NULL;
            allowwildcardsubs = true;
            YAML_PARSER_MAPPING_FOR_ALL(parser, event, key, { ret = MOSQ_ERR_INVAL; goto error; }, {
                if (strcasecmp(key, "rolename") == 0) {
                    char *rolename;
                    YAML_EVENT_INTO_SCALAR_STRING(event, &rolename, { ret = MOSQ_ERR_INVAL; goto error; });
                    role = dynsec_roles__find(data, rolename);
                    if (!role) role = dynsec_roles__create(rolename);
                    if (!role) { ret = MOSQ_ERR_NOMEM; mosquitto_free(rolename); goto error; }
                    mosquitto_free(rolename);
                } else if (strcasecmp(key, "textname") == 0) {
                    YAML_EVENT_INTO_SCALAR_STRING(event, &textname, { ret = MOSQ_ERR_INVAL; goto error; });
                } else if (strcasecmp(key, "textdescription") == 0) {
                    YAML_EVENT_INTO_SCALAR_STRING(event, &textdescription, { ret = MOSQ_ERR_INVAL; goto error; });
                } else if (strcasecmp(key, "allowwildcardsubs") == 0) {
                    YAML_EVENT_INTO_SCALAR_BOOL(event, &allowwildcardsubs, { ret = MOSQ_ERR_INVAL; goto error; });
                } else if (strcasecmp(key, "acls") == 0) {
                    if (dynsec_acls__load_yaml(parser, event, &acls)) { ret = MOSQ_ERR_INVAL; goto error; } //TODO: Memory allocated for acls is not freed if an error occurs later on.
                } else {
                    mosquitto_log_printf(MOSQ_LOG_ERR, "Unexpected key for client config %s \n", key);
                    yaml_dump_block(parser, event);
                }
            });

            if (role) {
                role->text_name = textname;
                role->text_description = textdescription;
                role->allow_wildcard_subs = allowwildcardsubs;
                role->acls = acls;
                dynsec_roles__insert(data, role);
            } else {
                mosquitto_free(textname);
                mosquitto_free(textdescription);
            }
    });

    return MOSQ_ERR_SUCCESS;

error:
    mosquitto_free(textname);
    mosquitto_free(textdescription);
    return ret;
}

