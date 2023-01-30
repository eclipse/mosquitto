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


int dynsec_acllist__to_yaml(yaml_emitter_t *emitter, yaml_event_t *event, struct dynsec__acl *acl, const char *acl_type)
{
    struct dynsec__acl *iter, *tmp = NULL;

    HASH_ITER(hh, acl, iter, tmp){
        yaml_mapping_start_event_initialize(event, NULL, (yaml_char_t *)YAML_MAP_TAG,
                                            1, YAML_FLOW_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;

        if (!yaml_emit_int_field(emitter, event, "priority", iter->priority)) return MOSQ_ERR_UNKNOWN;
        if (!yaml_emit_bool_field(emitter, event, "allow", iter->allow)) return MOSQ_ERR_UNKNOWN;
        if (!yaml_emit_string_field(emitter, event, "acltype", acl_type)) return MOSQ_ERR_UNKNOWN;
        if (!yaml_emit_string_field(emitter, event, "topic", iter->topic)) return MOSQ_ERR_UNKNOWN;

        yaml_mapping_end_event_initialize(event);
        if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;
    }

    return MOSQ_ERR_SUCCESS;
}

int dynsec_acllist_load_yaml(yaml_parser_t *parser, yaml_event_t *event, struct dynsec__acls* acls)
{
    struct dynsec__acl **acllist;
    char* topic;
    long int priority;
    bool allow;

    YAML_PARSER_SEQUENCE_FOR_ALL(parser, event, { goto error; }, {

        acllist = NULL;
        topic = NULL;
        priority = 0;
        allow = false;


        YAML_PARSER_MAPPING_FOR_ALL(parser, event, key, { goto error; }, {
                printf("KEY=%s %s:%d\n", key, __FILE__, __LINE__);
                if (strcasecmp(key, "acltype") == 0) {
                    char *acltype;
                    YAML_EVENT_INTO_SCALAR_STRING(event, &acltype, { goto error; });

                    printf("ACLTYPE=%s %s:%d\n", acltype, __FILE__, __LINE__);


                    if (strcasecmp(acltype, ACL_TYPE_PUB_C_SEND) == 0) acllist = &acls->publish_c_send;
                    else if (strcasecmp(acltype, ACL_TYPE_PUB_C_RECV) == 0) acllist = &acls->publish_c_recv;
                    else if (strcasecmp(acltype, ACL_TYPE_SUB_LITERAL) == 0) acllist = &acls->subscribe_literal;
                    else if (strcasecmp(acltype, ACL_TYPE_SUB_PATTERN) == 0) acllist = &acls->subscribe_pattern;
                    else if (strcasecmp(acltype, ACL_TYPE_UNSUB_LITERAL) == 0) acllist = &acls->unsubscribe_literal;
                    else if (strcasecmp(acltype, ACL_TYPE_UNSUB_PATTERN) == 0) acllist = &acls->unsubscribe_pattern;
                    else {
                        mosquitto_log_printf(MOSQ_LOG_ERR, "Unknown acltype %s \n", acltype);
                        mosquitto_free(acltype);
                        goto error;
                    }

                    mosquitto_free(acltype);
                } else if (strcasecmp(key, "topic") == 0) {
                    YAML_EVENT_INTO_SCALAR_STRING(event, &topic, { goto error; });
                } else if (strcasecmp(key, "priority") == 0) {
                    YAML_EVENT_INTO_SCALAR_LONG_INT(event, &priority, { goto error; });
                } else if (strcasecmp(key, "allow") == 0) {
                    YAML_EVENT_INTO_SCALAR_BOOL(event, &allow, { goto error; });
                } else {
                    mosquitto_log_printf(MOSQ_LOG_ERR, "Unexpected key for role config %s \n", key);
                    yaml_dump_block(parser, event);
                }
        });

        if (acllist) {
            mosquitto_log_printf(MOSQ_LOG_ERR, "INSERTING ACL %s:%d\n", __FILE__, __LINE__);
            size_t topic_len = strlen(topic);
            struct dynsec__acl *acl = mosquitto_calloc(1, sizeof(struct dynsec__acl) + topic_len + 1);

            memcpy(acl->topic, topic, topic_len);
            acl->priority = (int)priority;
            acl->allow = allow;

            dynsec_acllist__add(acllist, acl);
        } else {
            mosquitto_log_printf(MOSQ_LOG_ERR, "NOT INSERTING ACL %s:%d\n", __FILE__, __LINE__);
            mosquitto_free(topic);
        }


    });


    return 1;
    error:
    mosquitto_free(topic);
    return 0;
}
