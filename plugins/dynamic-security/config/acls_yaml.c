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

int dynsec__acls__to_yaml(yaml_emitter_t *emitter, yaml_event_t *event, struct dynsec__role *role)
{
    yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,
                                 (yaml_char_t *)"acls", strlen("acls"), 1, 0, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;


    yaml_sequence_start_event_initialize(event, NULL, (yaml_char_t *)YAML_SEQ_TAG,
                                         1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;

    if (dynsec_acllist__to_yaml(emitter, event, role->acls.publish_c_send, ACL_TYPE_PUB_C_SEND)) return MOSQ_ERR_UNKNOWN;
    if (dynsec_acllist__to_yaml(emitter, event, role->acls.publish_c_recv, ACL_TYPE_PUB_C_RECV)) return MOSQ_ERR_UNKNOWN;
    if (dynsec_acllist__to_yaml(emitter, event, role->acls.subscribe_literal, ACL_TYPE_SUB_LITERAL)) return MOSQ_ERR_UNKNOWN;
    if (dynsec_acllist__to_yaml(emitter, event, role->acls.subscribe_pattern, ACL_TYPE_SUB_PATTERN)) return MOSQ_ERR_UNKNOWN;
    if (dynsec_acllist__to_yaml(emitter, event, role->acls.unsubscribe_literal, ACL_TYPE_UNSUB_LITERAL)) return MOSQ_ERR_UNKNOWN;
    if (dynsec_acllist__to_yaml(emitter, event, role->acls.unsubscribe_pattern, ACL_TYPE_UNSUB_PATTERN)) return MOSQ_ERR_UNKNOWN;

    yaml_sequence_end_event_initialize(event);
    if (!yaml_emitter_emit(emitter, event)) return MOSQ_ERR_UNKNOWN;

    return MOSQ_ERR_SUCCESS;
}

int dynsec_acls__load_yaml(yaml_parser_t *parser, yaml_event_t *event, struct dynsec__acls* acls)
{
    struct dynsec__acl **acllist;
    char* topic;
    long int priority;
    bool allow;
    int ret;

    YAML_PARSER_SEQUENCE_FOR_ALL(parser, event, { ret = MOSQ_ERR_INVAL; goto error; }, {
        acllist = NULL;
        topic = NULL;
        priority = 0;
        allow = false;

        YAML_PARSER_MAPPING_FOR_ALL(parser, event, key, { ret = MOSQ_ERR_INVAL; goto error; }, {
                if (strcmp(key, "acltype") == 0) {
                    char *acltype;
                    YAML_EVENT_INTO_SCALAR_STRING(event, &acltype, { ret = MOSQ_ERR_INVAL; goto error; });

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
                } else if (strcmp(key, "topic") == 0) {
                    YAML_EVENT_INTO_SCALAR_STRING(event, &topic, { ret = MOSQ_ERR_INVAL; goto error; });
                } else if (strcmp(key, "priority") == 0) {
                    YAML_EVENT_INTO_SCALAR_LONG_INT(event, &priority, { ret = MOSQ_ERR_INVAL; goto error; });
                } else if (strcmp(key, "allow") == 0) {
                    YAML_EVENT_INTO_SCALAR_BOOL(event, &allow, { ret = MOSQ_ERR_INVAL; goto error; });
                } else {
                    mosquitto_log_printf(MOSQ_LOG_ERR, "Unexpected key for role config %s \n", key);
                    yaml_dump_block(parser, event);
                }
        });

        if (acllist) {
            size_t topic_len = strlen(topic);
            struct dynsec__acl *acl = mosquitto_calloc(1, sizeof(struct dynsec__acl) + topic_len + 1);

            memcpy(acl->topic, topic, topic_len);
            acl->priority = (int)priority;
            acl->allow = allow;

            dynsec_acllist__add(acllist, acl);
        } else {
            mosquitto_free(topic);
        }
    });

    return MOSQ_ERR_SUCCESS;
error:
    mosquitto_free(topic);
    return ret;
}
