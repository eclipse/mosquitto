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

static int add_role_to_yaml(yaml_emitter_t *emitter, yaml_event_t *event, struct dynsec__role *role);

static int insert_acl_cmp(struct dynsec__acl *a, struct dynsec__acl *b)
{
    return b->priority - a->priority;
}


static int add_single_acl_to_yaml(yaml_emitter_t *emitter, yaml_event_t *event, const char *acl_type, struct dynsec__acl *acl)
{
    struct dynsec__acl *iter, *tmp = NULL;

    HASH_ITER(hh, acl, iter, tmp){

        printf("%s:%d\n", __FILE__, __LINE__);
        yaml_mapping_start_event_initialize(event, NULL, (yaml_char_t *)YAML_MAP_TAG,
                                            1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, event)) return 1;
        printf("%s:%d\n", __FILE__, __LINE__);

        if (!yaml_emit_string_field(emitter, event, "acltype", acl_type)) return 1;
        if (!yaml_emit_string_field(emitter, event, "topic", iter->topic)) return 1;
        printf("%s:%d\n", __FILE__, __LINE__);
        if (!yaml_emit_int_field(emitter, event, "priority", iter->priority)) return 1;
        if (!yaml_emit_bool_field(emitter, event, "allow", iter->allow)) return 1;

        printf("%s:%d\n", __FILE__, __LINE__);
        yaml_mapping_end_event_initialize(event);
        if (!yaml_emitter_emit(emitter, event)) return 1;
    }

    return 0;
}

static int add_acls_to_yaml(yaml_emitter_t *emitter, yaml_event_t *event, struct dynsec__role *role)
{
    printf("%s:%d\n", __FILE__, __LINE__);
    yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,
                                 (yaml_char_t *)"acls", strlen("acls"), 1, 0, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 1;


    yaml_sequence_start_event_initialize(event, NULL, (yaml_char_t *)YAML_SEQ_TAG,
                                         1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 1;

    printf("%s:%d\n", __FILE__, __LINE__);
    if (add_single_acl_to_yaml(emitter, event, ACL_TYPE_PUB_C_SEND, role->acls.publish_c_send)) return 1;
    printf("%s:%d\n", __FILE__, __LINE__);
    if (add_single_acl_to_yaml(emitter, event, ACL_TYPE_PUB_C_RECV, role->acls.publish_c_recv)) return 1;
    printf("%s:%d\n", __FILE__, __LINE__);
    if (add_single_acl_to_yaml(emitter, event, ACL_TYPE_SUB_LITERAL, role->acls.subscribe_literal)) return 1;
    printf("%s:%d\n", __FILE__, __LINE__);
    if (add_single_acl_to_yaml(emitter, event, ACL_TYPE_SUB_PATTERN, role->acls.subscribe_pattern)) return 1;
    printf("%s:%d\n", __FILE__, __LINE__);
    if (add_single_acl_to_yaml(emitter, event, ACL_TYPE_UNSUB_LITERAL, role->acls.unsubscribe_literal)) return 1;
    printf("%s:%d\n", __FILE__, __LINE__);
    if (add_single_acl_to_yaml(emitter, event, ACL_TYPE_UNSUB_PATTERN, role->acls.unsubscribe_pattern)) return 1;
    printf("%s:%d\n", __FILE__, __LINE__);

    yaml_sequence_end_event_initialize(event);
    if (!yaml_emitter_emit(emitter, event)) return 1;

    printf("%s:%d\n", __FILE__, __LINE__);

    return 0;
}


int dynsec_roles__config_save_yaml(yaml_emitter_t *emitter, yaml_event_t *event, struct dynsec__data *data)
{
    struct dynsec__role *role, *role_tmp = NULL;

    printf("%s:%d\n", __FILE__, __LINE__);
    yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,
                                 (yaml_char_t *)"roles", strlen("roles"), 1, 0, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 1;

    printf("%s:%d\n", __FILE__, __LINE__);
    yaml_sequence_start_event_initialize(event, NULL, (yaml_char_t *)YAML_SEQ_TAG,
                                         1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 1;

    HASH_ITER(hh, data->roles, role, role_tmp){
        printf("%s:%d\n", __FILE__, __LINE__);
        if (add_role_to_yaml(emitter, event, role)) return 1;
    }

    printf("%s:%d\n", __FILE__, __LINE__);
    yaml_sequence_end_event_initialize(event);
    if (!yaml_emitter_emit(emitter, event)) return 1;


    return 0;
}

static int dynsec_roles__acl_load_yaml(yaml_parser_t *parser, yaml_event_t *event, struct dynsec__acls* acls)
{
    struct dynsec__acl **acllist;
    char* topic;
    long int priority;
    bool allow;

    YAML_PARSER_SEQUENCE_FOR_ALL(parser, event, { goto error; }, {
            printf("%s:%d\n", __FILE__, __LINE__);

            acllist = NULL;
            topic = NULL;
            priority = 0;
            allow = false;

            printf("%s:%d\n", __FILE__, __LINE__);

            YAML_PARSER_MAPPING_FOR_ALL(parser, event, key, { goto error; }, {
                printf("KEY=%s %s:%d\n", key, __FILE__, __LINE__);
                if (strcmp(key, "acltype") == 0) {
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
                } else if (strcmp(key, "topic") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_STRING(event, &topic, { goto error; });
                } else if (strcmp(key, "priority") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_LONG_INT(event, &priority, { goto error; });
                } else if (strcmp(key, "allow") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_BOOL(event, &allow, { goto error; });
                } else {
                    mosquitto_log_printf(MOSQ_LOG_ERR, "Unexpected key for role config %s \n", key);
                    yaml_dump_block(parser, event);
                    printf("%s:%d\n", __FILE__, __LINE__);
                }
            });

            if (acllist) {
                mosquitto_log_printf(MOSQ_LOG_ERR, "INSERTING ACL %s:%d\n", __FILE__, __LINE__);
                size_t topic_len = strlen(topic);
                struct dynsec__acl *acl = mosquitto_calloc(1, sizeof(struct dynsec__acl) + topic_len + 1);

                memcpy(acl->topic, topic, topic_len);
                acl->priority = (int)priority;
                acl->allow = allow;

                mosquitto_log_printf(MOSQ_LOG_ERR, "INSERTING ACL %s:%d\n", __FILE__, __LINE__);
                HASH_ADD_KEYPTR_INORDER(hh, *acllist, acl->topic, strlen(acl->topic), acl, insert_acl_cmp);
            } else {
                mosquitto_log_printf(MOSQ_LOG_ERR, "NOT INSERTING ACL %s:%d\n", __FILE__, __LINE__);
                mosquitto_free(topic);
            }

            printf("%s:%d\n", __FILE__, __LINE__);

    });

    printf("%s:%d\n", __FILE__, __LINE__);

    return 1;
    error:
    mosquitto_free(topic);
    return 0;
}

int dynsec_roles__config_load_yaml(yaml_parser_t *parser, yaml_event_t *event, struct dynsec__data *data)
{
    struct dynsec__role *role = NULL;
    char* textname;
    char* textdescription;
    struct dynsec__acls acls;

    YAML_PARSER_SEQUENCE_FOR_ALL(parser, event, { goto error; }, {
            memset(&acls, 0, sizeof(acls));
            printf("%s:%d\n", __FILE__, __LINE__);

            role = NULL;
            textname = textdescription = NULL;

            printf("%s:%d\n", __FILE__, __LINE__);

            YAML_PARSER_MAPPING_FOR_ALL(parser, event, key, { goto error; }, {
                printf("%s:%d\n", __FILE__, __LINE__);
                if (strcmp(key, "rolename") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    char *rolename;
                    YAML_EVENT_INTO_SCALAR_STRING(event, &rolename, { goto error; });
                    role = dynsec_roles__find_or_create(data, rolename);
                    mosquitto_free(rolename);
                } else if (strcmp(key, "textname") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_STRING(event, &textname, { goto error; });
                } else if (strcmp(key, "textdescription") == 0) {
                    printf("%s:%d\n", __FILE__, __LINE__);
                    YAML_EVENT_INTO_SCALAR_STRING(event, &textdescription, { goto error; });
                } else if (strcmp(key, "acls") == 0) {
                    if (!dynsec_roles__acl_load_yaml(parser, event, &acls)) goto error;
                    printf("%s:%d\n", __FILE__, __LINE__);
                } else {
                    yaml_dump_block(parser, event);
                    printf("%s:%d\n", __FILE__, __LINE__);
                    mosquitto_log_printf(MOSQ_LOG_ERR, "Unexpected key for client config %s \n", key);
                }
            });

            if (role) {
                role->text_name = textname;
                role->text_description = textdescription;
                role->acls = acls;
            } else {
                mosquitto_free(textname);
                mosquitto_free(textdescription);
            }

            printf("%s:%d\n", __FILE__, __LINE__);

    });

    printf("%s:%d\n", __FILE__, __LINE__);

    return 1;

    error:
    mosquitto_free(textname);
    mosquitto_free(textdescription);
    return 0;
}

static int add_role_to_yaml(yaml_emitter_t *emitter, yaml_event_t *event, struct dynsec__role *role)
{
    printf("%s:%d\n", __FILE__, __LINE__);
    yaml_mapping_start_event_initialize(event, NULL, (yaml_char_t *)YAML_MAP_TAG,
                                        1, YAML_ANY_MAPPING_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 1;

    printf("%s:%d\n", __FILE__, __LINE__);
    if (!yaml_emit_string_field(emitter, event, "rolename", role->rolename)) return 1;
    if (role->text_name && !yaml_emit_string_field(emitter, event, "textname", role->text_name)) return 1;
    if (role->text_description && !yaml_emit_string_field(emitter, event, "textdescription", role->text_description)) return 1;
    printf("%s:%d\n", __FILE__, __LINE__);

    if(add_acls_to_yaml(emitter, event, role)) return 1;

    printf("%s:%d\n", __FILE__, __LINE__);
    yaml_mapping_end_event_initialize(event);
    if (!yaml_emitter_emit(emitter, event)) return 1;

    printf("%s:%d\n", __FILE__, __LINE__);
    return 0;
}


