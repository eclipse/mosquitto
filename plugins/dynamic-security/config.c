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
*/

#include "config.h"

#include <cjson/cJSON.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "json_help.h"
#include "misc_mosq.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mqtt_protocol.h"

#include "dynamic_security.h"
#include "yaml.h"
#include "yaml_help.h"

static int dynsec__general_config_load_json(struct dynsec__data *data, cJSON *tree)
{
	cJSON *j_default_access;

	j_default_access = cJSON_GetObjectItem(tree, "defaultACLAccess");
	if(j_default_access && cJSON_IsObject(j_default_access)){
		json_get_bool(j_default_access, ACL_TYPE_PUB_C_SEND, &data->default_access.publish_c_send, true, false);
		json_get_bool(j_default_access, ACL_TYPE_PUB_C_RECV, &data->default_access.publish_c_recv, true, false);
		json_get_bool(j_default_access, ACL_TYPE_SUB_GENERIC, &data->default_access.subscribe, true, false);
		json_get_bool(j_default_access, ACL_TYPE_UNSUB_GENERIC, &data->default_access.unsubscribe, true, false);
	}
	return MOSQ_ERR_SUCCESS;
}

static int dynsec__general_config_load_yaml(yaml_parser_t *parser, yaml_event_t *event, struct dynsec__data *data)
{
    YAML_PARSER_MAPPING_FOR_ALL(parser, event, key, { return 0; }, {
        if (strcmp(key, ACL_TYPE_PUB_C_SEND) == 0) {
            YAML_EVENT_INTO_SCALAR_BOOL(event, &data->default_access.publish_c_send, { return 0; });
        } else if (strcmp(key, ACL_TYPE_PUB_C_RECV) == 0) {
            YAML_EVENT_INTO_SCALAR_BOOL(event, &data->default_access.publish_c_recv, { return 0; });
        } else if (strcmp(key, ACL_TYPE_SUB_GENERIC) == 0) {
            YAML_EVENT_INTO_SCALAR_BOOL(event, &data->default_access.subscribe, { return 0; });
        } else if (strcmp(key, ACL_TYPE_UNSUB_GENERIC) == 0) {
            YAML_EVENT_INTO_SCALAR_BOOL(event, &data->default_access.unsubscribe, { return 0; });
        } else {
            mosquitto_log_printf(MOSQ_LOG_ERR, "Error parsing Dynamic security plugin config. Unknown key %s found on line %d:%d at %s:%d, \n", key, event->start_mark.line, event->start_mark.column, __FILE__, __LINE__ );
            return 0;
        }
    });

    return 1;
}

static int dynsec__general_config_save_json(struct dynsec__data *data, cJSON *tree)
{
	cJSON *j_default_access;

	j_default_access = cJSON_CreateObject();
	if(j_default_access == NULL){
		return 1;
	}
	cJSON_AddItemToObject(tree, "defaultACLAccess", j_default_access);

	if(cJSON_AddBoolToObject(j_default_access, ACL_TYPE_PUB_C_SEND, data->default_access.publish_c_send) == NULL
			|| cJSON_AddBoolToObject(j_default_access, ACL_TYPE_PUB_C_RECV, data->default_access.publish_c_recv) == NULL
			|| cJSON_AddBoolToObject(j_default_access, ACL_TYPE_SUB_GENERIC, data->default_access.subscribe) == NULL
			|| cJSON_AddBoolToObject(j_default_access, ACL_TYPE_UNSUB_GENERIC, data->default_access.unsubscribe) == NULL
			){

		return 1;
	}

	return MOSQ_ERR_SUCCESS;
}

static int dynsec__general_config_save_yaml(yaml_emitter_t* emitter, yaml_event_t* event, struct dynsec__data *data)
{
    printf("%s:%d\n", __FILE__, __LINE__);

    yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,
                                 (yaml_char_t *)"defaultACLAccess", strlen("defaultACLAccess"), 1, 0, YAML_PLAIN_SCALAR_STYLE);

    printf("%s:%d\n", __FILE__, __LINE__);

    if (!yaml_emitter_emit(emitter, event)) return 1;

    printf("%s:%d\n", __FILE__, __LINE__);

    yaml_mapping_start_event_initialize(event, NULL, (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 1;

    printf("%s:%d\n", __FILE__, __LINE__);

    if (!yaml_emit_bool_field(emitter, event, ACL_TYPE_PUB_C_SEND, data->default_access.publish_c_send)) return 1;
    if (!yaml_emit_bool_field(emitter, event, ACL_TYPE_PUB_C_RECV, data->default_access.publish_c_recv)) return 1;
    if (!yaml_emit_bool_field(emitter, event, ACL_TYPE_SUB_GENERIC, data->default_access.subscribe)) return 1;
    if (!yaml_emit_bool_field(emitter, event, ACL_TYPE_UNSUB_GENERIC, data->default_access.unsubscribe)) return 1;

    printf("%s:%d\n", __FILE__, __LINE__);
    yaml_mapping_end_event_initialize(event);
    if (!yaml_emitter_emit(emitter, event)) return 1;

    printf("%s:%d\n", __FILE__, __LINE__);
    return 0;
}

static int dynsec__config_load_yaml(struct dynsec__data *data, FILE* fptr)
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
                if (!dynsec__general_config_load_yaml(&parser, &event, data)) goto print_error;
            } else if (strcmp(key, "clients") == 0) {
                if (!dynsec_clients__config_load_yaml(&parser, &event, data)) goto print_error;
            } else if (strcmp(key, "groups") == 0) {
                printf("groups:\n");
                if (!dynsec_groups__config_load_yaml(&parser, &event, data)) goto print_error;
            } else  if (strcmp(key, "roles") == 0) {
                printf("roles:\n");
                if (!dynsec_roles__config_load_yaml(&parser, &event, data)) goto print_error;
            } else {
                mosquitto_log_printf(MOSQ_LOG_ERR, "Error parsing Dynamic security plugin config. Unknown key %s found on line %d:%d at %s:%d, \n", event.data.scalar.value, event.start_mark.line, event.start_mark.column, __FILE__, __LINE__ );
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

static int dynsec__config_load_json(struct dynsec__data *data, FILE* fptr)
{
    size_t flen;
    long flen_l;
    char *json_str;
	cJSON *tree;

    fseek(fptr, 0, SEEK_END);
    flen_l = ftell(fptr);
    if (flen_l < 0) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error loading Dynamic security plugin config: %s", strerror(errno));
        return 1;
    } else if (flen_l == 0){
        return 0;
    }
    flen = (size_t)flen_l;
    fseek(fptr, 0, SEEK_SET);
    json_str = mosquitto_calloc(flen+1, sizeof(char));
    if (json_str == NULL) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Out of memory.");
        return 1;
    }
    if (fread(json_str, 1, flen, fptr) != flen) {
        mosquitto_log_printf(MOSQ_LOG_WARNING, "Error loading Dynamic security plugin config: Unable to read file contents.\n");
        mosquitto_free(json_str);
        return 1;
    }

	tree = cJSON_Parse(json_str);
	if(tree == NULL){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error loading Dynamic security plugin config: File is not valid JSON.");
		return 1;
	}

	if(dynsec__general_config_load_json(data, tree)
			|| dynsec_roles__config_load_json(data, tree)
			|| dynsec_clients__config_load_json(data, tree)
			|| dynsec_groups__config_load_json(data, tree)
			){

		cJSON_Delete(tree);
		return 1;
	}

	cJSON_Delete(tree);
	return 0;
}

char *dynsec__config_to_json(struct dynsec__data *data)
{
	cJSON *tree;
	char *json_str;

	tree = cJSON_CreateObject();
	if(tree == NULL) return NULL;

	if(dynsec__general_config_save_json(data, tree)
			|| dynsec_clients__config_save_json(data, tree)
			|| dynsec_groups__config_save_json(data, tree)
			|| dynsec_roles__config_save_json(data, tree)){

		cJSON_Delete(tree);
		return NULL;
	}

	/* Print json to string */
	json_str = cJSON_Print(tree);
	cJSON_Delete(tree);
	return json_str;
}

void dynsec__log_write_error(const char* msg)
{
	mosquitto_log_printf(MOSQ_LOG_ERR, "Error saving Dynamic security plugin config: %s", msg);
}

static int dynsec__write_json_config(FILE* fptr, void* user_data)
{
	struct dynsec__data *data = (struct dynsec__data *)user_data;
	char *json_str;
	size_t json_str_len;
	int rc = MOSQ_ERR_SUCCESS;

	json_str = dynsec__config_to_json(data);
	if(json_str == NULL){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error saving Dynamic security plugin config: Out of memory.\n");
		return MOSQ_ERR_NOMEM;
	}
	json_str_len = strlen(json_str);

	if (fwrite(json_str, 1, json_str_len, fptr) != json_str_len){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error saving Dynamic security plugin config: Cannot write whole config (%ld) bytes to file %s", json_str_len, data->config_file);
		rc = MOSQ_ERR_UNKNOWN;
  }

	mosquitto_free(json_str);
	return rc;
}

static int dynsec__write_yaml_config(FILE* fptr, void *user_data)
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


void dynsec__config_batch_save(struct dynsec__data *data)
{
	data->need_save = true;
}

static int str_ends_with(const char *str, const char *suffix) {
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);

    return (str_len >= suffix_len) &&
           (!memcmp(str + str_len - suffix_len, suffix, suffix_len));
}

int dynsec__config_load(struct dynsec__data *data)
{
    FILE *fptr;
    int rc;

    /* Load from file */
    fptr = fopen(data->config_file, "rb");
    if(fptr == NULL){
        /* Attempt to initialise a new config file */
        if(dynsec__config_init(data) == MOSQ_ERR_SUCCESS){
            /* If it works, try to open the file again */
            fptr = fopen(data->config_file, "rb");
        }

        if(fptr == NULL){
            mosquitto_log_printf(MOSQ_LOG_ERR,
                                 "Error loading Dynamic security plugin config: File is not readable - check permissions.");
            return MOSQ_ERR_UNKNOWN;
        }
    }

    if (str_ends_with(data->config_file, ".yaml") || str_ends_with(data->config_file, ".yml")) {
        rc = dynsec__config_load_yaml(data, fptr);
    } else {
        rc = dynsec__config_load_json(data, fptr);
    }

    fclose(fptr);

    return rc;
}

void dynsec__config_save(struct dynsec__data *data)
{
	data->need_save = false;

    if (str_ends_with(data->config_file, ".yaml") || str_ends_with(data->config_file, ".yml")) {
        mosquitto_write_file(data->config_file, true, &dynsec__write_yaml_config, data, &dynsec__log_write_error);
    } else {
        mosquitto_write_file(data->config_file, true, &dynsec__write_json_config, data, &dynsec__log_write_error);
    }
}
