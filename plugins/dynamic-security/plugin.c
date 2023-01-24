/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>

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

#ifndef WIN32
#  include <strings.h>
#endif

#include "json_help.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mqtt_protocol.h"

#include "dynamic_security.h"

#include "yaml.h"
#include "yaml_help.h"

static mosquitto_plugin_id_t *plg_id = NULL;
static char *config_file = NULL;
struct dynsec__acl_default_access default_access = {false, false, false, false};

void dynsec__command_reply(cJSON *j_responses, struct mosquitto *context, const char *command, const char *error, const char *correlation_data)
{
	cJSON *j_response;

	UNUSED(context);

	j_response = cJSON_CreateObject();
	if(j_response == NULL) return;

	if(cJSON_AddStringToObject(j_response, "command", command) == NULL
			|| (error && cJSON_AddStringToObject(j_response, "error", error) == NULL)
			|| (correlation_data && cJSON_AddStringToObject(j_response, "correlationData", correlation_data) == NULL)
			){

		cJSON_Delete(j_response);
		return;
	}

	cJSON_AddItemToArray(j_responses, j_response);
}


static void send_response(cJSON *tree)
{
	char *payload;
	size_t payload_len;

	payload = cJSON_PrintUnformatted(tree);
	cJSON_Delete(tree);
	if(payload == NULL) return;

	payload_len = strlen(payload);
	if(payload_len > MQTT_MAX_PAYLOAD){
		free(payload);
		return;
	}
	mosquitto_broker_publish(NULL, "$CONTROL/dynamic-security/v1/response",
			(int)payload_len, payload, 0, 0, NULL);
}


static int dynsec_control_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_control *ed = event_data;
	cJSON *tree, *commands;
	cJSON *j_response_tree, *j_responses;

	UNUSED(event);
	UNUSED(userdata);

	/* Create object for responses */
	j_response_tree = cJSON_CreateObject();
	if(j_response_tree == NULL){
		return MOSQ_ERR_NOMEM;
	}
	j_responses = cJSON_CreateArray();
	if(j_responses == NULL){
		cJSON_Delete(j_response_tree);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToObject(j_response_tree, "responses", j_responses);


	/* Parse cJSON tree.
	 * Using cJSON_ParseWithLength() is the best choice here, but Mosquitto
	 * always adds an extra 0 to the end of the payload memory, so using
	 * cJSON_Parse() on its own will still not overrun. */
#if CJSON_VERSION_FULL < 1007013
	tree = cJSON_Parse(ed->payload);
#else
	tree = cJSON_ParseWithLength(ed->payload, ed->payloadlen);
#endif
	if(tree == NULL){
		dynsec__command_reply(j_responses, ed->client, "Unknown command", "Payload not valid JSON", NULL);
		send_response(j_response_tree);
		return MOSQ_ERR_SUCCESS;
	}
	commands = cJSON_GetObjectItem(tree, "commands");
	if(commands == NULL || !cJSON_IsArray(commands)){
		cJSON_Delete(tree);
		dynsec__command_reply(j_responses, ed->client, "Unknown command", "Invalid/missing commands", NULL);
		send_response(j_response_tree);
		return MOSQ_ERR_SUCCESS;
	}

	/* Handle commands */
	dynsec__handle_control(j_responses, ed->client, commands);
	cJSON_Delete(tree);

	send_response(j_response_tree);

	return MOSQ_ERR_SUCCESS;
}

static int dynsec__process_set_default_acl_access(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	cJSON *j_actions, *j_action, *j_acltype, *j_allow;
	bool allow;
	const char *admin_clientid, *admin_username;

	j_actions = cJSON_GetObjectItem(command, "acls");
	if(j_actions == NULL || !cJSON_IsArray(j_actions)){
		dynsec__command_reply(j_responses, context, "setDefaultACLAccess", "Missing/invalid actions array", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);

	cJSON_ArrayForEach(j_action, j_actions){
		j_acltype = cJSON_GetObjectItem(j_action, "acltype");
		j_allow = cJSON_GetObjectItem(j_action, "allow");
		if(j_acltype && cJSON_IsString(j_acltype)
					&& j_allow && cJSON_IsBool(j_allow)){

			allow = cJSON_IsTrue(j_allow);

			if(!strcasecmp(j_acltype->valuestring, ACL_TYPE_PUB_C_SEND)){
				default_access.publish_c_send = allow;
			}else if(!strcasecmp(j_acltype->valuestring, ACL_TYPE_PUB_C_RECV)){
				default_access.publish_c_recv = allow;
			}else if(!strcasecmp(j_acltype->valuestring, ACL_TYPE_SUB_GENERIC)){
				default_access.subscribe = allow;
			}else if(!strcasecmp(j_acltype->valuestring, ACL_TYPE_UNSUB_GENERIC)){
				default_access.unsubscribe = allow;
			}
			mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | setDefaultACLAccess | acltype=%s | allow=%s",
					admin_clientid, admin_username, j_acltype->valuestring, allow?"true":"false");
		}
	}

	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "setDefaultACLAccess", NULL, correlation_data);
	return MOSQ_ERR_SUCCESS;
}


static int dynsec__process_get_default_acl_access(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	cJSON *tree, *jtmp, *j_data, *j_acls, *j_acl;
	const char *admin_clientid, *admin_username;

	UNUSED(command);

	tree = cJSON_CreateObject();
	if(tree == NULL){
		dynsec__command_reply(j_responses, context, "getDefaultACLAccess", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | getDefaultACLAccess",
			admin_clientid, admin_username);

	if(cJSON_AddStringToObject(tree, "command", "getDefaultACLAccess") == NULL
		|| ((j_data = cJSON_AddObjectToObject(tree, "data")) == NULL)

			){
		goto internal_error;
	}

	j_acls = cJSON_AddArrayToObject(j_data, "acls");
	if(j_acls == NULL){
		goto internal_error;
	}

	/* publishClientSend */
	j_acl = cJSON_CreateObject();
	if(j_acl == NULL){
		goto internal_error;
	}
	cJSON_AddItemToArray(j_acls, j_acl);
	if(cJSON_AddStringToObject(j_acl, "acltype", ACL_TYPE_PUB_C_SEND) == NULL
			|| cJSON_AddBoolToObject(j_acl, "allow", default_access.publish_c_send) == NULL
			){

		goto internal_error;
	}

	/* publishClientReceive */
	j_acl = cJSON_CreateObject();
	if(j_acl == NULL){
		goto internal_error;
	}
	cJSON_AddItemToArray(j_acls, j_acl);
	if(cJSON_AddStringToObject(j_acl, "acltype", ACL_TYPE_PUB_C_RECV) == NULL
			|| cJSON_AddBoolToObject(j_acl, "allow", default_access.publish_c_recv) == NULL
			){

		goto internal_error;
	}

	/* subscribe */
	j_acl = cJSON_CreateObject();
	if(j_acl == NULL){
		goto internal_error;
	}
	cJSON_AddItemToArray(j_acls, j_acl);
	if(cJSON_AddStringToObject(j_acl, "acltype", ACL_TYPE_SUB_GENERIC) == NULL
			|| cJSON_AddBoolToObject(j_acl, "allow", default_access.subscribe) == NULL
			){

		goto internal_error;
	}

	/* unsubscribe */
	j_acl = cJSON_CreateObject();
	if(j_acl == NULL){
		goto internal_error;
	}
	cJSON_AddItemToArray(j_acls, j_acl);
	if(cJSON_AddStringToObject(j_acl, "acltype", ACL_TYPE_UNSUB_GENERIC) == NULL
			|| cJSON_AddBoolToObject(j_acl, "allow", default_access.unsubscribe) == NULL
			){

		goto internal_error;
	}

	cJSON_AddItemToArray(j_responses, tree);

	if(correlation_data){
		jtmp = cJSON_AddStringToObject(tree, "correlationData", correlation_data);
		if(jtmp == NULL){
			goto internal_error;
		}
	}

	return MOSQ_ERR_SUCCESS;

internal_error:
	cJSON_Delete(tree);
	dynsec__command_reply(j_responses, context, "getDefaultACLAccess", "Internal error", correlation_data);
	return MOSQ_ERR_NOMEM;
}


int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)
{
	int i;

	for(i=0; i<supported_version_count; i++){
		if(supported_versions[i] == 5){
			return 5;
		}
	}
	return -1;
}

static int dynsec__general_config_load_yaml(yaml_parser_t *parser, yaml_event_t *event)
{
    YAML_PARSER_MAPPING_FOR_ALL(parser, event, key, { return 0; }, {
        if (strcmp(key, ACL_TYPE_PUB_C_SEND) == 0) {
            YAML_EVENT_INTO_SCALAR_BOOL(event, &default_access.publish_c_send, { return 0; });
        } else if (strcmp(key, ACL_TYPE_PUB_C_RECV) == 0) {
            YAML_EVENT_INTO_SCALAR_BOOL(event, &default_access.publish_c_recv, { return 0; });
        } else if (strcmp(key, ACL_TYPE_SUB_GENERIC) == 0) {
            YAML_EVENT_INTO_SCALAR_BOOL(event, &default_access.subscribe, { return 0; });
        } else if (strcmp(key, ACL_TYPE_UNSUB_GENERIC) == 0) {
            YAML_EVENT_INTO_SCALAR_BOOL(event, &default_access.unsubscribe, { return 0; });
        } else {
            mosquitto_log_printf(MOSQ_LOG_ERR, "Error parsing Dynamic security plugin config. Unknown key %s found on line %d:%d at %s:%d, \n", key, event->start_mark.line, event->start_mark.column, __FILE__, __LINE__ );
            return 0;
        }
    });

    return 1;
}


static int dynsec__general_config_load(cJSON *tree)
{
	cJSON *j_default_access, *jtmp;

	j_default_access = cJSON_GetObjectItem(tree, "defaultACLAccess");
	if(j_default_access && cJSON_IsObject(j_default_access)){
		jtmp = cJSON_GetObjectItem(j_default_access, ACL_TYPE_PUB_C_SEND);
		if(jtmp && cJSON_IsBool(jtmp)){
			default_access.publish_c_send = cJSON_IsTrue(jtmp);
		}else{
			default_access.publish_c_send = false;
		}

		jtmp = cJSON_GetObjectItem(j_default_access, ACL_TYPE_PUB_C_RECV);
		if(jtmp && cJSON_IsBool(jtmp)){
			default_access.publish_c_recv = cJSON_IsTrue(jtmp);
		}else{
			default_access.publish_c_recv = false;
		}

		jtmp = cJSON_GetObjectItem(j_default_access, ACL_TYPE_SUB_GENERIC);
		if(jtmp && cJSON_IsBool(jtmp)){
			default_access.subscribe = cJSON_IsTrue(jtmp);
		}else{
			default_access.subscribe = false;
		}

		jtmp = cJSON_GetObjectItem(j_default_access, ACL_TYPE_UNSUB_GENERIC);
		if(jtmp && cJSON_IsBool(jtmp)){
			default_access.unsubscribe = cJSON_IsTrue(jtmp);
		}else{
			default_access.unsubscribe = false;
		}
	}
	return MOSQ_ERR_SUCCESS;
}



static int dynsec__general_config_save(cJSON *tree)
{
	cJSON *j_default_access;

	j_default_access = cJSON_CreateObject();
	if(j_default_access == NULL){
		return 1;
	}
	cJSON_AddItemToObject(tree, "defaultACLAccess", j_default_access);

	if(cJSON_AddBoolToObject(j_default_access, ACL_TYPE_PUB_C_SEND, default_access.publish_c_send) == NULL
			|| cJSON_AddBoolToObject(j_default_access, ACL_TYPE_PUB_C_RECV, default_access.publish_c_recv) == NULL
			|| cJSON_AddBoolToObject(j_default_access, ACL_TYPE_SUB_GENERIC, default_access.subscribe) == NULL
			|| cJSON_AddBoolToObject(j_default_access, ACL_TYPE_UNSUB_GENERIC, default_access.unsubscribe) == NULL
			){

		return 1;
	}

	return MOSQ_ERR_SUCCESS;
}

static int dynsec__general_config_save_yaml(yaml_emitter_t* emitter, yaml_event_t* event)
{
    printf("%s:%d\n", __FILE__, __LINE__);

    yaml_scalar_event_initialize(event, NULL, (yaml_char_t *)YAML_STR_TAG,
                                 (yaml_char_t *)"defaultACLAccess", strlen("defaultACLAccess"), 1, 0, YAML_PLAIN_SCALAR_STYLE);

    printf("%s:%d\n", __FILE__, __LINE__);

    if (!yaml_emitter_emit(emitter, event)) return 0;

    printf("%s:%d\n", __FILE__, __LINE__);

    yaml_mapping_start_event_initialize(event, NULL, (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
    if (!yaml_emitter_emit(emitter, event)) return 0;

    printf("%s:%d\n", __FILE__, __LINE__);

    if (!yaml_emit_bool_field(emitter, event, ACL_TYPE_PUB_C_SEND, default_access.publish_c_send)) return 0;
    if (!yaml_emit_bool_field(emitter, event, ACL_TYPE_PUB_C_RECV, default_access.publish_c_recv)) return 0;
    if (!yaml_emit_bool_field(emitter, event, ACL_TYPE_SUB_GENERIC, default_access.subscribe)) return 0;
    if (!yaml_emit_bool_field(emitter, event, ACL_TYPE_UNSUB_GENERIC, default_access.unsubscribe)) return 0;

    printf("%s:%d\n", __FILE__, __LINE__);
    yaml_mapping_end_event_initialize(event);
    if (!yaml_emitter_emit(emitter, event)) return 0;

    printf("%s:%d\n", __FILE__, __LINE__);
    return 1;
}


static int dynsec__config_load_yaml(void)
{
    yaml_parser_t parser;
    yaml_event_t event;

    yaml_parser_initialize(&parser);

    /* Load from file */
    FILE *fptr = fopen(config_file, "rb");
    if(fptr == NULL){
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error loading Dynamic security plugin config: File is not readable - check permissions.\n");
        return MOSQ_ERR_ERRNO;
    }
#ifndef WIN32
    if(errno == ENOTDIR || errno == EISDIR){
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error loading Dynamic security plugin config: Config is not a file.\n");
        return MOSQ_ERR_ERRNO;
    }
#endif

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
            if (!dynsec__general_config_load_yaml(&parser, &event)) goto print_error;
        } else if (strcmp(key, "clients") == 0) {
            if (!dynsec_clients__config_load_yaml(&parser, &event)) goto print_error;
        } else if (strcmp(key, "groups") == 0) {
            printf("groups:\n");
            if (!dynsec_groups__config_load_yaml(&parser, &event)) goto print_error;
        } else  if (strcmp(key, "roles") == 0) {
            printf("roles:\n");
            if (!dynsec_roles__config_load_from_yaml(&parser, &event)) goto print_error;
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

    fclose(fptr);

    dynsec__config_save();

    return 0;

print_error:
    mosquitto_log_printf(MOSQ_LOG_ERR, "Error parsing Dynamic security plugin config on line %d:%d: %s, \n", parser.problem_mark.line, parser.problem_mark.column, parser.problem);
    return 1;
}


static int dynsec__config_load_json(void)
{
	FILE *fptr;
	long flen_l;
	size_t flen;
	char *json_str;
	cJSON *tree;

	/* Load from file */
	errno = 0;
	fptr = fopen(config_file, "rb");
	if(fptr == NULL){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error loading Dynamic security plugin config: File is not readable - check permissions.\n");
		return MOSQ_ERR_ERRNO;
	}
#ifndef WIN32
	if(errno == ENOTDIR || errno == EISDIR){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error loading Dynamic security plugin config: Config is not a file.\n");
		return MOSQ_ERR_ERRNO;
	}
#endif

	fseek(fptr, 0, SEEK_END);
	flen_l = ftell(fptr);
	if(flen_l < 0){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error loading Dynamic security plugin config: %s\n", strerror(errno));
		fclose(fptr);
		return MOSQ_ERR_ERRNO;
	}else if(flen_l == 0){
		fclose(fptr);
		return 0;
	}
	flen = (size_t)flen_l;
	fseek(fptr, 0, SEEK_SET);
	json_str = mosquitto_calloc(flen+1, sizeof(char));
	if(json_str == NULL){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Out of memory.");
		fclose(fptr);
		return MOSQ_ERR_NOMEM;
	}
	if(fread(json_str, 1, flen, fptr) != flen){
		mosquitto_log_printf(MOSQ_LOG_WARNING, "Error loading Dynamic security plugin config: Unable to read file contents.\n");
		mosquitto_free(json_str);
		fclose(fptr);
		return MOSQ_ERR_ERRNO;
	}
	fclose(fptr);

	tree = cJSON_Parse(json_str);
	mosquitto_free(json_str);
	if(tree == NULL){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error loading Dynamic security plugin config: File is not valid JSON.\n");
		return MOSQ_ERR_INVAL;
	}

	if(dynsec__general_config_load(tree)
			|| dynsec_roles__config_load(tree)
			|| dynsec_clients__config_load(tree)
			|| dynsec_groups__config_load(tree)
			){

		cJSON_Delete(tree);
		return MOSQ_ERR_NOMEM;
	}

	cJSON_Delete(tree);
	return 0;
}

static int str_ends_with(const char *str, const char *suffix) {
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);

    return (str_len >= suffix_len) &&
           (!memcmp(str + str_len - suffix_len, suffix, suffix_len));
}


static void dynsec__config_load(void)
{
    if (str_ends_with(config_file, ".yaml") || str_ends_with(config_file, ".yml")) {
        dynsec__config_load_yaml();
    } else {
        dynsec__config_load_json();
    }
}


static void dynsec__config_save_json(void)
{
    cJSON *tree;
    size_t file_path_len;
    char *file_path;
    FILE *fptr;
    size_t json_str_len;
    char *json_str;

    tree = cJSON_CreateObject();
    if(tree == NULL) return;

    if(dynsec__general_config_save(tree)
       || dynsec_clients__config_save(tree)
       || dynsec_groups__config_save(tree)
       || dynsec_roles__config_save(tree)){

        cJSON_Delete(tree);
        return;
    }

    /* Print json to string */
    json_str = cJSON_Print(tree);
    if(json_str == NULL){
        cJSON_Delete(tree);
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error saving Dynamic security plugin config: Out of memory.\n");
        return;
    }
    cJSON_Delete(tree);
    json_str_len = strlen(json_str);

    /* Save to file */
    file_path_len = strlen(config_file) + 4 + 1 ;
    file_path = mosquitto_malloc(file_path_len);
    if(file_path == NULL){
        mosquitto_free(json_str);
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error saving Dynamic security plugin config: Out of memory.\n");
        return;
    }
    snprintf(file_path, file_path_len, "%s.new", config_file);

    fptr = fopen(file_path, "wt");
    if(fptr == NULL){
        mosquitto_free(json_str);
        mosquitto_free(file_path);
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error saving Dynamic security plugin config: File is not writable - check permissions.\n");
        return;
    }
    fwrite(json_str, 1, json_str_len, fptr);
    mosquitto_free(json_str);
    fclose(fptr);

    /* Everything is ok, so move new file over proper file */
    if(rename(file_path, config_file) < 0){
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error updating dynsec config file: %s", strerror(errno));
    }
    mosquitto_free(file_path);

}

static void dynsec__config_save_yaml(void)
{
    yaml_emitter_t emitter;
    yaml_event_t event;

    /* Save to file */
    size_t tmp_fn_len = strlen(config_file) + 4 + 1 ;
    char *tmp_fn = mosquitto_malloc(tmp_fn_len);

    if(tmp_fn == NULL){
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error saving Dynamic security plugin config: Out of memory.\n");
        return;
    }
    snprintf(tmp_fn, tmp_fn_len, "%s.new", config_file);

    FILE *fptr = fopen(tmp_fn, "wt");
    if(fptr == NULL){
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error saving Dynamic security plugin config: File '%s' is not writable - check permissions.\n", tmp_fn);
        return;
    }

    yaml_emitter_initialize(&emitter);
    yaml_emitter_set_output_file(&emitter, fptr);


    yaml_stream_start_event_initialize(&event, YAML_UTF8_ENCODING);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;


    yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 1);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_mapping_start_event_initialize(&event, NULL, (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    if(!dynsec__general_config_save_yaml(&emitter, &event)) goto error;
    if(!dynsec_clients__config_save_yaml(&emitter, &event)) goto error;
    if(!dynsec_groups__config_save_yaml(&emitter, &event)) goto error;
    printf("%s:%d\n", __FILE__, __LINE__);
    if(!dynsec_roles__config_save_yaml(&emitter, &event)) goto error;
    printf("%s:%d\n", __FILE__, __LINE__);

    yaml_mapping_end_event_initialize(&event);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_document_end_event_initialize(&event, 1);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_stream_end_event_initialize(&event);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

/* Destroy the Emitter object. */
    yaml_emitter_delete(&emitter);

    fclose(fptr);

    /* Everything is ok, so move new file over proper file */
    if(rename(tmp_fn, config_file) < 0){
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error updating dynsec config file: %s", strerror(errno));
    }

    mosquitto_free(tmp_fn);

    return;

error:
    printf("%s:%d\n", __FILE__, __LINE__);
    fprintf(stderr, "Failed to emit event %d: %s\n", event.type, emitter.problem);
    yaml_emitter_delete(&emitter);
    fclose(fptr);
    mosquitto_free(tmp_fn);
}



void dynsec__config_save(void)
{
    if (str_ends_with(config_file, ".yaml") || str_ends_with(config_file, ".yml")) {
        printf("YAML\n");
        dynsec__config_save_yaml();
    } else {
        printf("JSON %s\n", config_file);
        dynsec__config_save_json();
    }
}


int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *options, int option_count)
{
	int i;
	int rc;

	UNUSED(user_data);

	for(i=0; i<option_count; i++){
		if(!strcasecmp(options[i].key, "config_file")){
			config_file = mosquitto_strdup(options[i].value);
			if(config_file == NULL){
				return MOSQ_ERR_NOMEM;
			}
			break;
		}
	}
	if(config_file == NULL){
		mosquitto_log_printf(MOSQ_LOG_WARNING, "Warning: Dynamic security plugin has no plugin_opt_config_file defined. The plugin will not be activated.");
		return MOSQ_ERR_SUCCESS;
	}

	plg_id = identifier;

	dynsec__config_load();

	rc = mosquitto_callback_register(plg_id, MOSQ_EVT_CONTROL, dynsec_control_callback, "$CONTROL/dynamic-security/v1", NULL);
	if(rc == MOSQ_ERR_ALREADY_EXISTS){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Dynamic security plugin can currently only be loaded once.");
		mosquitto_log_printf(MOSQ_LOG_ERR, "Note that this was previously incorrectly allowed but could cause problems with duplicate entries in the config.");
		goto error;
	}else if(rc == MOSQ_ERR_NOMEM){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Out of memory.");
		goto error;
	}else if(rc != MOSQ_ERR_SUCCESS){
		goto error;
	}

	rc = mosquitto_callback_register(plg_id, MOSQ_EVT_BASIC_AUTH, dynsec_auth__basic_auth_callback, NULL, NULL);
	if(rc == MOSQ_ERR_ALREADY_EXISTS){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Dynamic security plugin can only be loaded once.");
		goto error;
	}else if(rc == MOSQ_ERR_NOMEM){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Out of memory.");
		goto error;
	}else if(rc != MOSQ_ERR_SUCCESS){
		goto error;
	}

	rc = mosquitto_callback_register(plg_id, MOSQ_EVT_ACL_CHECK, dynsec__acl_check_callback, NULL, NULL);
	if(rc == MOSQ_ERR_ALREADY_EXISTS){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Dynamic security plugin can only be loaded once.");
		goto error;
	}else if(rc == MOSQ_ERR_NOMEM){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Out of memory.");
		goto error;
	}else if(rc != MOSQ_ERR_SUCCESS){
		goto error;
	}

	return MOSQ_ERR_SUCCESS;
error:
	mosquitto_free(config_file);
	config_file = NULL;
	return rc;
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *options, int option_count)
{
	UNUSED(user_data);
	UNUSED(options);
	UNUSED(option_count);

	if(plg_id){
		mosquitto_callback_unregister(plg_id, MOSQ_EVT_CONTROL, dynsec_control_callback, "$CONTROL/dynamic-security/v1");
		mosquitto_callback_unregister(plg_id, MOSQ_EVT_BASIC_AUTH, dynsec_auth__basic_auth_callback, NULL);
		mosquitto_callback_unregister(plg_id, MOSQ_EVT_ACL_CHECK, dynsec__acl_check_callback, NULL);
	}
	dynsec_groups__cleanup();
	dynsec_clients__cleanup();
	dynsec_roles__cleanup();

	mosquitto_free(config_file);
	config_file = NULL;
	return MOSQ_ERR_SUCCESS;
}

/* ################################################################
 * #
 * # $CONTROL/dynamic-security/v1 handler
 * #
 * ################################################################ */

int dynsec__handle_control(cJSON *j_responses, struct mosquitto *context, cJSON *commands)
{
	int rc = MOSQ_ERR_SUCCESS;
	cJSON *aiter;
	char *command;
	char *correlation_data = NULL;

	cJSON_ArrayForEach(aiter, commands){
		if(cJSON_IsObject(aiter)){
			if(json_get_string(aiter, "command", &command, false) == MOSQ_ERR_SUCCESS){
				if(json_get_string(aiter, "correlationData", &correlation_data, true) != MOSQ_ERR_SUCCESS){
					dynsec__command_reply(j_responses, context, command, "Invalid correlationData data type.", NULL);
					return MOSQ_ERR_INVAL;
				}

				/* Plugin */
				if(!strcasecmp(command, "setDefaultACLAccess")){
					rc = dynsec__process_set_default_acl_access(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "getDefaultACLAccess")){
					rc = dynsec__process_get_default_acl_access(j_responses, context, aiter, correlation_data);

				/* Clients */
				}else if(!strcasecmp(command, "createClient")){
					rc = dynsec_clients__process_create(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "deleteClient")){
					rc = dynsec_clients__process_delete(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "getClient")){
					rc = dynsec_clients__process_get(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "listClients")){
					rc = dynsec_clients__process_list(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "modifyClient")){
					rc = dynsec_clients__process_modify(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "setClientPassword")){
					rc = dynsec_clients__process_set_password(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "setClientId")){
					rc = dynsec_clients__process_set_id(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "addClientRole")){
					rc = dynsec_clients__process_add_role(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "removeClientRole")){
					rc = dynsec_clients__process_remove_role(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "enableClient")){
					rc = dynsec_clients__process_enable(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "disableClient")){
					rc = dynsec_clients__process_disable(j_responses, context, aiter, correlation_data);

				/* Groups */
				}else if(!strcasecmp(command, "addGroupClient")){
					rc = dynsec_groups__process_add_client(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "createGroup")){
					rc = dynsec_groups__process_create(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "deleteGroup")){
					rc = dynsec_groups__process_delete(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "getGroup")){
					rc = dynsec_groups__process_get(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "listGroups")){
					rc = dynsec_groups__process_list(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "modifyGroup")){
					rc = dynsec_groups__process_modify(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "removeGroupClient")){
					rc = dynsec_groups__process_remove_client(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "addGroupRole")){
					rc = dynsec_groups__process_add_role(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "removeGroupRole")){
					rc = dynsec_groups__process_remove_role(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "setAnonymousGroup")){
					rc = dynsec_groups__process_set_anonymous_group(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "getAnonymousGroup")){
					rc = dynsec_groups__process_get_anonymous_group(j_responses, context, aiter, correlation_data);

				/* Roles */
				}else if(!strcasecmp(command, "createRole")){
					rc = dynsec_roles__process_create(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "getRole")){
					rc = dynsec_roles__process_get(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "listRoles")){
					rc = dynsec_roles__process_list(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "modifyRole")){
					rc = dynsec_roles__process_modify(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "deleteRole")){
					rc = dynsec_roles__process_delete(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "addRoleACL")){
					rc = dynsec_roles__process_add_acl(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "removeRoleACL")){
					rc = dynsec_roles__process_remove_acl(j_responses, context, aiter, correlation_data);

				/* Unknown */
				}else{
					dynsec__command_reply(j_responses, context, command, "Unknown command", correlation_data);
					rc = MOSQ_ERR_INVAL;
				}
			}else{
				dynsec__command_reply(j_responses, context, "Unknown command", "Missing command", correlation_data);
				rc = MOSQ_ERR_INVAL;
			}
		}else{
			dynsec__command_reply(j_responses, context, "Unknown command", "Command not an object", correlation_data);
			rc = MOSQ_ERR_INVAL;
		}
	}

	return rc;
}
