/*
Copyright (c) 2021 Benjamin Hansmann <benjamin.hansmann@riedel.net>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Benjamin Hansmann - initial implementation and documentation.
*/

#include "config.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json_help.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mqtt_protocol.h"

#include "dynamic_bridge.h"

static mosquitto_plugin_id_t *plg_id = NULL;

void dynbridge__command_reply(cJSON *j_responses, struct mosquitto *context, const char *command, const char *error, const char *correlation_data)
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
	mosquitto_broker_publish(NULL, "$CONTROL/dynamic-bridge/v1/response",
			(int)payload_len, payload, 0, 0, NULL);
}


static int dynbridge_control_callback(int event, void *event_data, void *userdata)
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
		dynbridge__command_reply(j_responses, ed->client, "Unknown command", "Payload not valid JSON", NULL);
		send_response(j_response_tree);
		return MOSQ_ERR_SUCCESS;
	}
	// TODO remove debug print
	printf("Request: %s\n", cJSON_Print(tree));

	commands = cJSON_GetObjectItem(tree, "commands");
	if(commands == NULL || !cJSON_IsArray(commands)){
		cJSON_Delete(tree);
		dynbridge__command_reply(j_responses, ed->client, "Unknown command", "Invalid/missing commands", NULL);
		send_response(j_response_tree);
		return MOSQ_ERR_SUCCESS;
	}

	/* Handle commands */
	dynbridge__handle_control(j_responses, ed->client, commands);
	cJSON_Delete(tree);

	send_response(j_response_tree);

	return MOSQ_ERR_SUCCESS;
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

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *options, int option_count)
{
	UNUSED(user_data);
	UNUSED(options);
	UNUSED(option_count);

	plg_id = identifier;

	mosquitto_callback_register(plg_id, MOSQ_EVT_CONTROL, dynbridge_control_callback, "$CONTROL/dynamic-bridge/v1", NULL);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *options, int option_count)
{
	UNUSED(user_data);
	UNUSED(options);
	UNUSED(option_count);

	if(plg_id){
		mosquitto_callback_unregister(plg_id, MOSQ_EVT_CONTROL, dynbridge_control_callback, "$CONTROL/dynamic-bridge/v1");
	}

	return MOSQ_ERR_SUCCESS;
}

/* ################################################################
 * #
 * # $CONTROL/dynamic-bridge/v1 handler
 * #
 * ################################################################ */

int dynbridge__handle_control(cJSON *j_responses, struct mosquitto *context, cJSON *commands)
{
	int rc = MOSQ_ERR_SUCCESS;
	cJSON *aiter;
	char *command;
	char *correlation_data = NULL;

	cJSON_ArrayForEach(aiter, commands){
		if(cJSON_IsObject(aiter)){
			if(json_get_string(aiter, "command", &command, false) == MOSQ_ERR_SUCCESS){
				if(json_get_string(aiter, "correlationData", &correlation_data, true) != MOSQ_ERR_SUCCESS){
					dynbridge__command_reply(j_responses, context, command, "Invalid correlationData data type.", NULL);
					return MOSQ_ERR_INVAL;
				}

				/* Plugin */
				if(!strcasecmp(command, "create")){
					rc = dynbridge__process_create(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "list")){
					rc = dynbridge__process_list(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "delete")){
					rc = dynbridge__process_delete(j_responses, context, aiter, correlation_data);
				/* Unknown */
				}else{
					dynbridge__command_reply(j_responses, context, command, "Unknown command", correlation_data);
					rc = MOSQ_ERR_INVAL;
				}
			}else{
				dynbridge__command_reply(j_responses, context, "Unknown command", "Missing command", correlation_data);
				rc = MOSQ_ERR_INVAL;
			}
		}else{
			dynbridge__command_reply(j_responses, context, "Unknown command", "Command not an object", correlation_data);
			rc = MOSQ_ERR_INVAL;
		}
	}

	return rc;
}
