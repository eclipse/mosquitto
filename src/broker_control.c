/*
Copyright (c) 2021 Roger Light <roger@atchoo.org>

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

#ifdef WITH_CJSON

#include <cjson/cJSON.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <utlist.h>

#include "json_help.h"
#include "mosquitto.h"
#include "mosquitto_broker_internal.h"
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"

static mosquitto_plugin_id_t plg_id;

static int broker__handle_control(cJSON *j_responses, struct mosquitto *context, cJSON *commands);

static void broker__command_reply(cJSON *j_responses, struct mosquitto *context, const char *command, const char *error, const char *correlation_data)
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
		SAFE_FREE(payload);
		return;
	}
	mosquitto_broker_publish(NULL, "$CONTROL/broker/v1/response",
			(int)payload_len, payload, 0, 0, NULL);
}


static int add_plugin_info(cJSON *j_plugins, mosquitto_plugin_id_t *pid)
{
	cJSON *j_plugin, *j_eps, *j_ep;
	struct control_endpoint *ep;

	if(pid->plugin_name == NULL){
		return MOSQ_ERR_SUCCESS;
	}

	j_plugin = cJSON_CreateObject();
	if(j_plugin == NULL){
		return MOSQ_ERR_NOMEM;
	}

	if(cJSON_AddStringToObject(j_plugin, "name", pid->plugin_name) == NULL
			|| (pid->plugin_version && cJSON_AddStringToObject(j_plugin, "version", pid->plugin_version) == NULL)
			|| (pid->listener && cJSON_AddNumberToObject(j_plugin, "port", pid->listener->port) == NULL)
			|| (j_eps = cJSON_AddArrayToObject(j_plugin, "control-endpoints")) == NULL
			){

		cJSON_Delete(j_plugin);
		return MOSQ_ERR_NOMEM;
	}

	DL_FOREACH(pid->control_endpoints, ep){
		j_ep = cJSON_CreateString(ep->topic);
		if(j_ep == NULL){
			cJSON_Delete(j_plugin);
		}
		cJSON_AddItemToArray(j_eps, j_ep);
	}

	cJSON_AddItemToArray(j_plugins, j_plugin);
	return MOSQ_ERR_SUCCESS;
}


static int broker__process_list_plugins(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	cJSON *tree, *jtmp, *j_data, *j_plugins;
	const char *admin_clientid, *admin_username;
	int i;

	UNUSED(command);

	tree = cJSON_CreateObject();
	if(tree == NULL){
		broker__command_reply(j_responses, context, "listPlugins", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "Broker: %s/%s | listPlugins",
			admin_clientid, admin_username);

	if(cJSON_AddStringToObject(tree, "command", "listPlugins") == NULL
		|| ((j_data = cJSON_AddObjectToObject(tree, "data")) == NULL)

			){
		goto internal_error;
	}

	j_plugins = cJSON_AddArrayToObject(j_data, "plugins");
	if(j_plugins == NULL){
		goto internal_error;
	}

	for(i=0; i<db.config->security_options.plugin_config_count; i++){
		if(add_plugin_info(j_plugins, db.config->security_options.plugin_configs[i]->plugin.identifier)){
			goto internal_error;
		}
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
	broker__command_reply(j_responses, context, "listPlugins", "Internal error", correlation_data);
	return MOSQ_ERR_NOMEM;
}


static int add_listener(cJSON *j_listeners, struct mosquitto__listener *listener)
{
	cJSON *j_listener;
	const char *protocol = NULL;

	j_listener = cJSON_CreateObject();
	if(j_listener == NULL){
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToArray(j_listeners, j_listener);

	if(listener->protocol == mp_mqtt){
		protocol = "mqtt";
	}else if(listener->protocol == mp_websockets){
		protocol = "mqtt+websockets";
	}

	if(cJSON_AddNumberToObject(j_listener, "port", listener->port) == NULL
			|| (protocol && cJSON_AddStringToObject(j_listener, "protocol", protocol) == NULL)
			|| (listener->host && cJSON_AddStringToObject(j_listener, "bind-address", listener->host) == NULL)
#ifdef WITH_UNIX_SOCKETS
			|| (listener->unix_socket_path && cJSON_AddStringToObject(j_listener, "socket-path", listener->unix_socket_path) == NULL)
#endif
			){

		return MOSQ_ERR_NOMEM;
	}

#ifdef WITH_TLS
	if(cJSON_AddBoolToObject(j_listener, "tls", listener->ssl_ctx != NULL) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}
#endif

	return MOSQ_ERR_SUCCESS;
}


static int broker__process_list_listeners(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	cJSON *tree, *jtmp, *j_data, *j_listeners;
	const char *admin_clientid, *admin_username;
	int i;

	UNUSED(command);

	tree = cJSON_CreateObject();
	if(tree == NULL){
		broker__command_reply(j_responses, context, "listListeners", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "Broker: %s/%s | listListeners",
			admin_clientid, admin_username);

	if(cJSON_AddStringToObject(tree, "command", "listListeners") == NULL
		|| ((j_data = cJSON_AddObjectToObject(tree, "data")) == NULL)

			){
		goto internal_error;
	}

	j_listeners = cJSON_AddArrayToObject(j_data, "listeners");
	if(j_listeners == NULL){
		goto internal_error;
	}

	for(i=0; i<db.config->listener_count; i++){
		if(add_listener(j_listeners, &db.config->listeners[i])){
			goto internal_error;
		}
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
	broker__command_reply(j_responses, context, "listListeners", "Internal error", correlation_data);
	return MOSQ_ERR_NOMEM;
}


static int broker_control_callback(int event, void *event_data, void *userdata)
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
		broker__command_reply(j_responses, ed->client, "Unknown command", "Payload not valid JSON", NULL);
		send_response(j_response_tree);
		return MOSQ_ERR_SUCCESS;
	}
	commands = cJSON_GetObjectItem(tree, "commands");
	if(commands == NULL || !cJSON_IsArray(commands)){
		cJSON_Delete(tree);
		broker__command_reply(j_responses, ed->client, "Unknown command", "Invalid/missing commands", NULL);
		send_response(j_response_tree);
		return MOSQ_ERR_SUCCESS;
	}

	/* Handle commands */
	broker__handle_control(j_responses, ed->client, commands);
	cJSON_Delete(tree);

	send_response(j_response_tree);

	return MOSQ_ERR_SUCCESS;
}


void broker_control__init(void)
{
	memset(&plg_id, 0, sizeof(plg_id));

	if(db.config->enable_control_api){
		mosquitto_callback_register(&plg_id, MOSQ_EVT_CONTROL, broker_control_callback, "$CONTROL/broker/v1", NULL);
	}
}


void broker_control__cleanup(void)
{
	mosquitto_callback_unregister(&plg_id, MOSQ_EVT_CONTROL, broker_control_callback, "$CONTROL/broker/v1");
}


void broker_control__reload(void)
{
	broker_control__cleanup();
	broker_control__init();
}


/* ################################################################
 * #
 * # $CONTROL/broker/v1 handler
 * #
 * ################################################################ */

static int broker__handle_control(cJSON *j_responses, struct mosquitto *context, cJSON *commands)
{
	int rc = MOSQ_ERR_SUCCESS;
	cJSON *aiter;
	char *command;
	char *correlation_data = NULL;

	cJSON_ArrayForEach(aiter, commands){
		if(cJSON_IsObject(aiter)){
			if(json_get_string(aiter, "command", &command, false) == MOSQ_ERR_SUCCESS){
				if(json_get_string(aiter, "correlationData", &correlation_data, true) != MOSQ_ERR_SUCCESS){
					broker__command_reply(j_responses, context, command, "Invalid correlationData data type.", NULL);
					return MOSQ_ERR_INVAL;
				}

				if(!strcasecmp(command, "listPlugins")){
					rc = broker__process_list_plugins(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "listListeners")){
					rc = broker__process_list_listeners(j_responses, context, aiter, correlation_data);

				/* Unknown */
				}else{
					broker__command_reply(j_responses, context, command, "Unknown command", correlation_data);
					rc = MOSQ_ERR_INVAL;
				}
			}else{
				broker__command_reply(j_responses, context, "Unknown command", "Missing command", correlation_data);
				rc = MOSQ_ERR_INVAL;
			}
		}else{
			broker__command_reply(j_responses, context, "Unknown command", "Command not an object", correlation_data);
			rc = MOSQ_ERR_INVAL;
		}
	}

	return rc;
}
#endif
