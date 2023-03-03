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
#include "control_common.h"

static mosquitto_plugin_id_t plg_id;

static int broker__handle_control(struct control_cmd *cmd, struct mosquitto *context, const char *command, void *userdata);

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
			return MOSQ_ERR_NOMEM;
		}
		cJSON_AddItemToArray(j_eps, j_ep);
	}

	cJSON_AddItemToArray(j_plugins, j_plugin);
	return MOSQ_ERR_SUCCESS;
}


static int broker__process_list_plugins(struct control_cmd *cmd, struct mosquitto *context)
{
	cJSON *tree, *j_data, *j_plugins;
	const char *admin_clientid, *admin_username;
	int i;

	tree = cJSON_CreateObject();
	if(tree == NULL){
		control__command_reply(cmd, "Internal error");
		return MOSQ_ERR_NOMEM;
	}

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "Broker: %s/%s | listPlugins",
			admin_clientid, admin_username);

	if(cJSON_AddStringToObject(tree, "command", "listPlugins") == NULL
			|| ((j_data = cJSON_AddObjectToObject(tree, "data")) == NULL)
			|| (cmd->correlation_data && cJSON_AddStringToObject(tree, "correlationData", cmd->correlation_data) == NULL)
			){

		goto internal_error;
	}

	j_plugins = cJSON_AddArrayToObject(j_data, "plugins");
	if(j_plugins == NULL){
		goto internal_error;
	}

	for(i=0; i<db.plugin_count; i++){
		if(add_plugin_info(j_plugins, db.plugins[i])){
			goto internal_error;
		}
	}

	cJSON_AddItemToArray(cmd->j_responses, tree);

	return MOSQ_ERR_SUCCESS;

internal_error:
	cJSON_Delete(tree);
	control__command_reply(cmd, "Internal error");
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


static int broker__process_list_listeners(struct control_cmd *cmd, struct mosquitto *context)
{
	cJSON *tree, *j_data, *j_listeners;
	const char *admin_clientid, *admin_username;
	int i;

	tree = cJSON_CreateObject();
	if(tree == NULL){
		control__command_reply(cmd, "Internal error");
		return MOSQ_ERR_NOMEM;
	}

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "Broker: %s/%s | listListeners",
			admin_clientid, admin_username);

	if(cJSON_AddStringToObject(tree, "command", "listListeners") == NULL
			|| ((j_data = cJSON_AddObjectToObject(tree, "data")) == NULL)
			|| (cmd->correlation_data && cJSON_AddStringToObject(tree, "correlationData", cmd->correlation_data) == NULL)
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

	cJSON_AddItemToArray(cmd->j_responses, tree);

	return MOSQ_ERR_SUCCESS;

internal_error:
	cJSON_Delete(tree);
	control__command_reply(cmd, "Internal error");
	return MOSQ_ERR_NOMEM;
}


static int broker_control_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_control *ed = event_data;

	UNUSED(event);

	return control__generic_control_callback(ed, "$CONTROL/broker/v1/response", userdata, broker__handle_control);
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

static int broker__handle_control(struct control_cmd *cmd, struct mosquitto *context, const char *command, void *userdata)
{
	int rc = MOSQ_ERR_SUCCESS;

	UNUSED(userdata);

	if(!strcasecmp(command, "listPlugins")){
		rc = broker__process_list_plugins(cmd, context);
	}else if(!strcasecmp(command, "listListeners")){
		rc = broker__process_list_listeners(cmd, context);

	/* Unknown */
	}else{
		control__command_reply(cmd, "Unknown command");
		rc = MOSQ_ERR_INVAL;
	}
	return rc;
}
#endif
