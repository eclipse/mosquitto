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
#include <memory_mosq.h>

#include "json_help.h"
#include "mosquitto_broker_internal.h"

#include "dynamic_bridge.h"

static int from_json(cJSON *command, struct mosquitto__bridge *bridge)
{
	char *name_tmp, *address_tmp, *protocol_version_tmp;
	int port_tmp;
	bool cleansession;
	enum mosquitto__protocol protocol_version;
	int rc;

	if(json_get_string(command, "name", &name_tmp, false) != MOSQ_ERR_SUCCESS){
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(name_tmp, (int)strlen(name_tmp)) != MOSQ_ERR_SUCCESS){
		return MOSQ_ERR_INVAL;
	}
	if(json_get_string(command, "address", &address_tmp, false) != MOSQ_ERR_SUCCESS){
		return MOSQ_ERR_INVAL;
	}
	if(json_get_int(command, "port", &port_tmp, true, 1883) != MOSQ_ERR_SUCCESS){
		return MOSQ_ERR_INVAL;
	}
	if(port_tmp < 1 || port_tmp > UINT16_MAX){
		return MOSQ_ERR_INVAL;
	}
	if(json_get_string(command, "protocolVersion", &protocol_version_tmp, true) != MOSQ_ERR_SUCCESS){
		return MOSQ_ERR_INVAL;
	}
	if(!protocol_version_tmp || !strcmp(protocol_version_tmp, "mqttv311")){
		protocol_version = mosq_p_mqtt311;
	}else if(!strcmp(protocol_version_tmp, "mqttv31")){
		protocol_version = mosq_p_mqtt31;
	}else if(!strcmp(protocol_version_tmp, "mqttv50")){
		protocol_version = mosq_p_mqtt5;
	}else{
		return MOSQ_ERR_INVAL;
	}
	if(json_get_bool(command, "cleanSession", &cleansession, true, false) != MOSQ_ERR_SUCCESS){
		return MOSQ_ERR_INVAL;
	}

	rc = config__init_bridge(bridge, name_tmp);
	if(rc != MOSQ_ERR_SUCCESS) {
		return rc;
	}
	bridge->name = mosquitto__strdup(name_tmp);
	if(!bridge->name){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}
	if(bridge__add_topic(bridge, "#", bd_both, 0, "", "")){
		return MOSQ_ERR_INVAL;
	}
	bridge->addresses = mosquitto__realloc(bridge->addresses, sizeof(struct bridge_address)*(size_t)(bridge->address_count+1));
	if(!bridge->addresses){
		return MOSQ_ERR_NOMEM;
	}
	bridge->address_count++;
	bridge->addresses[bridge->address_count-1].address = mosquitto__strdup(address_tmp);
	bridge->addresses[bridge->address_count-1].port = (uint16_t)port_tmp;
	bridge->protocol_version = protocol_version;
	bridge->clean_start = cleansession;

	return rc;
}

static cJSON *to_json(const struct mosquitto__bridge *bridge)
{
	cJSON *j_bridge = NULL;

	j_bridge = cJSON_CreateObject();
	if(j_bridge == NULL){
		return NULL;
	}

	if(cJSON_AddStringToObject(j_bridge, "name", bridge->name) == NULL
			|| cJSON_AddStringToObject(j_bridge, "address", bridge->addresses->address) == NULL
			|| cJSON_AddIntToObject(j_bridge, "port", bridge->addresses->port) == NULL
			){
		cJSON_Delete(j_bridge);
		return NULL;
	}

	return j_bridge;
}

int dynbridge__process_create(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	struct mosquitto__bridge *bridge;
	int rc;
	const char *admin_clientid, *admin_username;

	bridge = mosquitto_calloc(1, sizeof(struct mosquitto__bridge));
	if(!bridge){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		dynbridge__command_reply(j_responses, context, "create", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}
	if(from_json(command, bridge) != MOSQ_ERR_SUCCESS){
		config__cleanup_bridge(bridge);
		mosquitto__free(bridge);
		dynbridge__command_reply(j_responses, context, "create", "Invalid bridge configuration", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	rc = config__check_dynamic_bridge(bridge);
	if(rc != MOSQ_ERR_SUCCESS){
		config__cleanup_bridge(bridge);
		mosquitto__free(bridge);
		if (rc == MOSQ_ERR_ALREADY_EXISTS){
			dynbridge__command_reply(j_responses, context, "create", "Bridge connection name or clientId already in use", correlation_data);
		}else{
			dynbridge__command_reply(j_responses, context, "create", "Invalid bridge configuration", correlation_data);
		}
		return MOSQ_ERR_INVAL;
	}

	config__add_dynamic_bridge(bridge);
	bridge__start_all();
	dynbridge__command_reply(j_responses, context, "create", NULL, correlation_data);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynbridge: %s/%s | create", admin_clientid, admin_username);

	return MOSQ_ERR_SUCCESS;
}

static void add_bridge_to_json(const struct mosquitto__bridge *bridge, cJSON *j_bridges)
{
	cJSON *j_bridge;
	j_bridge = to_json(bridge);
	if(j_bridge){
		cJSON_AddItemToArray(j_bridges, j_bridge);
	}else{
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
	}
}

int dynbridge__process_list(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	cJSON *tree, *j_bridges, *j_data;
	const char *admin_clientid, *admin_username;

	UNUSED(command);

	tree = cJSON_CreateObject();
	if(tree == NULL){
		dynbridge__command_reply(j_responses, context, "list", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	if(cJSON_AddStringToObject(tree, "command", "list") == NULL
			|| (j_data = cJSON_AddObjectToObject(tree, "data")) == NULL
			|| (j_bridges = cJSON_AddArrayToObject(j_data, "bridges")) == NULL
			|| (correlation_data && cJSON_AddStringToObject(tree, "correlationData", correlation_data) == NULL)
			){
		cJSON_Delete(tree);
		dynbridge__command_reply(j_responses, context, "list", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}
	config__visit_dynamic_bridges((FUNC_config__accept_bridge) add_bridge_to_json, j_bridges);
	cJSON_AddItemToArray(j_responses, tree);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynbridge: %s/%s | list", admin_clientid, admin_username);

	return MOSQ_ERR_SUCCESS;
}

int dynbridge__process_delete(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *name;
	int rc;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "name", &name, false) != MOSQ_ERR_SUCCESS){
		dynbridge__command_reply(j_responses, context, "delete", "Invalid/missing connection name", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	rc = config__invalidate_dynamic_bridge(name);
	bridge__start_all();
	if(rc){
		dynbridge__command_reply(j_responses, context, "delete", "Bridge not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}
	dynbridge__command_reply(j_responses, context, "delete", NULL, correlation_data);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynbridge: %s/%s | delete", admin_clientid, admin_username);

	return MOSQ_ERR_SUCCESS;
}
