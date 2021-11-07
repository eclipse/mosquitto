#ifdef WITH_BRIDGE
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

#include "mosquitto_ctrl.h"
#include "mosquitto.h"

void dynbridge__print_usage(void)
{
	printf("\nDynamic Bridge module\n");
	printf("=====================\n");
	printf("\nAvailable commands:\n-------------------\n");
	printf("Create dynamic bridge:    create <name> <address>\n");
	printf("  [-p port]\n");
	printf("  [-m protocol_version]   mqttv31|mqttv311|mqttv50 (default: mqttv311)\n");
	printf("  [-c]                    clean session (default: false)\n");
	printf("Get all dynamic bridges:  list\n");
	printf("Delete dynamic bridge:    delete <name>\n");
	printf("\n");
}

/* ################################################################
 * #
 * # Payload callback
 * #
 * ################################################################ */

static void dynbridge__payload_callback(struct mosq_ctrl *ctrl, long payloadlen, const void *payload)
{
	cJSON *tree, *j_responses, *j_response, *j_command, *j_error;

	UNUSED(ctrl);

#if CJSON_VERSION_FULL < 1007013
	UNUSED(payloadlen);
	tree = cJSON_Parse(payload);
#else
	tree = cJSON_ParseWithLength(payload, (size_t)payloadlen);
#endif
	if(tree == NULL){
		fprintf(stderr, "Error: Payload not JSON.\n");
		return;
	}

	j_responses = cJSON_GetObjectItem(tree, "responses");
	if(j_responses == NULL || !cJSON_IsArray(j_responses)){
		fprintf(stderr, "Error: Payload missing data.\n");
		cJSON_Delete(tree);
		return;
	}

	j_response = cJSON_GetArrayItem(j_responses, 0);
	if(j_response == NULL){
		fprintf(stderr, "Error: Payload missing data.\n");
		cJSON_Delete(tree);
		return;
	}

	j_command = cJSON_GetObjectItem(j_response, "command");
	if(j_command == NULL){
		fprintf(stderr, "Error: Payload missing data.\n");
		cJSON_Delete(tree);
		return;
	}

	j_error = cJSON_GetObjectItem(j_response, "error");
	if(j_error){
		fprintf(stderr, "%s: Error: %s\n", j_command->valuestring, j_error->valuestring);
	}else{
		if(!strcasecmp(j_command->valuestring, "list")){
			printf("Dynamic bridges: %s\n", cJSON_Print(j_responses));
		}
		fprintf(stderr, "%s: Success\n", j_command->valuestring);
	}
	cJSON_Delete(tree);
}

static int dynbridge__create(int argc, char *argv[], cJSON *j_command)
{
	char *name, *address;
	char *protocol_version = "mqttv311";
	int port = 1883;
	bool cleansession = false;
	int i;

	if(argc < 2){
		return MOSQ_ERR_INVAL;
	}
	name = argv[0];
	address = argv[1];

	for(i=1; i<argc; i++){
		if(!strcmp(argv[i], "-p")){
			if(i+1 == argc){
				fprintf(stderr, "Error: -p argument given, but no port provided.\n");
				return MOSQ_ERR_INVAL;
			}
			port = atoi(argv[i+1]);
			if(port < 1 || port > UINT16_MAX){
				fprintf(stderr, "Error: Invalid port provided.\n");
				return MOSQ_ERR_INVAL;
			}
			i++;
		}else if(!strcmp(argv[i], "-m")){
			if(i+1 == argc){
				fprintf(stderr, "Error: -m argument given, but no MQTT protocol version provided.\n");
				return MOSQ_ERR_INVAL;
			}
			protocol_version = argv[i+1];
			if(strcmp(protocol_version, "mqttv31")
					&& strcmp(protocol_version, "mqttv311")
					&& strcmp(protocol_version, "mqttv50")
					){
				fprintf(stderr, "Error: Invalid MQTT protocol version provided.\n");
				return MOSQ_ERR_INVAL;
			}
			i++;
		}else if(!strcmp(argv[i], "-c")){
			cleansession = true;
		}
	}

	if(cJSON_AddStringToObject(j_command, "command", "create") == NULL
			|| cJSON_AddStringToObject(j_command, "name", name) == NULL
			|| cJSON_AddStringToObject(j_command, "address", address) == NULL
			|| cJSON_AddIntToObject(j_command, "port", port) == NULL
			|| cJSON_AddStringToObject(j_command, "protocolVersion", protocol_version) == NULL
			|| cJSON_AddBoolToObject(j_command, "cleanSession", cleansession) == NULL
			){
		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

static int dynbridge__list(int argc, char *argv[], cJSON *j_command)
{
	UNUSED(argv);

	if(argc != 0){
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "list") == NULL){
		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

static int dynbridge__delete(int argc, char *argv[], cJSON *j_command)
{
	char *name;

	if(argc != 1){
		return MOSQ_ERR_INVAL;
	}
	name = argv[0];

	if(cJSON_AddStringToObject(j_command, "command", "delete") == NULL
			|| cJSON_AddStringToObject(j_command, "name", name) == NULL
			){
		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

/* ################################################################
 * #
 * # Main
 * #
 * ################################################################ */

int dynbridge__main(int argc, char *argv[], struct mosq_ctrl *ctrl)
{
	int rc = -1;
	cJSON *j_tree;
	cJSON *j_commands, *j_command;

	if(!strcasecmp(argv[0], "help")){
		dynbridge__print_usage();
		return -1;
	}

	/* The remaining commands need a network connection and JSON command. */

	ctrl->payload_callback = dynbridge__payload_callback;
	ctrl->request_topic = strdup("$CONTROL/dynamic-bridge/v1");
	ctrl->response_topic = strdup("$CONTROL/dynamic-bridge/v1/response");
	if(ctrl->request_topic == NULL || ctrl->response_topic == NULL){
		return MOSQ_ERR_NOMEM;
	}
	j_tree = cJSON_CreateObject();
	if(j_tree == NULL) return MOSQ_ERR_NOMEM;
	j_commands = cJSON_AddArrayToObject(j_tree, "commands");
	if(j_commands == NULL){
		cJSON_Delete(j_tree);
		j_tree = NULL;
		return MOSQ_ERR_NOMEM;
	}
	j_command = cJSON_CreateObject();
	if(j_command == NULL){
		cJSON_Delete(j_tree);
		j_tree = NULL;
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToArray(j_commands, j_command);

	if(!strcasecmp(argv[0], "create")){
		rc = dynbridge__create(argc - 1, &argv[1], j_command);
	} else if(!strcasecmp(argv[0], "list")){
		rc = dynbridge__list(argc-1, &argv[1], j_command);
	} else if(!strcasecmp(argv[0], "delete")){
		rc = dynbridge__delete(argc-1, &argv[1], j_command);
	}else{
		fprintf(stderr, "Command '%s' not recognised.\n", argv[0]);
		return MOSQ_ERR_UNKNOWN;
	}

	if(rc == MOSQ_ERR_SUCCESS){
		ctrl->payload = cJSON_PrintUnformatted(j_tree);
		cJSON_Delete(j_tree);
		if(ctrl->payload == NULL){
			fprintf(stderr, "Error: Out of memory.\n");
			return MOSQ_ERR_NOMEM;
		}
	}
	return rc;
}
#endif