/*
Copyright (c) 2010-2021 Roger Light <roger@atchoo.org>

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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <cjson/cJSON.h>

#include "db_dump.h"
#include "json_help.h"
#include <mosquitto_broker_internal.h>
#include <persist.h>

#define mosquitto_malloc(A) malloc((A))
#define mosquitto_free(A) free((A))
#define _mosquitto_malloc(A) malloc((A))
#define _mosquitto_free(A) free((A))
#include <uthash.h>

#include "db_dump.h"

cJSON *j_tree = NULL;
cJSON *j_base_msgs = NULL;
cJSON *j_clients = NULL;
cJSON *j_client_msgs = NULL;
cJSON *j_retained_msgs = NULL;
cJSON *j_subscriptions = NULL;


void json_init(void)
{
	j_tree = cJSON_CreateObject();
	if(!j_tree){
		fprintf(stderr, "Error: Out of memory.\n");
		exit(1);
	}

	if((j_base_msgs = cJSON_AddArrayToObject(j_tree, "base-messages")) == NULL
			|| (j_clients = cJSON_AddArrayToObject(j_tree, "clients")) == NULL
			|| (j_client_msgs = cJSON_AddArrayToObject(j_tree, "client-messages")) == NULL
			|| (j_retained_msgs = cJSON_AddArrayToObject(j_tree, "retained-messages")) == NULL
			|| (j_subscriptions = cJSON_AddArrayToObject(j_tree, "subscriptions")) == NULL
			){

		fprintf(stderr, "Error: Out of memory.\n");
		exit(1);
	}
}


void json_print(void)
{
	char *jstr = cJSON_Print(j_tree);
	printf("%s\n", jstr);
	free(jstr);
}


void json_cleanup(void)
{
	cJSON_Delete(j_tree);
}


void json_add_base_msg(struct P_base_msg *chunk)
{
	cJSON *j_base_msg = NULL;

	j_base_msg = cJSON_CreateObject();
	cJSON_AddItemToArray(j_base_msgs, j_base_msg);

	cJSON_AddUIntToObject(j_base_msg, "storeid", chunk->F.store_id);
	cJSON_AddIntToObject(j_base_msg, "expiry-time", chunk->F.expiry_time);
	cJSON_AddNumberToObject(j_base_msg, "source-mid", chunk->F.source_mid);
	cJSON_AddNumberToObject(j_base_msg, "source-port", chunk->F.source_port);
	cJSON_AddNumberToObject(j_base_msg, "qos", chunk->F.qos);
	cJSON_AddNumberToObject(j_base_msg, "retain", chunk->F.retain);
	cJSON_AddStringToObject(j_base_msg, "topic", chunk->topic);
	if(chunk->source.id){
		cJSON_AddStringToObject(j_base_msg, "clientid", chunk->source.id);
	}
	if(chunk->source.username){
		cJSON_AddStringToObject(j_base_msg, "username", chunk->source.username);
	}
	if(chunk->F.payloadlen > 0){
#ifdef WITH_TLS
		char *payload;
		if(mosquitto_base64_encode(chunk->payload, chunk->F.payloadlen, &payload) == MOSQ_ERR_SUCCESS){
			cJSON_AddStringToObject(j_base_msg, "payload", payload);
			mosquitto_free(payload);
		}
#else
		fprintf(stderr, "Warning: payload not output due to missing base64 support.\n");
#endif
	}
	if(chunk->properties){
		cJSON *j_props = mosquitto_properties_to_json(chunk->properties);
		if(j_props){
			cJSON_AddItemToObject(j_base_msg, "properties", j_props);
		}
	}
}


void json_add_client(struct P_client *chunk)
{
	cJSON *j_client;

	j_client = cJSON_CreateObject();
	cJSON_AddItemToArray(j_clients, j_client);

	cJSON_AddStringToObject(j_client, "clientid", chunk->clientid);
	if(chunk->username){
		cJSON_AddStringToObject(j_client, "username", chunk->username);
	}
	cJSON_AddIntToObject(j_client, "session-expiry-time", chunk->F.session_expiry_time);
	cJSON_AddNumberToObject(j_client, "session-expiry-interval", chunk->F.session_expiry_interval);
	cJSON_AddNumberToObject(j_client, "last-mid", chunk->F.last_mid);
	cJSON_AddNumberToObject(j_client, "listener-port", chunk->F.listener_port);

}


void json_add_client_msg(struct P_client_msg *chunk)
{
	cJSON *j_client_msg;

	j_client_msg = cJSON_CreateObject();
	cJSON_AddItemToArray(j_client_msgs, j_client_msg);

	cJSON_AddStringToObject(j_client_msg, "clientid", chunk->clientid);
	cJSON_AddNumberToObject(j_client_msg, "storeid", chunk->subscription_identifier);
	cJSON_AddNumberToObject(j_client_msg, "mid", chunk->F.mid);
	cJSON_AddNumberToObject(j_client_msg, "qos", chunk->F.qos);
	cJSON_AddNumberToObject(j_client_msg, "state", chunk->F.state);
	cJSON_AddNumberToObject(j_client_msg, "retain-dup", chunk->F.retain_dup);
	cJSON_AddNumberToObject(j_client_msg, "direction", chunk->F.direction);
	cJSON_AddNumberToObject(j_client_msg, "subscription-identifier", chunk->subscription_identifier);
}


void json_add_subscription(struct P_sub *chunk)
{
	cJSON *j_subscription;

	j_subscription = cJSON_CreateObject();
	cJSON_AddItemToArray(j_subscriptions, j_subscription);

	cJSON_AddStringToObject(j_subscription, "clientid", chunk->clientid);
	cJSON_AddStringToObject(j_subscription, "topic", chunk->topic);
	cJSON_AddNumberToObject(j_subscription, "qos", chunk->F.qos);
	cJSON_AddNumberToObject(j_subscription, "options", chunk->F.options);
	cJSON_AddNumberToObject(j_subscription, "identifier", chunk->F.identifier);
}


void json_add_retained_msg(struct P_retain *chunk)
{
	cJSON *j_retained_msg;

	j_retained_msg = cJSON_CreateObject();
	cJSON_AddItemToArray(j_retained_msgs, j_retained_msg);
	cJSON_AddUIntToObject(j_retained_msg, "storeid", chunk->F.store_id);
}
