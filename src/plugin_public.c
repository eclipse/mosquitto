/*
Copyright (c) 2016-2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
SPDX-License-Identifier: EPL-2.0 OR EDL-1.0

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include "mosquitto_broker_internal.h"
#include "mosquitto_internal.h"
#include "mosquitto_broker.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "send_mosq.h"
#include "util_mosq.h"
#include "utlist.h"

#ifdef WITH_TLS
#  include <openssl/ssl.h>
#endif

const char *mosquitto_client_address(const struct mosquitto *client)
{
	if(client){
		return client->address;
	}else{
		return NULL;
	}
}


bool mosquitto_client_clean_session(const struct mosquitto *client)
{
	if(client){
		return client->clean_start;
	}else{
		return true;
	}
}


const char *mosquitto_client_id(const struct mosquitto *client)
{
	if(client){
		return client->id;
	}else{
		return NULL;
	}
}


int mosquitto_client_keepalive(const struct mosquitto *client)
{
	if(client){
		return client->keepalive;
	}else{
		return -1;
	}
}


void *mosquitto_client_certificate(const struct mosquitto *client)
{
#ifdef WITH_TLS
	if(client && client->ssl){
		return SSL_get_peer_certificate(client->ssl);
	}else{
		return NULL;
	}
#else
	return NULL;
#endif
}


int mosquitto_client_protocol(const struct mosquitto *client)
{
#ifdef WITH_WEBSOCKETS
	if(client && client->wsi){
		return mp_websockets;
	}else
#endif
	{
		return mp_mqtt;
	}
}


int mosquitto_client_protocol_version(const struct mosquitto *client)
{
	if(client){
		switch(client->protocol){
			case mosq_p_mqtt31:
				return 3;
			case mosq_p_mqtt311:
				return 4;
			case mosq_p_mqtt5:
				return 5;
			default:
				return 0;
		}
	}else{
		return 0;
	}
}


int mosquitto_client_sub_count(const struct mosquitto *client)
{
	if(client){
		return client->sub_count;
	}else{
		return 0;
	}
}


const char *mosquitto_client_username(const struct mosquitto *client)
{
	if(client){
#ifdef WITH_BRIDGE
		if(client->bridge){
			return client->bridge->local_username;
		}else
#endif
		{
			return client->username;
		}
	}else{
		return NULL;
	}
}


int mosquitto_broker_publish(
		const char *clientid,
		const char *topic,
		int payloadlen,
		void *payload,
		int qos,
		bool retain,
		mosquitto_property *properties)
{
	struct mosquitto_message_v5 *msg;

	if(topic == NULL
			|| payloadlen < 0
			|| (payloadlen > 0 && payload == NULL)
			|| qos < 0 || qos > 2){

		return MOSQ_ERR_INVAL;
	}

	msg = mosquitto__malloc(sizeof(struct mosquitto_message_v5));
	if(msg == NULL) return MOSQ_ERR_NOMEM;
	
	msg->next = NULL;
	msg->prev = NULL;
	if(clientid){
		msg->clientid = mosquitto__strdup(clientid);
		if(msg->clientid == NULL){
			mosquitto__free(msg);
			return MOSQ_ERR_NOMEM;
		}
	}else{
		msg->clientid = NULL;
	}
	msg->topic = mosquitto__strdup(topic);
	if(msg->topic == NULL){
		mosquitto__free(msg->clientid);
		mosquitto__free(msg);
		return MOSQ_ERR_NOMEM;
	}
	msg->payloadlen = payloadlen;
	msg->payload = payload;
	msg->qos = qos;
	msg->retain = retain;
	msg->properties = properties;

	DL_APPEND(db.plugin_msgs, msg);

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_broker_publish_copy(
		const char *clientid,
		const char *topic,
		int payloadlen,
		const void *payload,
		int qos,
		bool retain,
		mosquitto_property *properties)
{
	void *payload_out;

	if(topic == NULL
			|| payloadlen < 0
			|| (payloadlen > 0 && payload == NULL)
			|| qos < 0 || qos > 2){

		return MOSQ_ERR_INVAL;
	}

	payload_out = calloc(1, (size_t)(payloadlen+1));
	if(payload_out == NULL){
		return MOSQ_ERR_NOMEM;
	}
	memcpy(payload_out, payload, (size_t)payloadlen);

	return mosquitto_broker_publish(
			clientid,
			topic,
			payloadlen,
			payload_out,
			qos,
			retain,
			properties);
}


int mosquitto_set_username(struct mosquitto *client, const char *username)
{
	char *u_dup;
	char *old;
	int rc;

	if(!client) return MOSQ_ERR_INVAL;

	if(username){
		u_dup = mosquitto__strdup(username);
		if(!u_dup) return MOSQ_ERR_NOMEM;
	}else{
		u_dup = NULL;
	}

	old = client->username;
	client->username = u_dup;

	rc = acl__find_acls(client);
	if(rc){
		client->username = old;
		mosquitto__free(u_dup);
		return rc;
	}else{
		mosquitto__free(old);
		return MOSQ_ERR_SUCCESS;
	}
}


static void disconnect_client(struct mosquitto *context, bool with_will)
{
	if(context->protocol == mosq_p_mqtt5){
		send__disconnect(context, MQTT_RC_ADMINISTRATIVE_ACTION, NULL);
	}
	if(with_will == false){
		mosquitto__set_state(context, mosq_cs_disconnecting);
	}
	do_disconnect(context, MOSQ_ERR_ADMINISTRATIVE_ACTION);
}

int mosquitto_kick_client_by_clientid(const char *clientid, bool with_will)
{
	struct mosquitto *ctxt, *ctxt_tmp;

	if(clientid == NULL){
		HASH_ITER(hh_sock, db.contexts_by_sock, ctxt, ctxt_tmp){
			disconnect_client(ctxt, with_will);
		}
		return MOSQ_ERR_SUCCESS;
	}else{
		HASH_FIND(hh_id, db.contexts_by_id, clientid, strlen(clientid), ctxt);
		if(ctxt){
			disconnect_client(ctxt, with_will);
			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_NOT_FOUND;
		}
	}
}

int mosquitto_kick_client_by_username(const char *username, bool with_will)
{
	struct mosquitto *ctxt, *ctxt_tmp;

	if(username == NULL){
		HASH_ITER(hh_sock, db.contexts_by_sock, ctxt, ctxt_tmp){
			if(ctxt->username == NULL){
				disconnect_client(ctxt, with_will);
			}
		}
	}else{
		HASH_ITER(hh_sock, db.contexts_by_sock, ctxt, ctxt_tmp){
			if(ctxt->username != NULL && !strcmp(ctxt->username, username)){
				disconnect_client(ctxt, with_will);
			}
		}
	}
	return MOSQ_ERR_SUCCESS;
}
