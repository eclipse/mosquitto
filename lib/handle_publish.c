/*
Copyright (c) 2009-2016 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

Contributors:
   Roger Light - initial implementation and documentation.
   Tatsuzo Osawa - Add mqtt version 5.
*/

#include <assert.h>
#include <string.h>

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "packet_mosq.h"
#include "send_mosq.h"
#include "time_mosq.h"
#include "mqtt3_protocol.h"


int handle__publish(struct mosquitto *mosq)
{
	uint8_t header;
	struct mosquitto_message_all *message;
	int rc = 0;
	uint16_t mid;
	struct mosquitto_v5_property property;

	assert(mosq);

	message = mosquitto__calloc(1, sizeof(struct mosquitto_message_all));
	if(!message) return MOSQ_ERR_NOMEM;

	header = mosq->in_packet.command;

	message->dup = (header & 0x08)>>3;
	message->msg.qos = (header & 0x06)>>1;
	message->msg.retain = (header & 0x01);

	rc = packet__read_string(&mosq->in_packet, &message->msg.topic);
	if(rc){
		message__cleanup(&message);
		return rc;
	}
	if(!strlen(message->msg.topic)){
		message__cleanup(&message);
		return MOSQ_ERR_PROTOCOL;
	}

	if(message->msg.qos > 0){
		rc = packet__read_uint16(&mosq->in_packet, &mid);
		if(rc){
			message__cleanup(&message);
			return rc;
		}
		message->msg.mid = (int)mid;
	}

	// Read and parse publish v5 property. (So far, read only.)
	if(mosq->protocol == mosq_p_mqtt5){
		memset(&property, 0, sizeof(struct mosquitto_v5_property));
		rc = packet__read_property(mosq, &mosq->in_packet, &property, PUBLISH);
		if(rc != MQTT5_RC_SUCCESS){
			packet__property_content_free(&property);
			return rc;
		}
		packet__property_content_free(&property);
	}

	message->msg.payloadlen = mosq->in_packet.remaining_length - mosq->in_packet.pos;
	if(message->msg.payloadlen){
		message->msg.payload = mosquitto__calloc(message->msg.payloadlen+1, sizeof(uint8_t));
		if(!message->msg.payload){
			message__cleanup(&message);
			return MOSQ_ERR_NOMEM;
		}
		rc = packet__read_bytes(&mosq->in_packet, message->msg.payload, message->msg.payloadlen);
		if(rc){
			message__cleanup(&message);
			return rc;
		}
	}
	log__printf(mosq, MOSQ_LOG_DEBUG,
			"Client %s received PUBLISH (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))",
			mosq->id, message->dup, message->msg.qos, message->msg.retain,
			message->msg.mid, message->msg.topic,
			(long)message->msg.payloadlen);

	message->timestamp = mosquitto_time();
	switch(message->msg.qos){
		case 0:
			pthread_mutex_lock(&mosq->callback_mutex);
			if(mosq->on_message){
				mosq->in_callback = true;
				mosq->on_message(mosq, mosq->userdata, &message->msg);
				mosq->in_callback = false;
			}
			pthread_mutex_unlock(&mosq->callback_mutex);
			message__cleanup(&message);
			return MOSQ_ERR_SUCCESS;
		case 1:
			rc = send__puback(mosq, message->msg.mid);
			pthread_mutex_lock(&mosq->callback_mutex);
			if(mosq->on_message){
				mosq->in_callback = true;
				mosq->on_message(mosq, mosq->userdata, &message->msg);
				mosq->in_callback = false;
			}
			pthread_mutex_unlock(&mosq->callback_mutex);
			message__cleanup(&message);
			return rc;
		case 2:
			rc = send__pubrec(mosq, message->msg.mid);
			pthread_mutex_lock(&mosq->in_message_mutex);
			message->state = mosq_ms_wait_for_pubrel;
			message__queue(mosq, message, mosq_md_in);
			pthread_mutex_unlock(&mosq->in_message_mutex);
			return rc;
		default:
			message__cleanup(&message);
			return MOSQ_ERR_PROTOCOL;
	}
}


