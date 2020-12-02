/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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

#include <assert.h>
#include <string.h>

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "messages_mosq.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "send_mosq.h"
#include "time_mosq.h"
#include "util_mosq.h"


int handle__publish(struct mosquitto *mosq)
{
	uint8_t header;
	struct mosquitto_message_all *message;
	int rc = 0;
	uint16_t mid;
	uint16_t slen;
	mosquitto_property *properties = NULL;

	assert(mosq);

	if(mosquitto__get_state(mosq) != mosq_cs_active){
		return MOSQ_ERR_PROTOCOL;
	}

	message = mosquitto__calloc(1, sizeof(struct mosquitto_message_all));
	if(!message) return MOSQ_ERR_NOMEM;

	header = mosq->in_packet.command;

	message->dup = (header & 0x08)>>3;
	message->msg.qos = (header & 0x06)>>1;
	message->msg.retain = (header & 0x01);

	rc = packet__read_string(&mosq->in_packet, &message->msg.topic, &slen);
	if(rc){
		message__cleanup(&message);
		return rc;
	}
	if(!slen){
		message__cleanup(&message);
		return MOSQ_ERR_PROTOCOL;
	}

	if(message->msg.qos > 0){
		if(mosq->protocol == mosq_p_mqtt5){
			if(mosq->msgs_in.inflight_quota == 0){
				message__cleanup(&message);
				/* FIXME - should send a DISCONNECT here */
				return MOSQ_ERR_PROTOCOL;
			}
		}

		rc = packet__read_uint16(&mosq->in_packet, &mid);
		if(rc){
			message__cleanup(&message);
			return rc;
		}
		if(mid == 0){
			message__cleanup(&message);
			return MOSQ_ERR_PROTOCOL;
		}
		message->msg.mid = (int)mid;
	}

	if(mosq->protocol == mosq_p_mqtt5){
		rc = property__read_all(CMD_PUBLISH, &mosq->in_packet, &properties);
		if(rc) return rc;
	}

	message->msg.payloadlen = (int)(mosq->in_packet.remaining_length - mosq->in_packet.pos);
	if(message->msg.payloadlen){
		message->msg.payload = mosquitto__calloc((size_t)message->msg.payloadlen+1, sizeof(uint8_t));
		if(!message->msg.payload){
			message__cleanup(&message);
			mosquitto_property_free_all(&properties);
			return MOSQ_ERR_NOMEM;
		}
		rc = packet__read_bytes(&mosq->in_packet, message->msg.payload, (uint32_t)message->msg.payloadlen);
		if(rc){
			message__cleanup(&message);
			mosquitto_property_free_all(&properties);
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
			if(mosq->on_message_v5){
				mosq->in_callback = true;
				mosq->on_message_v5(mosq, mosq->userdata, &message->msg, properties);
				mosq->in_callback = false;
			}
			pthread_mutex_unlock(&mosq->callback_mutex);
			message__cleanup(&message);
			mosquitto_property_free_all(&properties);
			return MOSQ_ERR_SUCCESS;
		case 1:
			util__decrement_receive_quota(mosq);
			rc = send__puback(mosq, mid, 0, NULL);
			pthread_mutex_lock(&mosq->callback_mutex);
			if(mosq->on_message){
				mosq->in_callback = true;
				mosq->on_message(mosq, mosq->userdata, &message->msg);
				mosq->in_callback = false;
			}
			if(mosq->on_message_v5){
				mosq->in_callback = true;
				mosq->on_message_v5(mosq, mosq->userdata, &message->msg, properties);
				mosq->in_callback = false;
			}
			pthread_mutex_unlock(&mosq->callback_mutex);
			message__cleanup(&message);
			mosquitto_property_free_all(&properties);
			return rc;
		case 2:
			message->properties = properties;
			util__decrement_receive_quota(mosq);
			rc = send__pubrec(mosq, mid, 0, NULL);
			pthread_mutex_lock(&mosq->msgs_in.mutex);
			message->state = mosq_ms_wait_for_pubrel;
			message__queue(mosq, message, mosq_md_in);
			pthread_mutex_unlock(&mosq->msgs_in.mutex);
			return rc;
		default:
			message__cleanup(&message);
			mosquitto_property_free_all(&properties);
			return MOSQ_ERR_PROTOCOL;
	}
}

