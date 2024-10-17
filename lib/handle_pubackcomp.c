/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef WITH_BROKER
#  include "mosquitto_broker_internal.h"
#endif

#include "mosquitto.h"
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "util_mosq.h"


int handle__pubackcomp(struct mosquitto *mosq, const char *type)
{
	uint8_t reason_code = 0;
	uint16_t mid;
	int rc;
	mosquitto_property *properties = NULL;
	int qos;

	assert(mosq);

	if(mosquitto__get_state(mosq) != mosq_cs_active){
		return MOSQ_ERR_PROTOCOL;
	}
	if(mosq->protocol != mosq_p_mqtt31){
		if((mosq->in_packet.command&0x0F) != 0x00){
			return MOSQ_ERR_MALFORMED_PACKET;
		}
	}

	COMPAT_pthread_mutex_lock(&mosq->msgs_out.mutex);
	util__increment_send_quota(mosq);
	COMPAT_pthread_mutex_unlock(&mosq->msgs_out.mutex);

	rc = packet__read_uint16(&mosq->in_packet, &mid);
	if(rc) return rc;
	if(type[3] == 'A'){ /* pubAck or pubComp */
		if(mosq->in_packet.command != CMD_PUBACK){
			return MOSQ_ERR_MALFORMED_PACKET;
		}
		qos = 1;
	}else{
		if(mosq->in_packet.command != CMD_PUBCOMP){
			return MOSQ_ERR_MALFORMED_PACKET;
		}
		qos = 2;
	}
	if(mid == 0){
		return MOSQ_ERR_PROTOCOL;
	}

	if(mosq->protocol == mosq_p_mqtt5 && mosq->in_packet.remaining_length > 2){
		rc = packet__read_byte(&mosq->in_packet, &reason_code);
		if(rc){
			return rc;
		}

		if(mosq->in_packet.remaining_length > 3){
			rc = property__read_all(CMD_PUBACK, &mosq->in_packet, &properties);
			if(rc) return rc;
		}
		if(type[3] == 'A'){ /* pubAck or pubComp */
			if(reason_code != MQTT_RC_SUCCESS
					&& reason_code != MQTT_RC_NO_MATCHING_SUBSCRIBERS
					&& reason_code != MQTT_RC_UNSPECIFIED
					&& reason_code != MQTT_RC_IMPLEMENTATION_SPECIFIC
					&& reason_code != MQTT_RC_NOT_AUTHORIZED
					&& reason_code != MQTT_RC_TOPIC_NAME_INVALID
					&& reason_code != MQTT_RC_PACKET_ID_IN_USE
					&& reason_code != MQTT_RC_QUOTA_EXCEEDED
					&& reason_code != MQTT_RC_PAYLOAD_FORMAT_INVALID
					){

				mosquitto_property_free_all(&properties);
				return MOSQ_ERR_PROTOCOL;
			}
		}else{
			if(reason_code != MQTT_RC_SUCCESS
					&& reason_code != MQTT_RC_PACKET_ID_NOT_FOUND
					){

				mosquitto_property_free_all(&properties);
				return MOSQ_ERR_PROTOCOL;
			}
		}
	}
	if(mosq->in_packet.pos < mosq->in_packet.remaining_length){
		mosquitto_property_free_all(&properties);
		return MOSQ_ERR_MALFORMED_PACKET;
	}

#ifdef WITH_BROKER
	log__printf(NULL, MOSQ_LOG_DEBUG, "Received %s from %s (Mid: %d, RC:%d)", type, SAFE_PRINT(mosq->id), mid, reason_code);

	/* Immediately free, we don't do anything with Reason String or User Property at the moment */
	mosquitto_property_free_all(&properties);

	rc = db__message_delete_outgoing(mosq, mid, mosq_ms_wait_for_pubcomp, qos);
	if(rc == MOSQ_ERR_NOT_FOUND){
		log__printf(mosq, MOSQ_LOG_WARNING, "Warning: Received %s from %s for an unknown packet identifier %d.", type, SAFE_PRINT(mosq->id), mid);
		return MOSQ_ERR_SUCCESS;
	}else{
		return rc;
	}
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s received %s (Mid: %d, RC:%d)", SAFE_PRINT(mosq->id), type, mid, reason_code);

	rc = message__delete(mosq, mid, mosq_md_out, qos);
	if(rc == MOSQ_ERR_SUCCESS){
		/* Only inform the client the message has been sent once. */
		COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
		if(mosq->on_publish){
			mosq->in_callback = true;
			mosq->on_publish(mosq, mosq->userdata, mid);
			mosq->in_callback = false;
		}
		if(mosq->on_publish_v5){
			mosq->in_callback = true;
			mosq->on_publish_v5(mosq, mosq->userdata, mid, reason_code, properties);
			mosq->in_callback = false;
		}
		COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
		mosquitto_property_free_all(&properties);
	}else if(rc != MOSQ_ERR_NOT_FOUND){
		return rc;
	}
	COMPAT_pthread_mutex_lock(&mosq->msgs_out.mutex);
	message__release_to_inflight(mosq, mosq_md_out);
	COMPAT_pthread_mutex_unlock(&mosq->msgs_out.mutex);

	return MOSQ_ERR_SUCCESS;
#endif
}

