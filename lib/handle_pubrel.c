/*
Copyright (c) 2009-2021 Roger Light <roger@atchoo.org>

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

#include "callbacks.h"
#include "mosquitto.h"
#include "logging_mosq.h"
#include "messages_mosq.h"
#include "mosquitto/mqtt_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "util_mosq.h"


int handle__pubrel(struct mosquitto *mosq)
{
	uint8_t reason_code;
	uint16_t mid;
#ifndef WITH_BROKER
	struct mosquitto_message_all *message = NULL;
#endif
	int rc;
	mosquitto_property *properties = NULL;

	assert(mosq);

	if(mosquitto__get_state(mosq) != mosq_cs_active){
		return MOSQ_ERR_PROTOCOL;
	}
	if(mosq->protocol != mosq_p_mqtt31 && mosq->in_packet.command != (CMD_PUBREL|2)){
		return MOSQ_ERR_MALFORMED_PACKET;
	}

	if(mosq->protocol != mosq_p_mqtt31){
		if((mosq->in_packet.command&0x0F) != 0x02){
			return MOSQ_ERR_PROTOCOL;
		}
	}
	rc = packet__read_uint16(&mosq->in_packet, &mid);
	if(rc) return rc;
	if(mid == 0) return MOSQ_ERR_PROTOCOL;

	if(mosq->protocol == mosq_p_mqtt5 && mosq->in_packet.remaining_length > 2){
		rc = packet__read_byte(&mosq->in_packet, &reason_code);
		if(rc) return rc;

		if(reason_code != MQTT_RC_SUCCESS && reason_code != MQTT_RC_PACKET_ID_NOT_FOUND){
			return MOSQ_ERR_PROTOCOL;
		}

		if(mosq->in_packet.remaining_length > 3){
			rc = property__read_all(CMD_PUBREL, &mosq->in_packet, &properties);
			if(rc) return rc;
			/* Immediately free, we don't do anything with Reason String or
			 * User Property at the moment */
			mosquitto_property_free_all(&properties);
		}
	}

	if(mosq->in_packet.pos < mosq->in_packet.remaining_length){
		return MOSQ_ERR_MALFORMED_PACKET;
	}

#ifdef WITH_BROKER
	log__printf(NULL, MOSQ_LOG_DEBUG, "Received PUBREL from %s (Mid: %d)", SAFE_PRINT(mosq->id), mid);

	rc = db__message_release_incoming(mosq, mid);
	if(rc == MOSQ_ERR_NOT_FOUND){
		/* Message not found. Still send a PUBCOMP anyway because this could be
		 * due to a repeated PUBREL after a client has reconnected. */
	}else if(rc != MOSQ_ERR_SUCCESS){
		return rc;
	}

	rc = send__pubcomp(mosq, mid, NULL);
	if(rc) return rc;
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s received PUBREL (Mid: %d)", SAFE_PRINT(mosq->id), mid);

	rc = send__pubcomp(mosq, mid, NULL);
	if(rc){
		message__remove(mosq, mid, mosq_md_in, &message, 2);
		return rc;
	}

	rc = message__remove(mosq, mid, mosq_md_in, &message, 2);
	if(rc == MOSQ_ERR_SUCCESS){
		/* Message was already passed to the application prior to PUBREC. */
		message__cleanup(&message);
	}else if(rc == MOSQ_ERR_NOT_FOUND){
		return MOSQ_ERR_SUCCESS;
	}else{
		return rc;
	}
#endif

	return MOSQ_ERR_SUCCESS;
}
