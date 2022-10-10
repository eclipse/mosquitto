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
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "util_mosq.h"


int handle__unsuback(struct mosquitto *mosq)
{
	uint16_t mid;
	int rc;
	mosquitto_property *properties = NULL;

	assert(mosq);

	if(mosquitto__get_state(mosq) != mosq_cs_active){
		return MOSQ_ERR_PROTOCOL;
	}
	if(mosq->in_packet.command != CMD_UNSUBACK){
		return MOSQ_ERR_MALFORMED_PACKET;
	}

#ifdef WITH_BROKER
	if(mosq->bridge == NULL){
		/* Client is not a bridge, so shouldn't be sending SUBACK */
		return MOSQ_ERR_PROTOCOL;
	}
	log__printf(NULL, MOSQ_LOG_DEBUG, "Received UNSUBACK from %s", SAFE_PRINT(mosq->id));
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s received UNSUBACK", SAFE_PRINT(mosq->id));
#endif
	rc = packet__read_uint16(&mosq->in_packet, &mid);
	if(rc) return rc;
	if(mid == 0) return MOSQ_ERR_PROTOCOL;

	if(mosq->protocol == mosq_p_mqtt5){
		rc = property__read_all(CMD_UNSUBACK, &mosq->in_packet, &properties);
		if(rc) return rc;
	}

#ifdef WITH_BROKER
	/* Immediately free, we don't do anything with Reason String or User Property at the moment */
	mosquitto_property_free_all(&properties);
#else
	callback__on_unsubscribe(mosq, mid, properties);
	mosquitto_property_free_all(&properties);
#endif

	return MOSQ_ERR_SUCCESS;
}

