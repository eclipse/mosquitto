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

#ifdef WITH_BROKER
#  include "mosquitto_broker_internal.h"
#endif

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "send_mosq.h"


int send__disconnect(struct mosquitto *mosq, uint8_t reason_code, const mosquitto_property *properties)
{
	struct mosquitto__packet *packet = NULL;
	int rc;

	assert(mosq);
#ifdef WITH_BROKER
#  ifdef WITH_BRIDGE
	if(mosq->bridge){
		log__printf(mosq, MOSQ_LOG_DEBUG, "Bridge %s sending DISCONNECT", mosq->id);
	}else
#  else
	{
		log__printf(mosq, MOSQ_LOG_DEBUG, "Sending DISCONNECT to %s (rc%d)", mosq->id, reason_code);
	}
#  endif
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending DISCONNECT", mosq->id);
#endif
	assert(mosq);
	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packet->command = CMD_DISCONNECT;
	if(mosq->protocol == mosq_p_mqtt5 && (reason_code != 0 || properties)){
		packet->remaining_length = 1;
		if(properties){
			packet->remaining_length += property__get_remaining_length(properties);
		}
	}else{
		packet->remaining_length = 0;
	}

	rc = packet__alloc(packet);
	if(rc){
		mosquitto__free(packet);
		return rc;
	}
	if(mosq->protocol == mosq_p_mqtt5 && (reason_code != 0 || properties)){
		packet__write_byte(packet, reason_code);
		if(properties){
			property__write_all(packet, properties, true);
		}
	}

	return packet__queue(mosq, packet);
}

