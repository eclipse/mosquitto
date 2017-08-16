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

#include "config.h"

#include "mosquitto_broker_internal.h"
#include "mqtt3_protocol.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "util_mosq.h"

int send__connack(struct mosquitto *context, int ack, int result)
{
	struct mosquitto__packet *packet = NULL;
	int rc, len;

	if(context){
		if(context->id){
			log__printf(NULL, MOSQ_LOG_DEBUG, "Sending CONNACK to %s (%d, %d)", context->id, ack, result);
		}else{
			log__printf(NULL, MOSQ_LOG_DEBUG, "Sending CONNACK to %s (%d, %d)", context->address, ack, result);
		}
	}

	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packet->command = CONNACK;
	packet->remaining_length = 2;
	if(context->protocol == mosq_p_mqtt5){
		len = packet__property_len(context->current_property);
		packet->remaining_length += variable_len(len) + len;
	}
	rc = packet__alloc(packet);
	if(rc){
		mosquitto__free(packet);
		return rc;
	}
	packet->payload[packet->pos+0] = ack;
	packet->payload[packet->pos+1] = result;
	
	if(context->protocol == mosq_p_mqtt5){
		packet->pos += 2;
		packet__write_property(context, packet, context->current_property, CONNACK);
	}

	return packet__queue(context, packet);
}


