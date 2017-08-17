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
#include "mqtt5_protocol.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "util_mosq.h"


int send__suback(struct mosquitto *context, uint16_t mid, uint32_t payloadlen, const void *payload)
{
	struct mosquitto__packet *packet = NULL;
	int rc;

	log__printf(NULL, MOSQ_LOG_DEBUG, "Sending SUBACK to %s", context->id);

	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packet->command = SUBACK;
	packet->remaining_length = 2+payloadlen;
	if(context->protocol == mosq_p_mqtt5){
		packet->remaining_length += varint_len(0);
	}
	rc = packet__alloc(packet);
	if(rc){
		mosquitto__free(packet);
		return rc;
	}
	packet__write_uint16(packet, mid);
	if(context->protocol == mosq_p_mqtt5){
		packet__write_property(context, packet);
	}
	if(payloadlen){
		packet__write_bytes(packet, payload, payloadlen);
	}

	return packet__queue(context, packet);
}

