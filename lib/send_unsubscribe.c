/*
Copyright (c) 2009-2015 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include <assert.h>
//#include <string.h>

#include "mosquitto.h"
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "mqtt3_protocol.h"
//#include "net_mosq.h"
#include "packet_mosq.h"
//#include "send_mosq.h"
#include "util_mosq.h"

#ifdef WITH_BROKER
#  include "mosquitto_broker.h"
#endif

int send__unsubscribe(struct mosquitto *mosq, int *mid, const char *topic)
{
	/* FIXME - only deals with a single topic */
	struct mosquitto__packet *packet = NULL;
	uint32_t packetlen;
	uint16_t local_mid;
	int rc;

	assert(mosq);
	assert(topic);

	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packetlen = 2 + 2+strlen(topic);

	packet->command = UNSUBSCRIBE | (1<<1);
	packet->remaining_length = packetlen;
	rc = packet__alloc(packet);
	if(rc){
		mosquitto__free(packet);
		return rc;
	}

	/* Variable header */
	local_mid = mosquitto__mid_generate(mosq);
	if(mid) *mid = (int)local_mid;
	packet__write_uint16(packet, local_mid);

	/* Payload */
	packet__write_string(packet, topic, strlen(topic));

#ifdef WITH_BROKER
# ifdef WITH_BRIDGE
	log__printf(mosq, MOSQ_LOG_DEBUG, "Bridge %s sending UNSUBSCRIBE (Mid: %d, Topic: %s)", mosq->id, local_mid, topic);
# endif
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending UNSUBSCRIBE (Mid: %d, Topic: %s)", mosq->id, local_mid, topic);
#endif
	return packet__queue(mosq, packet);
}

