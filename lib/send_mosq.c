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
#include <stdio.h>
#include <string.h>

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "logging_mosq.h"
#include "mqtt3_protocol.h"
#include "memory_mosq.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "send_mosq.h"
#include "time_mosq.h"
#include "util_mosq.h"

#ifdef WITH_BROKER
#  include "mosquitto_broker.h"
#  include "sys_tree.h"
#else
#  define G_PUB_BYTES_SENT_INC(A)
#endif

int send__pingreq(struct mosquitto *mosq)
{
	int rc;
	assert(mosq);
#ifdef WITH_BROKER
	log__printf(NULL, MOSQ_LOG_DEBUG, "Sending PINGREQ to %s", mosq->id);
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending PINGREQ", mosq->id);
#endif
	rc = send__simple_command(mosq, PINGREQ);
	if(rc == MOSQ_ERR_SUCCESS){
		mosq->ping_t = mosquitto_time();
	}
	return rc;
}

int send__pingresp(struct mosquitto *mosq)
{
#ifdef WITH_BROKER
	if(mosq) log__printf(NULL, MOSQ_LOG_DEBUG, "Sending PINGRESP to %s", mosq->id);
#else
	if(mosq) log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending PINGRESP", mosq->id);
#endif
	return send__simple_command(mosq, PINGRESP);
}

int send__puback(struct mosquitto *mosq, uint16_t mid)
{
#ifdef WITH_BROKER
	if(mosq) log__printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBACK to %s (Mid: %d)", mosq->id, mid);
#else
	if(mosq) log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending PUBACK (Mid: %d)", mosq->id, mid);
#endif
	return send__command_with_mid(mosq, PUBACK, mid, false);
}

int send__pubcomp(struct mosquitto *mosq, uint16_t mid)
{
#ifdef WITH_BROKER
	if(mosq) log__printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBCOMP to %s (Mid: %d)", mosq->id, mid);
#else
	if(mosq) log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending PUBCOMP (Mid: %d)", mosq->id, mid);
#endif
	return send__command_with_mid(mosq, PUBCOMP, mid, false);
}


int send__pubrec(struct mosquitto *mosq, uint16_t mid)
{
#ifdef WITH_BROKER
	if(mosq) log__printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBREC to %s (Mid: %d)", mosq->id, mid);
#else
	if(mosq) log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending PUBREC (Mid: %d)", mosq->id, mid);
#endif
	return send__command_with_mid(mosq, PUBREC, mid, false);
}

int send__pubrel(struct mosquitto *mosq, uint16_t mid)
{
#ifdef WITH_BROKER
	if(mosq) log__printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBREL to %s (Mid: %d)", mosq->id, mid);
#else
	if(mosq) log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending PUBREL (Mid: %d)", mosq->id, mid);
#endif
	return send__command_with_mid(mosq, PUBREL|2, mid, false);
}

/* For PUBACK, PUBCOMP, PUBREC, and PUBREL */
int send__command_with_mid(struct mosquitto *mosq, uint8_t command, uint16_t mid, bool dup)
{
	struct mosquitto__packet *packet = NULL;
	int rc;

	assert(mosq);
	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packet->command = command;
	if(dup){
		packet->command |= 8;
	}
	packet->remaining_length = 2;
	rc = packet__alloc(packet);
	if(rc){
		mosquitto__free(packet);
		return rc;
	}

	packet->payload[packet->pos+0] = MOSQ_MSB(mid);
	packet->payload[packet->pos+1] = MOSQ_LSB(mid);

	return packet__queue(mosq, packet);
}

/* For DISCONNECT, PINGREQ and PINGRESP */
int send__simple_command(struct mosquitto *mosq, uint8_t command)
{
	struct mosquitto__packet *packet = NULL;
	int rc;

	assert(mosq);
	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packet->command = command;
	packet->remaining_length = 0;

	rc = packet__alloc(packet);
	if(rc){
		mosquitto__free(packet);
		return rc;
	}

	return packet__queue(mosq, packet);
}

