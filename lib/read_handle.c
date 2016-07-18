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
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt3_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "time_mosq.h"
#include "util_mosq.h"

int handle__packet(struct mosquitto *mosq)
{
	assert(mosq);

	switch((mosq->in_packet.command)&0xF0){
		case PINGREQ:
			return handle__pingreq(mosq);
		case PINGRESP:
			return handle__pingresp(mosq);
		case PUBACK:
			return handle__pubackcomp(mosq, "PUBACK");
		case PUBCOMP:
			return handle__pubackcomp(mosq, "PUBCOMP");
		case PUBLISH:
			return handle__publish(mosq);
		case PUBREC:
			return handle__pubrec(mosq);
		case PUBREL:
			return handle__pubrel(NULL, mosq);
		case CONNACK:
			return handle__connack(mosq);
		case SUBACK:
			return handle__suback(mosq);
		case UNSUBACK:
			return handle__unsuback(mosq);
		default:
			/* If we don't recognise the command, return an error straight away. */
			log__printf(mosq, MOSQ_LOG_ERR, "Error: Unrecognised command %d\n", (mosq->in_packet.command)&0xF0);
			return MOSQ_ERR_PROTOCOL;
	}
}

