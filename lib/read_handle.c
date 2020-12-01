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
#include <stdio.h>
#include <string.h>

#include "mosquitto.h"
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt_protocol.h"
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
		case CMD_PINGREQ:
			return handle__pingreq(mosq);
		case CMD_PINGRESP:
			return handle__pingresp(mosq);
		case CMD_PUBACK:
			return handle__pubackcomp(mosq, "PUBACK");
		case CMD_PUBCOMP:
			return handle__pubackcomp(mosq, "PUBCOMP");
		case CMD_PUBLISH:
			return handle__publish(mosq);
		case CMD_PUBREC:
			return handle__pubrec(mosq);
		case CMD_PUBREL:
			return handle__pubrel(mosq);
		case CMD_CONNACK:
			return handle__connack(mosq);
		case CMD_SUBACK:
			return handle__suback(mosq);
		case CMD_UNSUBACK:
			return handle__unsuback(mosq);
		case CMD_DISCONNECT:
			return handle__disconnect(mosq);
		case CMD_AUTH:
			return handle__auth(mosq);
		default:
			/* If we don't recognise the command, return an error straight away. */
			log__printf(mosq, MOSQ_LOG_ERR, "Error: Unrecognised command %d\n", (mosq->in_packet.command)&0xF0);
			return MOSQ_ERR_PROTOCOL;
	}
}

