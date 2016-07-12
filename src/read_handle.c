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
*/

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "config.h"

#include "mosquitto_broker.h"
#include "mqtt3_protocol.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "sys_tree.h"
#include "util_mosq.h"


int handle__packet(struct mosquitto_db *db, struct mosquitto *context)
{
	if(!context) return MOSQ_ERR_INVAL;

	switch((context->in_packet.command)&0xF0){
		case PINGREQ:
			return handle__pingreq(context);
		case PINGRESP:
			return handle__pingresp(context);
		case PUBACK:
			return handle__pubackcomp(db, context, "PUBACK");
		case PUBCOMP:
			return handle__pubackcomp(db, context, "PUBCOMP");
		case PUBLISH:
			return handle__publish(db, context);
		case PUBREC:
			return handle__pubrec(context);
		case PUBREL:
			return handle__pubrel(db, context);
		case CONNECT:
			return handle__connect(db, context);
		case DISCONNECT:
			return handle__disconnect(db, context);
		case SUBSCRIBE:
			return handle__subscribe(db, context);
		case UNSUBSCRIBE:
			return handle__unsubscribe(db, context);
#ifdef WITH_BRIDGE
		case CONNACK:
			return handle__connack(db, context);
		case SUBACK:
			return handle__suback(context);
		case UNSUBACK:
			return handle__unsuback(context);
#endif
		default:
			/* If we don't recognise the command, return an error straight away. */
			return MOSQ_ERR_PROTOCOL;
	}
}

