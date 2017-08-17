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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "config.h"

#include "mosquitto_broker_internal.h"
#include "mqtt3_protocol.h"
#include "mqtt5_protocol.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "sys_tree.h"
#include "util_mosq.h"


int handle__packet(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;
	if(!context) return MOSQ_ERR_INVAL;

	switch((context->in_packet.command)&0xF0){
		case PINGREQ:
			rc = handle__pingreq(context);
			break;
		case PINGRESP:
			rc = handle__pingresp(context);
			break;
		case PUBACK:
			rc = handle__pubackcomp(db, context, "PUBACK");
			break;
		case PUBCOMP:
			rc = handle__pubackcomp(db, context, "PUBCOMP");
			break;
		case PUBLISH:
			rc = handle__publish(db, context);
			break;
		case PUBREC:
			rc = handle__pubrec(context);
			break;
		case PUBREL:
			rc = handle__pubrel(db, context);
			break;
		case CONNECT:
			return handle__connect(db, context);
		case DISCONNECT:
			return handle__disconnect(db, context);
		case SUBSCRIBE:
			rc = handle__subscribe(db, context);
			break;
		case UNSUBSCRIBE:
			rc = handle__unsubscribe(db, context);
			break;
		case AUTH:
			log__printf(NULL, MOSQ_LOG_INFO, "Received AUTH from %s, but not supperted.", context->id);
			rc = MQTT5_RC_PROTOCOL_ERROR;
			break;
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
			rc = MOSQ_ERR_PROTOCOL;
	}

	/* For v5, should send explicit DISCONNECT from server before disconnect a network connection. */
	if((context->protocol == mosq_p_mqtt5) && (rc != MQTT5_RC_SUCCESS)){
		if(rc == MOSQ_ERR_PROTOCOL){
			rc = MQTT5_RC_MALFORMED_PACKET;
		}else if(rc < MQTT5_RC_UNSPECIFIED_ERROR) {
			rc = MQTT5_RC_UNSPECIFIED_ERROR;
		}
		send__disconnect_v5(context, rc);
	}
	return rc;
}


