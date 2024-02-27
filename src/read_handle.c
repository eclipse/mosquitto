/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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

#include <stdio.h>
#include <string.h>

#include "mosquitto_broker_internal.h"
#include "mqtt_protocol.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "sys_tree.h"
#include "util_mosq.h"


int handle__packet(struct mosquitto *context)
{
	int rc = MOSQ_ERR_INVAL;

	if(!context) return MOSQ_ERR_INVAL;

	switch((context->in_packet.command)&0xF0){
		case CMD_PINGREQ:
			rc = handle__pingreq(context);
			break;
		case CMD_PINGRESP:
			rc = handle__pingresp(context);
			break;
		case CMD_PUBACK:
			rc = handle__pubackcomp(context, "PUBACK");
			break;
		case CMD_PUBCOMP:
			rc = handle__pubackcomp(context, "PUBCOMP");
			break;
		case CMD_PUBLISH:
			rc = handle__publish(context);
			break;
		case CMD_PUBREC:
			rc = handle__pubrec(context);
			break;
		case CMD_PUBREL:
			rc = handle__pubrel(context);
			break;
		case CMD_CONNECT:
			return handle__connect(context);
		case CMD_DISCONNECT:
			rc = handle__disconnect(context);
			break;
		case CMD_SUBSCRIBE:
			rc = handle__subscribe(context);
			break;
		case CMD_UNSUBSCRIBE:
			rc = handle__unsubscribe(context);
			break;
#ifdef WITH_BRIDGE
		case CMD_CONNACK:
			rc = handle__connack(context);
			break;
		case CMD_SUBACK:
			rc = handle__suback(context);
			break;
		case CMD_UNSUBACK:
			rc = handle__unsuback(context);
			break;
#endif
		case CMD_AUTH:
			rc = handle__auth(context);
			break;
		default:
			rc = MOSQ_ERR_PROTOCOL;
	}

	if(context->protocol == mosq_p_mqtt5){
		if(rc == MOSQ_ERR_PROTOCOL || rc == MOSQ_ERR_DUPLICATE_PROPERTY){
			send__disconnect(context, MQTT_RC_PROTOCOL_ERROR, NULL);
		}else if(rc == MOSQ_ERR_MALFORMED_PACKET){
			send__disconnect(context, MQTT_RC_MALFORMED_PACKET, NULL);
		}else if(rc == MOSQ_ERR_QOS_NOT_SUPPORTED){
			send__disconnect(context, MQTT_RC_QOS_NOT_SUPPORTED, NULL);
		}else if(rc == MOSQ_ERR_RETAIN_NOT_SUPPORTED){
			send__disconnect(context, MQTT_RC_RETAIN_NOT_SUPPORTED, NULL);
		}else if(rc == MOSQ_ERR_TOPIC_ALIAS_INVALID){
			send__disconnect(context, MQTT_RC_TOPIC_ALIAS_INVALID, NULL);
		}else if(rc == MOSQ_ERR_UNKNOWN || rc == MOSQ_ERR_NOMEM){
			send__disconnect(context, MQTT_RC_UNSPECIFIED, NULL);
		}
	}
	return rc;
}
