/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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

#include "config.h"

#include <stdio.h>
#include <string.h>

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "packet_mosq.h"
#include "send_mosq.h"
#include "util_mosq.h"

int handle__connack(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;
	uint8_t connect_acknowledge;
	uint8_t reason_code;
	mosquitto_property *properties = NULL;
	uint32_t maximum_packet_size;

	if(!context){
		return MOSQ_ERR_INVAL;
	}
	log__printf(NULL, MOSQ_LOG_DEBUG, "Received CONNACK on connection %s.", context->id);
	if(packet__read_byte(&context->in_packet, &connect_acknowledge)) return 1;
	if(packet__read_byte(&context->in_packet, &reason_code)) return 1;

	if(context->protocol == mosq_p_mqtt5){
		if(context->in_packet.remaining_length == 2 && reason_code == CONNACK_REFUSED_PROTOCOL_VERSION){
			/* We have connected to a MQTT v3.x broker that doesn't support MQTT v5.0
			 * It has correctly replied with a CONNACK code of a bad protocol version.
			 */
			log__printf(NULL, MOSQ_LOG_NOTICE,
					"Warning: Remote bridge %s does not support MQTT v5.0, reconnecting using MQTT v3.1.1.",
					context->bridge->name);

			context->protocol = mosq_p_mqtt311;
			context->bridge->protocol_version = mosq_p_mqtt311;
			return MOSQ_ERR_PROTOCOL;
		}
		rc = property__read_all(CMD_CONNACK, &context->in_packet, &properties);
		if(rc) return rc;

		if(mosquitto_property_read_int32(properties, MQTT_PROP_MAXIMUM_PACKET_SIZE,
					&maximum_packet_size, false)){

			if(context->maximum_packet_size == 0 || context->maximum_packet_size > maximum_packet_size){
				context->maximum_packet_size = maximum_packet_size;
			}
		}

		mosquitto_property_free_all(&properties);
	}
	mosquitto_property_free_all(&properties); /* FIXME - TEMPORARY UNTIL PROPERTIES PROCESSED */

	if(reason_code == MQTT_RC_SUCCESS){
#ifdef WITH_BRIDGE
		if(context->bridge){
			rc = bridge__on_connect(db, context);
			if(rc) return rc;
		}
#endif
		mosquitto__set_state(context, mosq_cs_active);
		rc = db__message_write_queued_out(db, context);
		if(rc) return rc;
		rc = db__message_write_inflight_out_all(db, context);
		return rc;
	}else{
		if(context->protocol == mosq_p_mqtt5){
			switch(reason_code){
				case MQTT_RC_RETAIN_NOT_SUPPORTED:
					context->retain_available = 0;
					log__printf(NULL, MOSQ_LOG_ERR, "Connection Refused: retain not available (will retry)");
					return 1;
				default:
					log__printf(NULL, MOSQ_LOG_ERR, "Connection Refused: %s", "FIXME"); //mosquitto_reason_string(reason_code));
					return 1;
			}
		}else{
			switch(reason_code){
				case CONNACK_REFUSED_PROTOCOL_VERSION:
					if(context->bridge){
						context->bridge->try_private_accepted = false;
					}
					log__printf(NULL, MOSQ_LOG_ERR, "Connection Refused: unacceptable protocol version");
					return 1;
				case CONNACK_REFUSED_IDENTIFIER_REJECTED:
					log__printf(NULL, MOSQ_LOG_ERR, "Connection Refused: identifier rejected");
					return 1;
				case CONNACK_REFUSED_SERVER_UNAVAILABLE:
					log__printf(NULL, MOSQ_LOG_ERR, "Connection Refused: broker unavailable");
					return 1;
				case CONNACK_REFUSED_BAD_USERNAME_PASSWORD:
					log__printf(NULL, MOSQ_LOG_ERR, "Connection Refused: broker unavailable");
					return 1;
				case CONNACK_REFUSED_NOT_AUTHORIZED:
					log__printf(NULL, MOSQ_LOG_ERR, "Connection Refused: not authorised");
					return 1;
				default:
					log__printf(NULL, MOSQ_LOG_ERR, "Connection Refused: unknown reason");
					return 1;
			}
		}
	}
	return 1;
}

