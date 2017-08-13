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

#include <stdio.h>
#include <string.h>

#include "config.h"

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "mqtt3_protocol.h"
#include "packet_mosq.h"
#include "send_mosq.h"
/*
#include "sys_tree.h"
#include "time_mosq.h"
#include "tls_mosq.h"
#include "util_mosq.h"
*/

int handle__unsubscribe(struct mosquitto_db *db, struct mosquitto *context)
{
	uint16_t mid;
	char *sub;
	int rc = 0;
	uint8_t *payload = NULL, *tmp_payload;
	uint32_t payloadlen = 0;

	if(!context) return MOSQ_ERR_INVAL;
	log__printf(NULL, MOSQ_LOG_DEBUG, "Received UNSUBSCRIBE from %s", context->id);

	if((context->protocol == mosq_p_mqtt311) || (context->protocol == mosq_p_mqtt5)){
		if((context->in_packet.command&0x0F) != 0x02){
			if(context->protocol == mosq_p_mqtt5){
				rc = MQTT5_RC_MALFORMED_PACKET;
				goto handle_unsubscribe_error;
			}
			return MOSQ_ERR_PROTOCOL;
		}
	}
	if(packet__read_uint16(&context->in_packet, &mid)){
		if(context->protocol == mosq_p_mqtt5){
			rc = MQTT5_RC_MALFORMED_PACKET;
			goto handle_unsubscribe_error;
		}
		return 1;
	}

	while(context->in_packet.pos < context->in_packet.remaining_length){
		sub = NULL;
		if(packet__read_string(&context->in_packet, &sub)){
			if(context->protocol == mosq_p_mqtt5){
				rc = MQTT5_RC_MALFORMED_PACKET;
				goto handle_unsubscribe_error;
			}
			return 1;
		}

		if(sub){
			if(STREMPTY(sub)){
				log__printf(NULL, MOSQ_LOG_INFO,
						"Empty unsubscription string from %s, disconnecting.",
						context->id);
				if(context->protocol == mosq_p_mqtt5){
					rc = MQTT5_RC_PROTOCOL_ERROR;
					goto handle_unsubscribe_error;
				}
				mosquitto__free(sub);
				return 1;
			}
			if(mosquitto_sub_topic_check(sub)){
				log__printf(NULL, MOSQ_LOG_INFO,
						"Invalid unsubscription string from %s, disconnecting.",
						context->id);
				if(context->protocol == mosq_p_mqtt5){
					rc = MQTT5_RC_MALFORMED_PACKET;
					goto handle_unsubscribe_error;
				}
				mosquitto__free(sub);
				return 1;
			}
			if(mosquitto_validate_utf8(sub, strlen(sub))){
				log__printf(NULL, MOSQ_LOG_INFO,
						"Malformed UTF-8 in unsubscription string from %s, disconnecting.",
						context->id);
				if(context->protocol == mosq_p_mqtt5){
					rc = MQTT5_RC_MALFORMED_PACKET;
					goto handle_unsubscribe_error;
				}
				mosquitto__free(sub);
				return 1;
			}

			log__printf(NULL, MOSQ_LOG_DEBUG, "\t%s", sub);
			sub__remove(db, context, sub, db->subs);
			log__printf(NULL, MOSQ_LOG_UNSUBSCRIBE, "%s %s", context->id, sub);
			mosquitto__free(sub);

			if(context->protocol == mosq_p_mqtt5){
				tmp_payload = mosquitto__realloc(payload, payloadlen + 1);
				if(tmp_payload){
					payload = tmp_payload;
					payload[payloadlen] = MQTT5_RC_SUCCESS;
					payloadlen++;
				}else{
					rc = MQTT5_RC_UNSPECIFIED_ERROR;
					goto handle_unsubscribe_error;
				}
			}
		}
	}
#ifdef WITH_PERSISTENCE
	db->persistence_changes++;
#endif

	if(context->protocol == mosq_p_mqtt5){
		return send__unsuback(context, mid, payloadlen, payload);
	}
	return send__command_with_mid(context, UNSUBACK, mid, false);

handle_unsubscribe_error:  // for v5 only
	mosquitto__free(sub);
	mosquitto__free(payload);
	if(rc == MOSQ_ERR_PROTOCOL){
		rc = MQTT5_RC_MALFORMED_PACKET;
	}else if(rc == MOSQ_ERR_NOMEM) {
		rc = MQTT5_RC_UNSPECIFIED_ERROR;
	}
	context->rc_current = rc;
	if(context__current_property_init(context)){
		return MOSQ_ERR_NOMEM;	
	}
	send__disconnect(context);
	context->rc_current = 0;
	context__current_property_free(context);

	do_disconnect(db, context);
	return rc;
}


