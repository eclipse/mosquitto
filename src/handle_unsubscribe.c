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

#include <stdio.h>
#include <string.h>

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "packet_mosq.h"
#include "send_mosq.h"

int handle__unsubscribe(struct mosquitto *context)
{
	uint16_t mid;
	char *sub;
	uint16_t slen;
	int rc;
	uint8_t reason;
	int reason_code_count = 0;
	int reason_code_max;
	uint8_t *reason_codes = NULL, *reason_tmp;
	mosquitto_property *properties = NULL;
	bool allowed;

	if(!context) return MOSQ_ERR_INVAL;

	if(context->state != mosq_cs_active){
		return MOSQ_ERR_PROTOCOL;
	}
	log__printf(NULL, MOSQ_LOG_DEBUG, "Received UNSUBSCRIBE from %s", context->id);

	if(context->protocol != mosq_p_mqtt31){
		if((context->in_packet.command&0x0F) != 0x02){
			return MOSQ_ERR_MALFORMED_PACKET;
		}
	}
	if(packet__read_uint16(&context->in_packet, &mid)) return MOSQ_ERR_MALFORMED_PACKET;
	if(mid == 0) return MOSQ_ERR_MALFORMED_PACKET;

	if(context->protocol == mosq_p_mqtt5){
		rc = property__read_all(CMD_UNSUBSCRIBE, &context->in_packet, &properties);
		if(rc){
			/* FIXME - it would be better if property__read_all() returned
			 * MOSQ_ERR_MALFORMED_PACKET, but this is would change the library
			 * return codes so needs doc changes as well. */
			if(rc == MOSQ_ERR_PROTOCOL){
				return MOSQ_ERR_MALFORMED_PACKET;
			}else{
				return rc;
			}
		}
		/* Immediately free, we don't do anything with User Property at the moment */
		mosquitto_property_free_all(&properties);
	}

	if(context->protocol == mosq_p_mqtt311 || context->protocol == mosq_p_mqtt5){
		if(context->in_packet.pos == context->in_packet.remaining_length){
			/* No topic specified, protocol error. */
			return MOSQ_ERR_MALFORMED_PACKET;
		}
	}

	reason_code_max = 10;
	reason_codes = mosquitto__malloc((size_t)reason_code_max);
	if(!reason_codes){
		return MOSQ_ERR_NOMEM;
	}

	while(context->in_packet.pos < context->in_packet.remaining_length){
		sub = NULL;
		if(packet__read_string(&context->in_packet, &sub, &slen)){
			mosquitto__free(reason_codes);
			return MOSQ_ERR_MALFORMED_PACKET;
		}

		if(!slen){
			log__printf(NULL, MOSQ_LOG_INFO,
					"Empty unsubscription string from %s, disconnecting.",
					context->id);
			mosquitto__free(sub);
			mosquitto__free(reason_codes);
			return MOSQ_ERR_MALFORMED_PACKET;
		}
		if(mosquitto_sub_topic_check(sub)){
			log__printf(NULL, MOSQ_LOG_INFO,
					"Invalid unsubscription string from %s, disconnecting.",
					context->id);
			mosquitto__free(sub);
			mosquitto__free(reason_codes);
			return MOSQ_ERR_MALFORMED_PACKET;
		}

		/* ACL check */
		allowed = true;
		rc = mosquitto_acl_check(context, sub, 0, NULL, 0, false, MOSQ_ACL_UNSUBSCRIBE);
		switch(rc){
			case MOSQ_ERR_SUCCESS:
				break;
			case MOSQ_ERR_ACL_DENIED:
				allowed = false;
				reason = MQTT_RC_NOT_AUTHORIZED;
				break;
			default:
				mosquitto__free(sub);
				mosquitto__free(reason_codes);
				return rc;
		}

		log__printf(NULL, MOSQ_LOG_DEBUG, "\t%s", sub);
		if(allowed){
			rc = sub__remove(context, sub, db.subs, &reason);
		}else{
			rc = MOSQ_ERR_SUCCESS;
		}
		log__printf(NULL, MOSQ_LOG_UNSUBSCRIBE, "%s %s", context->id, sub);
		mosquitto__free(sub);
		if(rc){
			mosquitto__free(reason_codes);
			return rc;
		}

		reason_codes[reason_code_count] = reason;
		reason_code_count++;
		if(reason_code_count == reason_code_max){
			reason_tmp = mosquitto__realloc(reason_codes, (size_t)(reason_code_max*2));
			if(!reason_tmp){
				mosquitto__free(reason_codes);
				return MOSQ_ERR_NOMEM;
			}
			reason_codes = reason_tmp;
			reason_code_max *= 2;
		}
	}
#ifdef WITH_PERSISTENCE
	db.persistence_changes++;
#endif

	log__printf(NULL, MOSQ_LOG_DEBUG, "Sending UNSUBACK to %s", context->id);

	/* We don't use Reason String or User Property yet. */
	rc = send__unsuback(context, mid, reason_code_count, reason_codes, NULL);
	mosquitto__free(reason_codes);
	return rc;
}
