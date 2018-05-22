/*
Copyright (c) 2009-2018 Roger Light <roger@atchoo.org>

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

#include <stdio.h>
#include <string.h>

#include "config.h"

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "packet_mosq.h"



int handle__subscribe(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc = 0;
	int rc2;
	uint16_t mid;
	char *sub;
	uint8_t qos;
	uint8_t *payload = NULL, *tmp_payload;
	uint32_t payloadlen = 0;
	int len;
	int slen;
	char *sub_mount;

	if(!context) return MOSQ_ERR_INVAL;
	log__printf(NULL, MOSQ_LOG_DEBUG, "Received SUBSCRIBE from %s", context->id);
	/* FIXME - plenty of potential for memory leaks here */

	if(context->protocol == mosq_p_mqtt311){
		if((context->in_packet.command&0x0F) != 0x02){
			return MOSQ_ERR_PROTOCOL;
		}
	}
	if(packet__read_uint16(&context->in_packet, &mid)) return 1;

	while(context->in_packet.pos < context->in_packet.remaining_length){
		sub = NULL;
		if(packet__read_string(&context->in_packet, &sub, &slen)){
			mosquitto__free(payload);
			return 1;
		}

		if(sub){
			if(!slen){
				log__printf(NULL, MOSQ_LOG_INFO,
						"Empty subscription string from %s, disconnecting.",
						context->address);
				mosquitto__free(sub);
				mosquitto__free(payload);
				return 1;
			}
			if(mosquitto_sub_topic_check(sub)){
				log__printf(NULL, MOSQ_LOG_INFO,
						"Invalid subscription string from %s, disconnecting.",
						context->address);
				mosquitto__free(sub);
				mosquitto__free(payload);
				return 1;
			}
			if(mosquitto_validate_utf8(sub, slen)){
				log__printf(NULL, MOSQ_LOG_INFO,
						"Malformed UTF-8 in subscription string from %s, disconnecting.",
						context->id);
				mosquitto__free(sub);
				return 1;
			}

			if(packet__read_byte(&context->in_packet, &qos)){
				mosquitto__free(sub);
				mosquitto__free(payload);
				return 1;
			}
			if(qos > 2){
				log__printf(NULL, MOSQ_LOG_INFO,
						"Invalid QoS in subscription command from %s, disconnecting.",
						context->address);
				mosquitto__free(sub);
				mosquitto__free(payload);
				return 1;
			}
			if(context->listener && context->listener->mount_point){
				len = strlen(context->listener->mount_point) + slen + 1;
				sub_mount = mosquitto__malloc(len+1);
				if(!sub_mount){
					mosquitto__free(sub);
					mosquitto__free(payload);
					return MOSQ_ERR_NOMEM;
				}
				snprintf(sub_mount, len, "%s%s", context->listener->mount_point, sub);
				sub_mount[len] = '\0';

				mosquitto__free(sub);
				sub = sub_mount;

			}
			log__printf(NULL, MOSQ_LOG_DEBUG, "\t%s (QoS %d)", sub, qos);

			if(context->protocol == mosq_p_mqtt311){
				rc = mosquitto_acl_check(db, context, sub, 0, NULL, qos, false, MOSQ_ACL_SUBSCRIBE);
				switch(rc){
					case MOSQ_ERR_SUCCESS:
						break;
					case MOSQ_ERR_ACL_DENIED:
						qos = 0x80;
						break;
					default:
						mosquitto__free(sub);
						return rc;
				}
			}

			if(qos != 0x80){
				rc2 = sub__add(db, context, sub, qos, &db->subs);
				if(rc2 == MOSQ_ERR_SUCCESS){
					if(sub__retain_queue(db, context, sub, qos)) rc = 1;
				}else if(rc2 != -1){
					rc = rc2;
				}
				log__printf(NULL, MOSQ_LOG_SUBSCRIBE, "%s %d %s", context->id, qos, sub);
			}
			mosquitto__free(sub);

			tmp_payload = mosquitto__realloc(payload, payloadlen + 1);
			if(tmp_payload){
				payload = tmp_payload;
				payload[payloadlen] = qos;
				payloadlen++;
			}else{
				mosquitto__free(payload);

				return MOSQ_ERR_NOMEM;
			}
		}
	}

	if(context->protocol == mosq_p_mqtt311){
		if(payloadlen == 0){
			/* No subscriptions specified, protocol error. */
			return MOSQ_ERR_PROTOCOL;
		}
	}
	if(send__suback(context, mid, payloadlen, payload)) rc = 1;
	mosquitto__free(payload);

#ifdef WITH_PERSISTENCE
	db->persistence_changes++;
#endif

	return rc;
}


