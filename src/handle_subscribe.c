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

#include "mqtt3_protocol.h"
#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "send_mosq.h"



int handle__subscribe(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc = 0;
	int rc2;
	uint16_t mid;
	char *sub;
	uint8_t opt, qos, no_local, retain, retain_handle;
	uint8_t *payload = NULL, *tmp_payload;
	uint32_t payloadlen = 0;
	int len;
	char *sub_mount;
	struct mosquitto_v5_property property;

	if(!context) return MOSQ_ERR_INVAL;
	log__printf(NULL, MOSQ_LOG_DEBUG, "Received SUBSCRIBE from %s", context->id);
	/* FIXME - plenty of potential for memory leaks here */

	if(context->protocol == mosq_p_mqtt5){
		memset(&property, 0, sizeof(struct mosquitto_v5_property));
	}

	if((context->protocol == mosq_p_mqtt311) || (context->protocol == mosq_p_mqtt5)){
		if((context->in_packet.command&0x0F) != 0x02){
			if(context->protocol == mosq_p_mqtt5){
				rc = MQTT5_RC_MALFORMED_PACKET;
				goto handle_subscribe_error;
			}
			return MOSQ_ERR_PROTOCOL;
		}
	}
	if(packet__read_uint16(&context->in_packet, &mid)){
		if(context->protocol == mosq_p_mqtt5){
			rc = MQTT5_RC_MALFORMED_PACKET;
			goto handle_subscribe_error;
		}
		return 1;
	}

	// Read and parse publish v5 property
	if(context->protocol == mosq_p_mqtt5){
		rc = packet__read_property(context, &context->in_packet, &property, SUBSCRIBE);
		if(rc != MQTT5_RC_SUCCESS){
			goto handle_subscribe_error;
		}
		// Subscription_identifiers is not supported.
		if(property.subscription_identifiers_count > 0){
			rc = MQTT5_RC_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED;
			goto handle_subscribe_error;
		}
	}

	while(context->in_packet.pos < context->in_packet.remaining_length){
		sub = NULL;
		if(packet__read_string(&context->in_packet, &sub)){
			mosquitto__free(payload);
			if(context->protocol == mosq_p_mqtt5){
				rc = MQTT5_RC_MALFORMED_PACKET;
				goto handle_subscribe_error;
			}
			return 1;
		}

		if(sub){
			if(STREMPTY(sub)){
				log__printf(NULL, MOSQ_LOG_INFO,
						"Empty subscription string from %s, disconnecting.",
						context->address);
				mosquitto__free(sub);
				mosquitto__free(payload);
				if(context->protocol == mosq_p_mqtt5){
					rc = MQTT5_RC_PROTOCOL_ERROR;
					goto handle_subscribe_error;
				}
				return 1;
			}
			if(mosquitto_sub_topic_check(sub)){
				log__printf(NULL, MOSQ_LOG_INFO,
						"Invalid subscription string from %s, disconnecting.",
						context->address);
				mosquitto__free(sub);
				mosquitto__free(payload);
				if(context->protocol == mosq_p_mqtt5){
					rc = MQTT5_RC_MALFORMED_PACKET;
					goto handle_subscribe_error;
				}
				return 1;
			}
			if(mosquitto_validate_utf8(sub, strlen(sub))){
				log__printf(NULL, MOSQ_LOG_INFO,
						"Malformed UTF-8 in subscription string from %s, disconnecting.",
						context->id);
				mosquitto__free(sub);
				if(context->protocol == mosq_p_mqtt5){
					rc = MQTT5_RC_MALFORMED_PACKET;
					goto handle_subscribe_error;
				}
				return 1;
			}

			if(packet__read_byte(&context->in_packet, &opt)){
				mosquitto__free(sub);
				mosquitto__free(payload);
				if(context->protocol == mosq_p_mqtt5){
					rc = MQTT5_RC_MALFORMED_PACKET;
					goto handle_subscribe_error;
				}
				return 1;
			}
			qos = opt & 0x03;
			no_local = (opt & 0x04) >> 2;
			retain = (opt & 0x08) >> 3;
			retain_handle = (opt & 0x30) >> 4;
			if(qos > 2){
				log__printf(NULL, MOSQ_LOG_INFO,
						"Invalid QoS in subscription command from %s, disconnecting.",
						context->address);
				mosquitto__free(sub);
				mosquitto__free(payload);
				if(context->protocol == mosq_p_mqtt5){
					rc = MQTT5_RC_PROTOCOL_ERROR;
					goto handle_subscribe_error;
				}
				return 1;
			}
			// V5 new options should be implimented later.
			if(context->protocol == mosq_p_mqtt5){
				if(no_local == 1){
					// Should check shared subscription later.
				}
				if(retain){
					// Dummy (Prevent warning.)
				}
				if(retain_handle > 2){
					log__printf(NULL, MOSQ_LOG_INFO,
							"Invalid Retain Handling option in subscription command from %s, disconnecting.",
							context->address);
					mosquitto__free(sub);
					mosquitto__free(payload);
					rc = MQTT5_RC_PROTOCOL_ERROR;
					goto handle_subscribe_error;
				}
				if((opt & 0xC0) != 0){
					log__printf(NULL, MOSQ_LOG_INFO,
							"Invalid reserved option in subscription command from %s, disconnecting.",
							context->address);
					mosquitto__free(sub);
					mosquitto__free(payload);
					rc = MQTT5_RC_PROTOCOL_ERROR;
					goto handle_subscribe_error;
				}
			}

			if(context->listener && context->listener->mount_point){
				len = strlen(context->listener->mount_point) + strlen(sub) + 1;
				sub_mount = mosquitto__malloc(len+1);
				if(!sub_mount){
					mosquitto__free(sub);
					mosquitto__free(payload);
					if(context->protocol == mosq_p_mqtt5){
						rc = MQTT5_RC_UNSPECIFIED_ERROR;
						goto handle_subscribe_error;
					}
					return MOSQ_ERR_NOMEM;
				}
				snprintf(sub_mount, len, "%s%s", context->listener->mount_point, sub);
				sub_mount[len] = '\0';

				mosquitto__free(sub);
				sub = sub_mount;

			}
			log__printf(NULL, MOSQ_LOG_DEBUG, "\t%s (QoS %d)", sub, qos);

			if((context->protocol == mosq_p_mqtt311) || (context->protocol == mosq_p_mqtt5)){
				rc = mosquitto_acl_check(db, context, sub, MOSQ_ACL_SUBSCRIBE);
				switch(rc){
					case MOSQ_ERR_SUCCESS:
						break;
					case MOSQ_ERR_ACL_DENIED:
						qos = 0x80;
						break;
					default:
						mosquitto__free(sub);
						if(context->protocol == mosq_p_mqtt5){
							rc = MQTT5_RC_UNSPECIFIED_ERROR;
							goto handle_subscribe_error;
						}
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

				if(context->protocol == mosq_p_mqtt5){
					rc = MQTT5_RC_UNSPECIFIED_ERROR;
					goto handle_subscribe_error;
				}
				return MOSQ_ERR_NOMEM;
			}
		}
	}

	if(context->protocol == mosq_p_mqtt311){
		if(payloadlen == 0){
			/* No subscriptions specified, protocol error. */
			if(context->protocol == mosq_p_mqtt5){
				rc = MQTT5_RC_PROTOCOL_ERROR;
				goto handle_subscribe_error;
			}
			return MOSQ_ERR_PROTOCOL;
		}
	}
	if(send__suback(context, mid, payloadlen, payload)) rc = 1;
	mosquitto__free(payload);

#ifdef WITH_PERSISTENCE
	db->persistence_changes++;
#endif

	return rc;

handle_subscribe_error:  // for v5 only
	packet__property_content_free(&property);
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



