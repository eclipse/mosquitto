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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "mosquitto_broker_internal.h"
#include "alias_mosq.h"
#include "mqtt_protocol.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "sys_tree.h"
#include "util_mosq.h"


int handle__publish(struct mosquitto_db *db, struct mosquitto *context)
{
	char *topic;
	mosquitto__payload_uhpa payload;
	uint32_t payloadlen;
	uint8_t dup, qos, retain;
	uint16_t mid = 0;
	int rc = 0;
	int rc2;
	uint8_t header = context->in_packet.command;
	int res = 0;
	struct mosquitto_msg_store *stored = NULL;
	int len;
	int slen;
	char *topic_mount;
	mosquitto_property *properties = NULL;
	mosquitto_property *p, *p_prev;
	mosquitto_property *msg_properties = NULL, *msg_properties_last;
	uint32_t message_expiry_interval = 0;
	int topic_alias = -1;
	uint8_t reason_code = 0;

#ifdef WITH_BRIDGE
	char *topic_temp;
	int i;
	struct mosquitto__bridge_topic *cur_topic;
	bool match;
#endif

	if(context->state != mosq_cs_active){
		return MOSQ_ERR_PROTOCOL;
	}

	payload.ptr = NULL;

	dup = (header & 0x08)>>3;
	qos = (header & 0x06)>>1;
	if(qos == 3){
		log__printf(NULL, MOSQ_LOG_INFO,
				"Invalid QoS in PUBLISH from %s, disconnecting.", context->id);
		return 1;
	}
	if(qos > context->maximum_qos){
		log__printf(NULL, MOSQ_LOG_INFO,
				"Too high QoS in PUBLISH from %s, disconnecting.", context->id);
		return 1;
	}
	retain = (header & 0x01);

	if(retain && db->config->retain_available == false){
		if(context->protocol == mosq_p_mqtt5){
			send__disconnect(context, MQTT_RC_RETAIN_NOT_SUPPORTED, NULL);
		}
		return 1;
	}

	if(packet__read_string(&context->in_packet, &topic, &slen)) return 1;
	if(!slen && context->protocol != mosq_p_mqtt5){
		/* Invalid publish topic, disconnect client. */
		mosquitto__free(topic);
		return 1;
	}

	if(qos > 0){
		if(packet__read_uint16(&context->in_packet, &mid)){
			mosquitto__free(topic);
			return 1;
		}
		if(mid == 0){
			mosquitto__free(topic);
			return MOSQ_ERR_PROTOCOL;
		}
	}

	/* Handle properties */
	if(context->protocol == mosq_p_mqtt5){
		rc = property__read_all(CMD_PUBLISH, &context->in_packet, &properties);
		if(rc){
			mosquitto__free(topic);
			return rc;
		}

		p = properties;
		p_prev = NULL;
		msg_properties = NULL;
		msg_properties_last = NULL;
		while(p){
			switch(p->identifier){
				case MQTT_PROP_CONTENT_TYPE:
				case MQTT_PROP_CORRELATION_DATA:
				case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
				case MQTT_PROP_RESPONSE_TOPIC:
				case MQTT_PROP_USER_PROPERTY:
					if(msg_properties){
						msg_properties_last->next = p;
						msg_properties_last = p;
					}else{
						msg_properties = p;
						msg_properties_last = p;
					}
					if(p_prev){
						p_prev->next = p->next;
						p = p_prev->next;
					}else{
						properties = p->next;
						p = properties;
					}
					msg_properties_last->next = NULL;
					break;

				case MQTT_PROP_TOPIC_ALIAS:
					topic_alias = p->value.i16;
					p_prev = p;
					p = p->next;
					break;

				case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
					message_expiry_interval = p->value.i32;
					p_prev = p;
					p = p->next;
					break;

				case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
					p_prev = p;
					p = p->next;
					break;

				default:
					p = p->next;
					break;
			}
		}
	}
	mosquitto_property_free_all(&properties);

	if(topic_alias == 0 || (context->listener && topic_alias > context->listener->max_topic_alias)){
		mosquitto__free(topic);
		send__disconnect(context, MQTT_RC_TOPIC_ALIAS_INVALID, NULL);
		return MOSQ_ERR_PROTOCOL;
	}else if(topic_alias > 0){
		if(topic){
			rc = alias__add(context, topic, topic_alias);
			if(rc){
				mosquitto__free(topic);
				return rc;
			}
		}else{
			rc = alias__find(context, &topic, topic_alias);
			if(rc){
				send__disconnect(context, MQTT_RC_TOPIC_ALIAS_INVALID, NULL);
				mosquitto__free(topic);
				return rc;
			}
		}
	}
	if(mosquitto_validate_utf8(topic, slen) != MOSQ_ERR_SUCCESS){
		log__printf(NULL, MOSQ_LOG_INFO, "Client %s sent topic with invalid UTF-8, disconnecting.", context->id);
		mosquitto__free(topic);
		return 1;
	}

#ifdef WITH_BRIDGE
	if(context->bridge && context->bridge->topics && context->bridge->topic_remapping){
		for(i=0; i<context->bridge->topic_count; i++){
			cur_topic = &context->bridge->topics[i];
			if((cur_topic->direction == bd_both || cur_topic->direction == bd_in)
					&& (cur_topic->remote_prefix || cur_topic->local_prefix)){

				/* Topic mapping required on this topic if the message matches */

				rc = mosquitto_topic_matches_sub(cur_topic->remote_topic, topic, &match);
				if(rc){
					mosquitto__free(topic);
					return rc;
				}
				if(match){
					if(cur_topic->remote_prefix){
						/* This prefix needs removing. */
						if(!strncmp(cur_topic->remote_prefix, topic, strlen(cur_topic->remote_prefix))){
							topic_temp = mosquitto__strdup(topic+strlen(cur_topic->remote_prefix));
							if(!topic_temp){
								mosquitto__free(topic);
								return MOSQ_ERR_NOMEM;
							}
							mosquitto__free(topic);
							topic = topic_temp;
						}
					}

					if(cur_topic->local_prefix){
						/* This prefix needs adding. */
						len = strlen(topic) + strlen(cur_topic->local_prefix)+1;
						topic_temp = mosquitto__malloc(len+1);
						if(!topic_temp){
							mosquitto__free(topic);
							return MOSQ_ERR_NOMEM;
						}
						snprintf(topic_temp, len, "%s%s", cur_topic->local_prefix, topic);
						topic_temp[len] = '\0';

						mosquitto__free(topic);
						topic = topic_temp;
					}
					break;
				}
			}
		}
	}
#endif
	if(mosquitto_pub_topic_check(topic) != MOSQ_ERR_SUCCESS){
		/* Invalid publish topic, just swallow it. */
		mosquitto__free(topic);
		return 1;
	}

	payloadlen = context->in_packet.remaining_length - context->in_packet.pos;
	G_PUB_BYTES_RECEIVED_INC(payloadlen);
	if(context->listener && context->listener->mount_point){
		len = strlen(context->listener->mount_point) + strlen(topic) + 1;
		topic_mount = mosquitto__malloc(len+1);
		if(!topic_mount){
			mosquitto__free(topic);
			mosquitto_property_free_all(&msg_properties);
			return MOSQ_ERR_NOMEM;
		}
		snprintf(topic_mount, len, "%s%s", context->listener->mount_point, topic);
		topic_mount[len] = '\0';

		mosquitto__free(topic);
		topic = topic_mount;
	}

	if(payloadlen){
		if(db->config->message_size_limit && payloadlen > db->config->message_size_limit){
			log__printf(NULL, MOSQ_LOG_DEBUG, "Dropped too large PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, qos, retain, mid, topic, (long)payloadlen);
			reason_code = MQTT_RC_IMPLEMENTATION_SPECIFIC;
			goto process_bad_message;
		}
		if(UHPA_ALLOC(payload, payloadlen) == 0){
			mosquitto__free(topic);
			mosquitto_property_free_all(&msg_properties);
			return MOSQ_ERR_NOMEM;
		}

		if(packet__read_bytes(&context->in_packet, UHPA_ACCESS(payload, payloadlen), payloadlen)){
			mosquitto__free(topic);
			UHPA_FREE(payload, payloadlen);
			mosquitto_property_free_all(&msg_properties);
			return 1;
		}
	}

	/* Check for topic access */
	rc = mosquitto_acl_check(db, context, topic, payloadlen, UHPA_ACCESS(payload, payloadlen), qos, retain, MOSQ_ACL_WRITE);
	if(rc == MOSQ_ERR_ACL_DENIED){
		log__printf(NULL, MOSQ_LOG_DEBUG, "Denied PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, qos, retain, mid, topic, (long)payloadlen);
			reason_code = MQTT_RC_NOT_AUTHORIZED;
		goto process_bad_message;
	}else if(rc != MOSQ_ERR_SUCCESS){
		mosquitto__free(topic);
		UHPA_FREE(payload, payloadlen);
		mosquitto_property_free_all(&msg_properties);
		return rc;
	}

	/* Check if demand concern bridge dynamic */
	if(db->config->allow_sys_update){
		rc = bridge__dynamic_analyse(db, topic, UHPA_ACCESS(payload, payloadlen), payloadlen);
		if(rc == MOSQ_ERR_BRIDGE_DYNA ){
			log__printf(NULL, MOSQ_LOG_DEBUG, "PUBLISH Invalid bridge dynamic configuration.");
			rc = 0; /* To not disturbe normal publish management */
		}
	}

	log__printf(NULL, MOSQ_LOG_DEBUG, "Received PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, qos, retain, mid, topic, (long)payloadlen);
	if(qos > 0){
		db__message_store_find(context, mid, &stored);
	}
	if(!stored){
		if(qos == 0
				|| db__ready_for_flight(&context->msgs_in, qos)
				|| db__ready_for_queue(context, qos, &context->msgs_in)){

			dup = 0;
			if(db__message_store(db, context, mid, topic, qos, payloadlen, &payload, retain, &stored, message_expiry_interval, msg_properties, 0, mosq_mo_client)){
				mosquitto_property_free_all(&msg_properties);
				return 1;
			}
			msg_properties = NULL; /* Now belongs to db__message_store() */
		}else{
			/* Client isn't allowed any more incoming messages, so fail early */
			reason_code = MQTT_RC_QUOTA_EXCEEDED;
			goto process_bad_message;
		}
	}else{
		mosquitto__free(topic);
		topic = stored->topic;
		dup = 1;
		mosquitto_property_free_all(&msg_properties);
		UHPA_FREE(payload, payloadlen);
	}

	switch(qos){
		case 0:
			rc2 = sub__messages_queue(db, context->id, topic, qos, retain, &stored);
			if(rc2 > 0) rc = 1;
			break;
		case 1:
			util__decrement_receive_quota(context);
			rc2 = sub__messages_queue(db, context->id, topic, qos, retain, &stored);
			if(rc2 == MOSQ_ERR_SUCCESS || context->protocol != mosq_p_mqtt5){
				if(send__puback(context, mid, 0)) rc = 1;
			}else if(rc2 == MOSQ_ERR_NO_SUBSCRIBERS){
				if(send__puback(context, mid, MQTT_RC_NO_MATCHING_SUBSCRIBERS)) rc = 1;
			}else{
				rc = rc2;
			}
			break;
		case 2:
			if(dup == 0){
				res = db__message_insert(db, context, mid, mosq_md_in, qos, retain, stored, NULL);
			}else{
				res = 0;
			}
			/* db__message_insert() returns 2 to indicate dropped message
			 * due to queue. This isn't an error so don't disconnect them. */
			/* FIXME - this is no longer necessary due to failing early above */
			if(!res){
				if(send__pubrec(context, mid, 0)) rc = 1;
			}else if(res == 1){
				rc = 1;
			}
			break;
	}

	return rc;
process_bad_message:
	mosquitto__free(topic);
	UHPA_FREE(payload, payloadlen);
	switch(qos){
		case 0:
			return MOSQ_ERR_SUCCESS;
		case 1:
			return send__puback(context, mid, reason_code);
		case 2:
			if(context->protocol == mosq_p_mqtt5){
				return send__pubrec(context, mid, reason_code);
			}else{
				return send__pubrec(context, mid, 0);
			}
	}
	return 1;
}
