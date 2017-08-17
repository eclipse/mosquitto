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


int handle__publish(struct mosquitto_db *db, struct mosquitto *context)
{
	char *topic;
	mosquitto__payload_uhpa payload;
	uint32_t payloadlen;
	uint8_t dup, qos, retain;
	uint16_t mid = 0;
	int rc = 0;
	uint8_t header = context->in_packet.command;
	int res = 0;
	struct mosquitto_msg_store *stored = NULL;
	int len;
	char *topic_mount;
#ifdef WITH_BRIDGE
	char *topic_temp;
	int i;
	struct mosquitto__bridge_topic *cur_topic;
	bool match;
#endif

	payload.ptr = NULL;

	int property_pos = 0;

	dup = (header & 0x08)>>3;
	qos = (header & 0x06)>>1;
	if(qos == 3){
		log__printf(NULL, MOSQ_LOG_INFO,
				"Invalid QoS in PUBLISH from %s, disconnecting.", context->id);
		return MOSQ_ERR_PROTOCOL;
	}
	retain = (header & 0x01);

	if(packet__read_string(&context->in_packet, &topic)) return MOSQ_ERR_PROTOCOL;
	if(STREMPTY(topic)){
		/* Invalid publish topic, disconnect client. */
		mosquitto__free(topic);
		/* NOTE: For v5, zero length of topic is valid for using topic alias.
		         Should be implimented later */
		return MOSQ_ERR_PROTOCOL;
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
		return MOSQ_ERR_PROTOCOL;
	}

	if(mosquitto_validate_utf8(topic, strlen(topic)) != MOSQ_ERR_SUCCESS){
		mosquitto__free(topic);
		return MOSQ_ERR_PROTOCOL;
	}

	if(qos > 0){
		if(packet__read_uint16(&context->in_packet, &mid)){
			mosquitto__free(topic);
			return MOSQ_ERR_PROTOCOL;
		}
	}

	/* Skip v5 property so far. Should be implimented in the future. */
	if(context->protocol == mosq_p_mqtt5){
		property_pos = context->in_packet.pos;
		rc = packet__read_property(context, &context->in_packet);
		if(rc != MQTT5_RC_SUCCESS){
			mosquitto__free(topic);
			return rc;
		}
	}

	payloadlen = context->in_packet.remaining_length - context->in_packet.pos;
	G_PUB_BYTES_RECEIVED_INC(payloadlen);
	if(context->listener && context->listener->mount_point){
		len = strlen(context->listener->mount_point) + strlen(topic) + 1;
		topic_mount = mosquitto__malloc(len+1);
		if(!topic_mount){
			mosquitto__free(topic);
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
			if(context->protocol == mosq_p_mqtt5){
				mosquitto__free(topic);
				return MQTT5_RC_PACKET_TOO_LARGE;
				/* For v5, no need to process_bad_message because server can send DISCONNECT. */
			}
			goto process_bad_message;
		}
	}
	/* For v5, merge property to payload in order to transfer messages. */
	if(context->protocol == mosq_p_mqtt5){
		payloadlen += context->in_packet.pos - property_pos;
		context->in_packet.pos -= context->in_packet.pos - property_pos;
	}
	if(payloadlen){
		if(UHPA_ALLOC(payload, payloadlen+1) == 0){
			mosquitto__free(topic);
			return MOSQ_ERR_NOMEM;
		}
		if(packet__read_bytes(&context->in_packet, UHPA_ACCESS(payload, payloadlen), payloadlen)){
			mosquitto__free(topic);
			UHPA_FREE(payload, payloadlen);
			return MOSQ_ERR_PROTOCOL;
		}
	}

	/* Check for topic access */
	rc = mosquitto_acl_check(db, context, topic, MOSQ_ACL_WRITE);
	if(rc == MOSQ_ERR_ACL_DENIED){
		log__printf(NULL, MOSQ_LOG_DEBUG, "Denied PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, qos, retain, mid, topic, (long)payloadlen);
		if(context->protocol == mosq_p_mqtt5){
			mosquitto__free(topic);
			UHPA_FREE(payload, payloadlen);
			return MQTT5_RC_NOT_AUTHORIZED;
			/* For v5, no need to process_bad_message because server can send DISCONNECT. */
		}
		goto process_bad_message;
	}else if(rc != MOSQ_ERR_SUCCESS){
		mosquitto__free(topic);
		UHPA_FREE(payload, payloadlen);
		return rc;
	}

	log__printf(NULL, MOSQ_LOG_DEBUG, "Received PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, qos, retain, mid, topic, (long)payloadlen);
	if(qos > 0){
		db__message_store_find(context, mid, &stored);
	}
	if(!stored){
		dup = 0;
		if(db__message_store(db, context->id, mid, topic, qos, payloadlen, &payload, retain, &stored, 0)){
			return 1;
		}
	}else{
		mosquitto__free(topic);
		topic = stored->topic;
		dup = 1;
	}

	switch(qos){
		case 0:
			if(sub__messages_queue(db, context->id, topic, qos, retain, &stored)) rc = 1;
			break;
		case 1:
			if(sub__messages_queue(db, context->id, topic, qos, retain, &stored)) rc = 1;
			if(send__puback(context, mid)) rc = 1;
			break;
		case 2:
			if(!dup){
				res = db__message_insert(db, context, mid, mosq_md_in, qos, retain, stored);
			}else{
				res = 0;
			}
			/* db__message_insert() returns 2 to indicate dropped message
			 * due to queue. This isn't an error so don't disconnect them. */
			if(!res){
				if(send__pubrec(context, mid)) rc = 1;
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
			return send__puback(context, mid);
		case 2:
			db__message_store_find(context, mid, &stored);
			if(!stored){
				if(db__message_store(db, context->id, mid, NULL, qos, 0, NULL, false, &stored, 0)){
					return 1;
				}
				res = db__message_insert(db, context, mid, mosq_md_in, qos, false, stored);
			}else{
				res = 0;
			}
			if(!res){
				res = send__pubrec(context, mid);
			}
			return res;
	}
	return 1;
}


