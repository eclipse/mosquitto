/*
Copyright (c) 2009-2021 Roger Light <roger@atchoo.org>

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

#include <assert.h>
#include <string.h>

#ifdef WITH_BROKER
#  include "mosquitto_broker_internal.h"
#  include "sys_tree.h"
#else
#  define G_PUB_BYTES_SENT_INC(A)
#endif

#include "alias_mosq.h"
#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "logging_mosq.h"
#include "mqtt_protocol.h"
#include "memory_mosq.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "send_mosq.h"
#include "utlist.h"

int send__publish(struct mosquitto *mosq, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, uint8_t qos, bool retain, bool dup, uint32_t subscription_identifier, const mosquitto_property *store_props, uint32_t expiry_interval)
{
#ifdef WITH_BROKER
	size_t len;
#ifdef WITH_BRIDGE
	struct mosquitto__bridge_topic *cur_topic;
	bool match;
	int rc;
	char *mapped_topic = NULL;
	char *topic_temp = NULL;
#endif
#endif
	assert(mosq);

	if(!net__is_connected(mosq)) return MOSQ_ERR_NO_CONN;

#ifdef WITH_BROKER
	bool payload_changed = false;
	bool topic_changed = false;
	bool properties_changed = false;

	{
		struct mosquitto_base_msg tmp_msg;
		tmp_msg.topic = (char *) topic;
		tmp_msg.payloadlen = payloadlen;
		tmp_msg.payload = (void *) payload;
		tmp_msg.qos = qos;
		tmp_msg.retain = retain;
		tmp_msg.properties = (mosquitto_property *) store_props;

		rc = plugin__handle_message_out(mosq, &tmp_msg);

		if(tmp_msg.payload != payload) payload_changed = true;
		if(tmp_msg.topic != topic) topic_changed = true;
		if(tmp_msg.properties != store_props) properties_changed = true;

		topic = tmp_msg.topic;
		payloadlen = tmp_msg.payloadlen;
		payload = tmp_msg.payload;
		qos = tmp_msg.qos;
		retain = tmp_msg.retain;
		store_props = tmp_msg.properties;

		if(rc != MOSQ_ERR_SUCCESS){
			if(payload_changed) mosquitto__free((void *) payload);
			if(topic_changed) mosquitto__free((char *) topic);
			if(properties_changed) mosquitto_property_free_all((mosquitto_property **) &store_props);
			if(rc == MOSQ_ERR_ACL_DENIED){
				log__printf(NULL, MOSQ_LOG_DEBUG,
						"Denied PUBLISH to %s (q%d, r%d, '%s', ... (%ld bytes))",
						mosq->id, qos, retain, topic, (long)payloadlen);

			}else if(rc == MOSQ_ERR_QUOTA_EXCEEDED){
				log__printf(NULL, MOSQ_LOG_DEBUG,
						"Rejected PUBLISH to %s, quota exceeded.", mosq->id);
			}

			return MOSQ_ERR_SUCCESS;
		}
	}
#endif

	if(!mosq->retain_available){
		retain = false;
	}

#ifdef WITH_BROKER
	if(mosq->listener && mosq->listener->mount_point){
		len = strlen(mosq->listener->mount_point);
		if(len < strlen(topic)){
			topic += len;
		}else{
			/* Invalid topic string. Should never happen, but silently swallow the message anyway. */
			return MOSQ_ERR_SUCCESS;
		}
	}
#ifdef WITH_BRIDGE
	if(mosq->bridge && mosq->bridge->topics && mosq->bridge->topic_remapping){
		LL_FOREACH(mosq->bridge->topics, cur_topic){
			if((cur_topic->direction == bd_both || cur_topic->direction == bd_out)
					&& (cur_topic->remote_prefix || cur_topic->local_prefix)){
				/* Topic mapping required on this topic if the message matches */

				rc = mosquitto_topic_matches_sub(cur_topic->local_topic, topic, &match);
				if(rc){
					return rc;
				}
				if(match){
					mapped_topic = mosquitto__strdup(topic);
					if(!mapped_topic) return MOSQ_ERR_NOMEM;
					if(cur_topic->local_prefix){
						/* This prefix needs removing. */
						if(!strncmp(cur_topic->local_prefix, mapped_topic, strlen(cur_topic->local_prefix))){
							topic_temp = mosquitto__strdup(mapped_topic+strlen(cur_topic->local_prefix));
							mosquitto__FREE(mapped_topic);
							if(!topic_temp){
								return MOSQ_ERR_NOMEM;
							}
							mapped_topic = topic_temp;
						}
					}

					if(cur_topic->remote_prefix){
						/* This prefix needs adding. */
						len = strlen(mapped_topic) + strlen(cur_topic->remote_prefix)+1;
						topic_temp = mosquitto__malloc(len+1);
						if(!topic_temp){
							mosquitto__FREE(mapped_topic);
							return MOSQ_ERR_NOMEM;
						}
						snprintf(topic_temp, len, "%s%s", cur_topic->remote_prefix, mapped_topic);
						topic_temp[len] = '\0';
						mosquitto__FREE(mapped_topic);
						mapped_topic = topic_temp;
					}
					log__printf(mosq, MOSQ_LOG_DEBUG, "Sending PUBLISH to %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", SAFE_PRINT(mosq->id), dup, qos, retain, mid, mapped_topic, (long)payloadlen);
					G_PUB_BYTES_SENT_INC(payloadlen);
					rc =  send__real_publish(mosq, mid, mapped_topic, payloadlen, payload, qos, retain, dup, subscription_identifier, store_props, expiry_interval);
					mosquitto__FREE(mapped_topic);
					return rc;
				}
			}
		}
	}
#endif
	log__printf(mosq, MOSQ_LOG_DEBUG, "Sending PUBLISH to %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", SAFE_PRINT(mosq->id), dup, qos, retain, mid, topic, (long)payloadlen);
	G_PUB_BYTES_SENT_INC(payloadlen);
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending PUBLISH (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", SAFE_PRINT(mosq->id), dup, qos, retain, mid, topic, (long)payloadlen);
#endif

#ifdef WITH_BROKER
	rc = send__real_publish(mosq, mid, topic, payloadlen, payload, qos, retain, dup, subscription_identifier, store_props, expiry_interval);
	if(payload_changed) mosquitto__free((void *) payload);
	if(topic_changed) mosquitto__free((char *) topic);
	if(properties_changed) mosquitto_property_free_all((mosquitto_property **) &store_props);
	return rc;
#else
	return send__real_publish(mosq, mid, topic, payloadlen, payload, qos, retain, dup, subscription_identifier, store_props, expiry_interval);
#endif
}


int send__real_publish(struct mosquitto *mosq, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, uint8_t qos, bool retain, bool dup, uint32_t subscription_identifier, const mosquitto_property *store_props, uint32_t expiry_interval)
{
	struct mosquitto__packet *packet = NULL;
	unsigned int packetlen;
	unsigned int proplen = 0, varbytes;
	int rc;
	mosquitto_property expiry_prop;
#ifdef WITH_BROKER
	mosquitto_property topic_alias_prop;
	uint16_t topic_alias = 0;
	mosquitto_property subscription_id_prop;
#endif

#ifndef WITH_BROKER
	UNUSED(subscription_identifier);
#endif

	assert(mosq);

#ifdef WITH_BROKER
	if(mosq->protocol == mosq_p_mqtt5){
		if(alias__find_by_topic(mosq, ALIAS_DIR_L2R, topic, &topic_alias) == MOSQ_ERR_SUCCESS){
			/* If we have an existing alias, no need to send the topic */
			topic = NULL;
		}else{
			/* Try to add a new alias - if this succeeds, topic_alias will be
			 * set to the new alias but we still need to send the topic. If it
			 * fails, topic_alias will be set to 0. */
			alias__add_l2r(mosq, topic, &topic_alias);
		}
	}
#endif

	if(topic){
		packetlen = 2+(unsigned int)strlen(topic) + payloadlen;
	}else{
		packetlen = 2 + payloadlen;
	}
	if(qos > 0) packetlen += 2; /* For message id */
	if(mosq->protocol == mosq_p_mqtt5){
		proplen = 0;
		proplen += property__get_length_all(store_props);
		if(expiry_interval > 0){
			expiry_prop.next = NULL;
			expiry_prop.value.i32 = expiry_interval;
			expiry_prop.identifier = MQTT_PROP_MESSAGE_EXPIRY_INTERVAL;
			expiry_prop.client_generated = false;

			proplen += property__get_length_all(&expiry_prop);
		}
#ifdef WITH_BROKER
		if(topic_alias != 0){
			topic_alias_prop.next = NULL;
			topic_alias_prop.value.i16 = topic_alias;
			topic_alias_prop.identifier = MQTT_PROP_TOPIC_ALIAS;
			topic_alias_prop.client_generated = false;

			proplen += property__get_length_all(&topic_alias_prop);
		}
		if(subscription_identifier){
			subscription_id_prop.next = NULL;
			subscription_id_prop.value.varint = subscription_identifier;
			subscription_id_prop.identifier = MQTT_PROP_SUBSCRIPTION_IDENTIFIER;
			subscription_id_prop.client_generated = false;

			proplen += property__get_length_all(&subscription_id_prop);
		}
#endif

		varbytes = packet__varint_bytes(proplen);
		if(varbytes > 4){
			/* FIXME - Properties too big, don't publish any - should remove some first really */
			store_props = NULL;
			expiry_interval = 0;
		}else{
			packetlen += proplen + varbytes;
		}
	}
	if(packet__check_oversize(mosq, packetlen)){
#ifdef WITH_BROKER
		log__printf(mosq, MOSQ_LOG_NOTICE, "Dropping too large outgoing PUBLISH for %s (%d bytes)", SAFE_PRINT(mosq->id), packetlen);
#else
		log__printf(mosq, MOSQ_LOG_NOTICE, "Dropping too large outgoing PUBLISH (%d bytes)", packetlen);
#endif
		return MOSQ_ERR_OVERSIZE_PACKET;
	}

	rc = packet__alloc(&packet, (uint8_t)(CMD_PUBLISH | (uint8_t)((dup&0x1)<<3) | (uint8_t)(qos<<1) | retain), packetlen);
	if(rc){
		return rc;
	}
	packet->mid = mid;
	/* Variable header (topic string) */
	if(topic){
		packet__write_string(packet, topic, (uint16_t)strlen(topic));
	}else{
		packet__write_uint16(packet, 0);
	}
	if(qos > 0){
		packet__write_uint16(packet, mid);
	}

	if(mosq->protocol == mosq_p_mqtt5){
		packet__write_varint(packet, proplen);
		property__write_all(packet, store_props, false);
		if(expiry_interval > 0){
			property__write_all(packet, &expiry_prop, false);
		}
#ifdef WITH_BROKER
		if(topic_alias != 0){
			property__write_all(packet, &topic_alias_prop, false);
		}
		if(subscription_identifier != 0){
			property__write_all(packet, &subscription_id_prop, false);
		}
#endif
	}

	/* Payload */
	if(payloadlen && payload){
		packet__write_bytes(packet, payload, payloadlen);
	}

	return packet__queue(mosq, packet);
}
