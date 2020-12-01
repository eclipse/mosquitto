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

#include <assert.h>
#include <string.h>

#ifdef WITH_BROKER
#  include "mosquitto_broker_internal.h"
#  include "sys_tree.h"
#else
#  define G_PUB_BYTES_SENT_INC(A)
#endif

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "logging_mosq.h"
#include "mqtt_protocol.h"
#include "memory_mosq.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "send_mosq.h"


int send__publish(struct mosquitto *mosq, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, uint8_t qos, bool retain, bool dup, const mosquitto_property *cmsg_props, const mosquitto_property *store_props, uint32_t expiry_interval)
{
#ifdef WITH_BROKER
	size_t len;
#ifdef WITH_BRIDGE
	int i;
	struct mosquitto__bridge_topic *cur_topic;
	bool match;
	int rc;
	char *mapped_topic = NULL;
	char *topic_temp = NULL;
#endif
#endif
	assert(mosq);

#if defined(WITH_BROKER) && defined(WITH_WEBSOCKETS)
	if(mosq->sock == INVALID_SOCKET && !mosq->wsi) return MOSQ_ERR_NO_CONN;
#else
	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;
#endif

	if(!mosq->retain_available){
		retain = false;
	}

#ifdef WITH_BROKER
#ifdef WITH_BRIDGE
	if(mosq->bridge && mosq->bridge->topics && mosq->bridge->topic_remapping){
		for(i=0; i<mosq->bridge->topic_count; i++){
			cur_topic = &mosq->bridge->topics[i];
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
							mosquitto__free(mapped_topic);
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
							mosquitto__free(mapped_topic);
							return MOSQ_ERR_NOMEM;
						}
						snprintf(topic_temp, len, "%s%s", cur_topic->remote_prefix, mapped_topic);
						topic_temp[len] = '\0';
						mosquitto__free(mapped_topic);
						mapped_topic = topic_temp;
					}
					log__printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBLISH to %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", mosq->id, dup, qos, retain, mid, mapped_topic, (long)payloadlen);
					G_PUB_BYTES_SENT_INC(payloadlen);
					rc =  send__real_publish(mosq, mid, mapped_topic, payloadlen, payload, qos, retain, dup, cmsg_props, store_props, expiry_interval);
					mosquitto__free(mapped_topic);
					return rc;
				}
			}
		}
	}
#endif
	log__printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBLISH to %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", mosq->id, dup, qos, retain, mid, topic, (long)payloadlen);
	G_PUB_BYTES_SENT_INC(payloadlen);
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending PUBLISH (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", mosq->id, dup, qos, retain, mid, topic, (long)payloadlen);
#endif

	return send__real_publish(mosq, mid, topic, payloadlen, payload, qos, retain, dup, cmsg_props, store_props, expiry_interval);
}


int send__real_publish(struct mosquitto *mosq, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, uint8_t qos, bool retain, bool dup, const mosquitto_property *cmsg_props, const mosquitto_property *store_props, uint32_t expiry_interval)
{
	struct mosquitto__packet *packet = NULL;
	unsigned int packetlen;
	unsigned int proplen = 0, varbytes;
	int rc;
	mosquitto_property expiry_prop;

	assert(mosq);

	if(topic){
		packetlen = 2+(unsigned int)strlen(topic) + payloadlen;
	}else{
		packetlen = 2 + payloadlen;
	}
	if(qos > 0) packetlen += 2; /* For message id */
	if(mosq->protocol == mosq_p_mqtt5){
		proplen = 0;
		proplen += property__get_length_all(cmsg_props);
		proplen += property__get_length_all(store_props);
		if(expiry_interval > 0){
			expiry_prop.next = NULL;
			expiry_prop.value.i32 = expiry_interval;
			expiry_prop.identifier = MQTT_PROP_MESSAGE_EXPIRY_INTERVAL;
			expiry_prop.client_generated = false;

			proplen += property__get_length_all(&expiry_prop);
		}

		varbytes = packet__varint_bytes(proplen);
		if(varbytes > 4){
			/* FIXME - Properties too big, don't publish any - should remove some first really */
			cmsg_props = NULL;
			store_props = NULL;
			expiry_interval = 0;
		}else{
			packetlen += proplen + varbytes;
		}
	}
	if(packet__check_oversize(mosq, packetlen)){
#ifdef WITH_BROKER
		log__printf(NULL, MOSQ_LOG_NOTICE, "Dropping too large outgoing PUBLISH for %s (%d bytes)", mosq->id, packetlen);
#else
		log__printf(NULL, MOSQ_LOG_NOTICE, "Dropping too large outgoing PUBLISH (%d bytes)", packetlen);
#endif
		return MOSQ_ERR_OVERSIZE_PACKET;
	}

	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packet->mid = mid;
	packet->command = (uint8_t)(CMD_PUBLISH | (uint8_t)((dup&0x1)<<3) | (uint8_t)(qos<<1) | retain);
	packet->remaining_length = packetlen;
	rc = packet__alloc(packet);
	if(rc){
		mosquitto__free(packet);
		return rc;
	}
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
		property__write_all(packet, cmsg_props, false);
		property__write_all(packet, store_props, false);
		if(expiry_interval > 0){
			property__write_all(packet, &expiry_prop, false);
		}
	}

	/* Payload */
	if(payloadlen){
		packet__write_bytes(packet, payload, payloadlen);
	}

	return packet__queue(mosq, packet);
}
