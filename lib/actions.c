/*
Copyright (c) 2010-2020 Roger Light <roger@atchoo.org>

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

#include <string.h>

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "send_mosq.h"
#include "util_mosq.h"


int mosquitto_publish(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain)
{
	return mosquitto_publish_v5(mosq, mid, topic, payloadlen, payload, qos, retain, NULL);
}

int mosquitto_publish_v5(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain, const mosquitto_property *properties)
{
	struct mosquitto_message_all *message;
	uint16_t local_mid;
	const mosquitto_property *p;
	const mosquitto_property *outgoing_properties = NULL;
	mosquitto_property *properties_copy = NULL;
	mosquitto_property local_property;
	bool have_topic_alias;
	int rc;
	size_t tlen = 0;
	uint32_t remaining_length;

	if(!mosq || qos<0 || qos>2) return MOSQ_ERR_INVAL;
	if(mosq->protocol != mosq_p_mqtt5 && properties) return MOSQ_ERR_NOT_SUPPORTED;
	if(qos > mosq->max_qos) return MOSQ_ERR_QOS_NOT_SUPPORTED;

	if(!mosq->retain_available){
		retain = false;
	}

	if(properties){
		if(properties->client_generated){
			outgoing_properties = properties;
		}else{
			memcpy(&local_property, properties, sizeof(mosquitto_property));
			local_property.client_generated = true;
			local_property.next = NULL;
			outgoing_properties = &local_property;
		}
		rc = mosquitto_property_check_all(CMD_PUBLISH, outgoing_properties);
		if(rc) return rc;
	}

	if(!topic || STREMPTY(topic)){
		if(topic) topic = NULL;

		if(mosq->protocol == mosq_p_mqtt5){
			p = outgoing_properties;
			have_topic_alias = false;
			while(p){
				if(p->identifier == MQTT_PROP_TOPIC_ALIAS){
					have_topic_alias = true;
					break;
				}
				p = p->next;
			}
			if(have_topic_alias == false){
				return MOSQ_ERR_INVAL;
			}
		}else{
			return MOSQ_ERR_INVAL;
		}
	}else{
		tlen = strlen(topic);
		if(mosquitto_validate_utf8(topic, (int)tlen)) return MOSQ_ERR_MALFORMED_UTF8;
		if(payloadlen < 0 || payloadlen > MQTT_MAX_PAYLOAD) return MOSQ_ERR_PAYLOAD_SIZE;
		if(mosquitto_pub_topic_check(topic) != MOSQ_ERR_SUCCESS){
			return MOSQ_ERR_INVAL;
		}
	}

	if(mosq->maximum_packet_size > 0){
		remaining_length = 1 + 2+(uint32_t)tlen + (uint32_t)payloadlen + property__get_length_all(outgoing_properties);
		if(qos > 0){
			remaining_length++;
		}
		if(packet__check_oversize(mosq, remaining_length)){
			return MOSQ_ERR_OVERSIZE_PACKET;
		}
	}

	local_mid = mosquitto__mid_generate(mosq);
	if(mid){
		*mid = local_mid;
	}

	if(qos == 0){
		return send__publish(mosq, local_mid, topic, (uint32_t)payloadlen, payload, (uint8_t)qos, retain, false, outgoing_properties, NULL, 0);
	}else{
		if(outgoing_properties){
			rc = mosquitto_property_copy_all(&properties_copy, outgoing_properties);
			if(rc) return rc;
		}
		message = mosquitto__calloc(1, sizeof(struct mosquitto_message_all));
		if(!message){
			mosquitto_property_free_all(&properties_copy);
			return MOSQ_ERR_NOMEM;
		}

		message->next = NULL;
		message->timestamp = mosquitto_time();
		message->msg.mid = local_mid;
		if(topic){
			message->msg.topic = mosquitto__strdup(topic);
			if(!message->msg.topic){
				message__cleanup(&message);
				mosquitto_property_free_all(&properties_copy);
				return MOSQ_ERR_NOMEM;
			}
		}
		if(payloadlen){
			message->msg.payloadlen = payloadlen;
			message->msg.payload = mosquitto__malloc((unsigned int)payloadlen*sizeof(uint8_t));
			if(!message->msg.payload){
				message__cleanup(&message);
				mosquitto_property_free_all(&properties_copy);
				return MOSQ_ERR_NOMEM;
			}
			memcpy(message->msg.payload, payload, (uint32_t)payloadlen*sizeof(uint8_t));
		}else{
			message->msg.payloadlen = 0;
			message->msg.payload = NULL;
		}
		message->msg.qos = (uint8_t)qos;
		message->msg.retain = retain;
		message->dup = false;
		message->properties = properties_copy;

		pthread_mutex_lock(&mosq->msgs_out.mutex);
		message->state = mosq_ms_invalid;
		rc = message__queue(mosq, message, mosq_md_out);
		pthread_mutex_unlock(&mosq->msgs_out.mutex);
		return rc;
	}
}


int mosquitto_subscribe(struct mosquitto *mosq, int *mid, const char *sub, int qos)
{
	return mosquitto_subscribe_multiple(mosq, mid, 1, (char *const *const)&sub, qos, 0, NULL);
}


int mosquitto_subscribe_v5(struct mosquitto *mosq, int *mid, const char *sub, int qos, int options, const mosquitto_property *properties)
{
	return mosquitto_subscribe_multiple(mosq, mid, 1, (char *const *const)&sub, qos, options, properties);
}


int mosquitto_subscribe_multiple(struct mosquitto *mosq, int *mid, int sub_count, char *const *const sub, int qos, int options, const mosquitto_property *properties)
{
	const mosquitto_property *outgoing_properties = NULL;
	mosquitto_property local_property;
	int i;
	int rc;
	uint32_t remaining_length = 0;
	int slen;

	if(!mosq || !sub_count || !sub) return MOSQ_ERR_INVAL;
	if(mosq->protocol != mosq_p_mqtt5 && properties) return MOSQ_ERR_NOT_SUPPORTED;
	if(qos < 0 || qos > 2) return MOSQ_ERR_INVAL;
	if((options & 0x30) == 0x30 || (options & 0xC0) != 0) return MOSQ_ERR_INVAL;
	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;

	if(properties){
		if(properties->client_generated){
			outgoing_properties = properties;
		}else{
			memcpy(&local_property, properties, sizeof(mosquitto_property));
			local_property.client_generated = true;
			local_property.next = NULL;
			outgoing_properties = &local_property;
		}
		rc = mosquitto_property_check_all(CMD_SUBSCRIBE, outgoing_properties);
		if(rc) return rc;
	}

	for(i=0; i<sub_count; i++){
		if(mosquitto_sub_topic_check(sub[i])) return MOSQ_ERR_INVAL;
		slen = (int)strlen(sub[i]);
		if(mosquitto_validate_utf8(sub[i], slen)) return MOSQ_ERR_MALFORMED_UTF8;
		remaining_length += 2+(uint32_t)slen + 1;
	}

	if(mosq->maximum_packet_size > 0){
		remaining_length += 2 + property__get_length_all(outgoing_properties);
		if(packet__check_oversize(mosq, remaining_length)){
			return MOSQ_ERR_OVERSIZE_PACKET;
		}
	}
	if(mosq->protocol == mosq_p_mqtt311 || mosq->protocol == mosq_p_mqtt31){
		options = 0;
	}

	return send__subscribe(mosq, mid, sub_count, sub, qos|options, outgoing_properties);
}


int mosquitto_unsubscribe(struct mosquitto *mosq, int *mid, const char *sub)
{
	return mosquitto_unsubscribe_multiple(mosq, mid, 1, (char *const *const)&sub, NULL);
}

int mosquitto_unsubscribe_v5(struct mosquitto *mosq, int *mid, const char *sub, const mosquitto_property *properties)
{
	return mosquitto_unsubscribe_multiple(mosq, mid, 1, (char *const *const)&sub, properties);
}

int mosquitto_unsubscribe_multiple(struct mosquitto *mosq, int *mid, int sub_count, char *const *const sub, const mosquitto_property *properties)
{
	const mosquitto_property *outgoing_properties = NULL;
	mosquitto_property local_property;
	int rc;
	int i;
	uint32_t remaining_length = 0;
	int slen;

	if(!mosq) return MOSQ_ERR_INVAL;
	if(mosq->protocol != mosq_p_mqtt5 && properties) return MOSQ_ERR_NOT_SUPPORTED;
	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;

	if(properties){
		if(properties->client_generated){
			outgoing_properties = properties;
		}else{
			memcpy(&local_property, properties, sizeof(mosquitto_property));
			local_property.client_generated = true;
			local_property.next = NULL;
			outgoing_properties = &local_property;
		}
		rc = mosquitto_property_check_all(CMD_UNSUBSCRIBE, outgoing_properties);
		if(rc) return rc;
	}

	for(i=0; i<sub_count; i++){
		if(mosquitto_sub_topic_check(sub[i])) return MOSQ_ERR_INVAL;
		slen = (int)strlen(sub[i]);
		if(mosquitto_validate_utf8(sub[i], slen)) return MOSQ_ERR_MALFORMED_UTF8;
		remaining_length += 2U + (uint32_t)slen;
	}

	if(mosq->maximum_packet_size > 0){
		remaining_length += 2U + property__get_length_all(outgoing_properties);
		if(packet__check_oversize(mosq, remaining_length)){
			return MOSQ_ERR_OVERSIZE_PACKET;
		}
	}

	return send__unsubscribe(mosq, mid, sub_count, sub, outgoing_properties);
}

