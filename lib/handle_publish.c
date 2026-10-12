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

#include "alias_mosq.h"
#include "callbacks.h"
#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "logging_mosq.h"
#include "mosquitto/mqtt_protocol.h"
#include "messages_mosq.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "util_mosq.h"


static int property__process_publish(struct mosquitto *mosq, mosquitto_property *props, struct mosquitto_message_all *message, uint16_t *topic_alias)
{
	while(props){
		switch(mosquitto_property_identifier(props)){
			case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
			case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
			case MQTT_PROP_CONTENT_TYPE:
			case MQTT_PROP_RESPONSE_TOPIC: //
			case MQTT_PROP_CORRELATION_DATA:
			case MQTT_PROP_USER_PROPERTY:
				/* Allowed */
				break;

			case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
				/* Allowed */
				if(mosquitto_property_varint_value(props) == 0){
					return MOSQ_ERR_PROTOCOL;
				}
				break;

			case MQTT_PROP_TOPIC_ALIAS:
				{
					*topic_alias = mosquitto_property_int16_value(props);
					if(*topic_alias == 0 || *topic_alias > mosq->alias_max_l2r){
						return MOSQ_ERR_TOPIC_ALIAS_INVALID;
					}
					if(message->msg.topic){
						/* Set a new topic alias */
						if(alias__add_r2l(mosq, message->msg.topic, *topic_alias)){
							return MOSQ_ERR_NOMEM;
						}
					}else{
						/* Retrieve an existing topic alias */
						mosquitto_FREE(message->msg.topic);
						if(alias__find_by_alias(mosq, ALIAS_DIR_R2L, *topic_alias, &message->msg.topic)){
							return MOSQ_ERR_PROTOCOL;
						}
					}
				}
				break;

			default:
				return MOSQ_ERR_PROTOCOL;
		}
		props = mosquitto_property_next(props);
	}

	return MOSQ_ERR_SUCCESS;
}


int handle__publish(struct mosquitto *mosq)
{
	uint8_t header;
	struct mosquitto_message_all *message;
	int rc = 0;
	uint16_t mid = 0;
	uint16_t slen;
	mosquitto_property *properties = NULL;
	uint16_t topic_alias = 0;

	assert(mosq);

	if(mosquitto__get_state(mosq) != mosq_cs_active){
		return MOSQ_ERR_PROTOCOL;
	}

	message = mosquitto_calloc(1, sizeof(struct mosquitto_message_all));
	if(!message){
		return MOSQ_ERR_NOMEM;
	}

	header = mosq->in_packet.command;

	message->dup = (header & 0x08)>>3;
	message->msg.qos = (header & 0x06)>>1;
	message->msg.retain = (header & 0x01);

	rc = packet__read_string(&mosq->in_packet, &message->msg.topic, &slen);
	if(rc){
		message__cleanup(&message);
		return rc;
	}
	if(mosq->protocol != mosq_p_mqtt5 && slen == 0){
		message__cleanup(&message);
		return MOSQ_ERR_PROTOCOL;
	}

	if(message->msg.qos > 0){
		if(mosq->protocol == mosq_p_mqtt5){
			if(mosq->msgs_in.inflight_quota == 0){
				message__cleanup(&message);
				send__disconnect(mosq, MQTT_RC_RECEIVE_MAXIMUM_EXCEEDED, NULL );
				return MOSQ_ERR_RECEIVE_MAXIMUM_EXCEEDED;
			}
		}

		rc = packet__read_uint16(&mosq->in_packet, &mid);
		if(rc){
			message__cleanup(&message);
			return rc;
		}
		if(mid == 0){
			message__cleanup(&message);
			return MOSQ_ERR_PROTOCOL;
		}
		message->msg.mid = (int)mid;
	}

	if(mosq->protocol == mosq_p_mqtt5){
		rc = property__read_all(CMD_PUBLISH, &mosq->in_packet, &properties);
		if(rc){
			message__cleanup(&message);
			return rc;
		}

		rc = property__process_publish(mosq, properties, message, &topic_alias);
		if(rc){
			message__cleanup(&message);
			mosquitto_property_free_all(&properties);
			return rc;
		}
	}
	/* If we haven't got a topic at this point, it's a protocol error. */
	if(topic_alias == 0 && message->msg.topic == NULL){
		message__cleanup(&message);
		mosquitto_property_free_all(&properties);
		return MOSQ_ERR_PROTOCOL;
	}
	if(mosquitto_pub_topic_check(message->msg.topic) != MOSQ_ERR_SUCCESS){
		message__cleanup(&message);
		mosquitto_property_free_all(&properties);
		return MOSQ_ERR_MALFORMED_PACKET;
	}

	message->msg.payloadlen = (int)(mosq->in_packet.remaining_length - mosq->in_packet.pos);
	if(message->msg.payloadlen){
		message->msg.payload = mosquitto_calloc((size_t)message->msg.payloadlen+1, sizeof(uint8_t));
		if(!message->msg.payload){
			message__cleanup(&message);
			mosquitto_property_free_all(&properties);
			return MOSQ_ERR_NOMEM;
		}
		rc = packet__read_bytes(&mosq->in_packet, message->msg.payload, (uint32_t)message->msg.payloadlen);
		if(rc){
			message__cleanup(&message);
			mosquitto_property_free_all(&properties);
			return rc;
		}
	}
	log__printf(mosq, MOSQ_LOG_DEBUG,
			"Client %s received PUBLISH (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))",
			SAFE_PRINT(mosq->id), message->dup, message->msg.qos, message->msg.retain,
			message->msg.mid, message->msg.topic,
			(long)message->msg.payloadlen);

	switch(message->msg.qos){
		case 0:
			callback__on_message(mosq, &message->msg, properties);
			message__cleanup(&message);
			mosquitto_property_free_all(&properties);
			return MOSQ_ERR_SUCCESS;
		case 1:
			util__decrement_receive_quota(mosq);
			rc = send__puback(mosq, mid, 0, NULL);
			callback__on_message(mosq, &message->msg, properties);
			message__cleanup(&message);
			mosquitto_property_free_all(&properties);
			return rc;
		case 2:
			message->properties = properties;
			util__decrement_receive_quota(mosq);
			rc = send__pubrec(mosq, mid, 0, NULL);
			COMPAT_pthread_mutex_lock(&mosq->msgs_in.mutex);
			message->state = mosq_ms_wait_for_pubrel;
			message__queue(mosq, message, mosq_md_in);
			COMPAT_pthread_mutex_unlock(&mosq->msgs_in.mutex);
			return rc;
		default:
			message__cleanup(&message);
			mosquitto_property_free_all(&properties);
			return MOSQ_ERR_PROTOCOL;
	}
}

