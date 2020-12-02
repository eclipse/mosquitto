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


int handle__publish(struct mosquitto *context)
{
	uint8_t dup;
	int rc = 0;
	int rc2;
	uint8_t header = context->in_packet.command;
	int res = 0;
	struct mosquitto_msg_store *msg, *stored = NULL;
	size_t len;
	uint16_t slen;
	char *topic_mount;
	mosquitto_property *properties = NULL;
	mosquitto_property *p, *p_prev;
	mosquitto_property *msg_properties_last;
	uint32_t message_expiry_interval = 0;
	int topic_alias = -1;
	uint8_t reason_code = 0;
	uint16_t mid = 0;

	if(context->state != mosq_cs_active){
		return MOSQ_ERR_PROTOCOL;
	}

	msg = mosquitto__calloc(1, sizeof(struct mosquitto_msg_store));
	if(msg == NULL){
		return MOSQ_ERR_NOMEM;
	}

	dup = (header & 0x08)>>3;
	msg->qos = (header & 0x06)>>1;
	if(msg->qos == 3){
		log__printf(NULL, MOSQ_LOG_INFO,
				"Invalid QoS in PUBLISH from %s, disconnecting.", context->id);
		db__msg_store_free(msg);
		return MOSQ_ERR_MALFORMED_PACKET;
	}
	if(msg->qos > context->max_qos){
		log__printf(NULL, MOSQ_LOG_INFO,
				"Too high QoS in PUBLISH from %s, disconnecting.", context->id);
		db__msg_store_free(msg);
		return MOSQ_ERR_QOS_NOT_SUPPORTED;
	}
	msg->retain = (header & 0x01);

	if(msg->retain && db.config->retain_available == false){
		db__msg_store_free(msg);
		return MOSQ_ERR_RETAIN_NOT_SUPPORTED;
	}

	if(packet__read_string(&context->in_packet, &msg->topic, &slen)){
		db__msg_store_free(msg);
		return MOSQ_ERR_MALFORMED_PACKET;
	}
	if(!slen && context->protocol != mosq_p_mqtt5){
		/* Invalid publish topic, disconnect client. */
		db__msg_store_free(msg);
		return MOSQ_ERR_MALFORMED_PACKET;
	}

	if(msg->qos > 0){
		if(packet__read_uint16(&context->in_packet, &mid)){
			db__msg_store_free(msg);
			return MOSQ_ERR_MALFORMED_PACKET;
		}
		if(mid == 0){
			db__msg_store_free(msg);
			return MOSQ_ERR_PROTOCOL;
		}
		/* It is important to have a separate copy of mid, because msg may be
		 * freed before we want to send a PUBACK/PUBREC. */
		msg->source_mid = mid;
	}

	/* Handle properties */
	if(context->protocol == mosq_p_mqtt5){
		rc = property__read_all(CMD_PUBLISH, &context->in_packet, &properties);
		if(rc){
			db__msg_store_free(msg);
			if(rc == MOSQ_ERR_PROTOCOL){
				return MOSQ_ERR_MALFORMED_PACKET;
			}else{
				return rc;
			}
		}

		p = properties;
		p_prev = NULL;
		msg->properties = NULL;
		msg_properties_last = NULL;
		while(p){
			switch(p->identifier){
				case MQTT_PROP_CONTENT_TYPE:
				case MQTT_PROP_CORRELATION_DATA:
				case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
				case MQTT_PROP_RESPONSE_TOPIC:
				case MQTT_PROP_USER_PROPERTY:
					if(msg->properties){
						msg_properties_last->next = p;
						msg_properties_last = p;
					}else{
						msg->properties = p;
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
		db__msg_store_free(msg);
		return MOSQ_ERR_TOPIC_ALIAS_INVALID;
	}else if(topic_alias > 0){
		if(msg->topic){
			rc = alias__add(context, msg->topic, (uint16_t)topic_alias);
			if(rc){
				db__msg_store_free(msg);
				return rc;
			}
		}else{
			rc = alias__find(context, &msg->topic, (uint16_t)topic_alias);
			if(rc){
				db__msg_store_free(msg);
				return MOSQ_ERR_TOPIC_ALIAS_INVALID;
			}
		}
	}

#ifdef WITH_BRIDGE
	rc = bridge__remap_topic_in(context, &msg->topic);
	if(rc){
		db__msg_store_free(msg);
		return rc;
	}

#endif
	if(mosquitto_pub_topic_check(msg->topic) != MOSQ_ERR_SUCCESS){
		/* Invalid publish topic, just swallow it. */
		db__msg_store_free(msg);
		return MOSQ_ERR_PROTOCOL;
	}

	msg->payloadlen = context->in_packet.remaining_length - context->in_packet.pos;
	G_PUB_BYTES_RECEIVED_INC(msg->payloadlen);
	if(context->listener && context->listener->mount_point){
		len = strlen(context->listener->mount_point) + strlen(msg->topic) + 1;
		topic_mount = mosquitto__malloc(len+1);
		if(!topic_mount){
			db__msg_store_free(msg);
			return MOSQ_ERR_NOMEM;
		}
		snprintf(topic_mount, len, "%s%s", context->listener->mount_point, msg->topic);
		topic_mount[len] = '\0';

		mosquitto__free(msg->topic);
		msg->topic = topic_mount;
	}

	if(msg->payloadlen){
		if(db.config->message_size_limit && msg->payloadlen > db.config->message_size_limit){
			log__printf(NULL, MOSQ_LOG_DEBUG, "Dropped too large PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, msg->qos, msg->retain, msg->source_mid, msg->topic, (long)msg->payloadlen);
			reason_code = MQTT_RC_IMPLEMENTATION_SPECIFIC;
			goto process_bad_message;
		}
		msg->payload = mosquitto__malloc(msg->payloadlen+1);
		if(msg->payload == NULL){
			db__msg_store_free(msg);
			return MOSQ_ERR_NOMEM;
		}
		/* Ensure payload is always zero terminated, this is the reason for the extra byte above */
		((uint8_t *)msg->payload)[msg->payloadlen] = 0;

		if(packet__read_bytes(&context->in_packet, msg->payload, msg->payloadlen)){
			db__msg_store_free(msg);
			return MOSQ_ERR_MALFORMED_PACKET;
		}
	}

	/* Check for topic access */
	rc = mosquitto_acl_check(context, msg->topic, msg->payloadlen, msg->payload, msg->qos, msg->retain, MOSQ_ACL_WRITE);
	if(rc == MOSQ_ERR_ACL_DENIED){
		log__printf(NULL, MOSQ_LOG_DEBUG, "Denied PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, msg->qos, msg->retain, msg->source_mid, msg->topic, (long)msg->payloadlen);
			reason_code = MQTT_RC_NOT_AUTHORIZED;
		goto process_bad_message;
	}else if(rc != MOSQ_ERR_SUCCESS){
		db__msg_store_free(msg);
		return rc;
	}

	log__printf(NULL, MOSQ_LOG_DEBUG, "Received PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, msg->qos, msg->retain, msg->source_mid, msg->topic, (long)msg->payloadlen);

	if(!strncmp(msg->topic, "$CONTROL/", 9)){
#ifdef WITH_CONTROL
		rc = control__process(context, msg);
		db__msg_store_free(msg);
		return rc;
#else
		if(msg->qos == 1){
			if (send__puback(context, msg->source_mid, MQTT_RC_SUCCESS, NULL)) {
				return MOSQ_ERR_UNKNOWN;
			}
		}else if(msg->qos == 2){
			if(send__pubrec(context, msg->source_mid, MQTT_RC_SUCCESS, NULL)){
				return MOSQ_ERR_UNKNOWN;
			}
		}
		db__msg_store_free(msg);
		return MOSQ_ERR_SUCCESS;
#endif
	}

	{
		rc = plugin__handle_message(context, msg);
		if(rc){
			db__msg_store_free(msg);
			return rc;
		}
	}

	if(msg->qos > 0){
		db__message_store_find(context, msg->source_mid, &stored);
	}
	if(!stored){
		if(msg->qos == 0
				|| db__ready_for_flight(&context->msgs_in, msg->qos)
				|| db__ready_for_queue(context, msg->qos, &context->msgs_in)){

			dup = 0;
			rc = db__message_store(context, msg, message_expiry_interval, 0, mosq_mo_client);
			if(rc) return rc;
		}else{
			/* Client isn't allowed any more incoming messages, so fail early */
			reason_code = MQTT_RC_QUOTA_EXCEEDED;
			goto process_bad_message;
		}
		stored = msg;
		msg = NULL;
	}else{
		db__msg_store_free(msg);
		msg = NULL;
		dup = 1;
	}

	switch(stored->qos){
		case 0:
			rc2 = sub__messages_queue(context->id, stored->topic, stored->qos, stored->retain, &stored);
			if(rc2 > 0) rc = 1;
			break;
		case 1:
			util__decrement_receive_quota(context);
			rc2 = sub__messages_queue(context->id, stored->topic, stored->qos, stored->retain, &stored);
			/* stored may now be free, so don't refer to it */
			if(rc2 == MOSQ_ERR_SUCCESS || context->protocol != mosq_p_mqtt5){
				if(send__puback(context, mid, 0, NULL)) rc = 1;
			}else if(rc2 == MOSQ_ERR_NO_SUBSCRIBERS){
				if(send__puback(context, mid, MQTT_RC_NO_MATCHING_SUBSCRIBERS, NULL)) rc = 1;
			}else{
				rc = rc2;
			}
			break;
		case 2:
			if(dup == 0){
				res = db__message_insert(context, stored->source_mid, mosq_md_in, stored->qos, stored->retain, stored, NULL, false);
			}else{
				res = 0;
			}
			/* db__message_insert() returns 2 to indicate dropped message
			 * due to queue. This isn't an error so don't disconnect them. */
			/* FIXME - this is no longer necessary due to failing early above */
			if(!res){
				if(send__pubrec(context, stored->source_mid, 0, NULL)) rc = 1;
			}else if(res == 1){
				rc = 1;
			}
			break;
	}

	db__message_write_queued_in(context);
	return rc;
process_bad_message:
	rc = 1;
	if(msg){
		switch(msg->qos){
			case 0:
				rc = MOSQ_ERR_SUCCESS;
				break;
			case 1:
				rc = send__puback(context, msg->source_mid, reason_code, NULL);
				break;
			case 2:
				if(context->protocol == mosq_p_mqtt5){
					rc = send__pubrec(context, msg->source_mid, reason_code, NULL);
				}else{
					rc = send__pubrec(context, msg->source_mid, 0, NULL);
				}
				break;
		}
		db__msg_store_free(msg);
	}
	return rc;
}

