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

#include <stdio.h>
#include <string.h>

#include "mosquitto_broker_internal.h"
#include "alias_mosq.h"
#include "mosquitto/mqtt_protocol.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "sys_tree.h"
#include "util_mosq.h"


static int process_bad_message(struct mosquitto *context, struct mosquitto__base_msg *base_msg, uint8_t reason_code)
{
	int rc = MOSQ_ERR_UNKNOWN;
	if(base_msg){
		switch(base_msg->data.qos){
			case 0:
				rc = MOSQ_ERR_SUCCESS;
				break;
			case 1:
				if(context){
					rc = send__puback(context, base_msg->data.source_mid, reason_code, NULL);
				}else{
					rc = MOSQ_ERR_SUCCESS;
				}
				break;
			case 2:
				if(context){
					rc = send__pubrec(context, base_msg->data.source_mid, reason_code, NULL);
				}else{
					rc = MOSQ_ERR_SUCCESS;
				}
				break;
		}
		db__msg_store_free(base_msg);
	}
	if(context && db.config->max_queued_messages > 0 && context->out_packet_count >= db.config->max_queued_messages){
		rc = MQTT_RC_QUOTA_EXCEEDED;
	}
	return rc;
}


int handle__accepted_publish(struct mosquitto *context, struct mosquitto__base_msg *base_msg, uint16_t mid, int dup, uint32_t *message_expiry_interval)
{
	int rc;
	int rc2;
	struct mosquitto__base_msg *stored = NULL;
	struct mosquitto__client_msg *cmsg_stored = NULL;

	{
		rc = plugin__handle_message_in(context, &base_msg->data);
		if(rc == MOSQ_ERR_ACL_DENIED){
			log__printf(NULL, MOSQ_LOG_DEBUG,
					"Denied PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))",
					context->id, dup, base_msg->data.qos, base_msg->data.retain, base_msg->data.source_mid, base_msg->data.topic,
					(long)base_msg->data.payloadlen);

			return process_bad_message(context, base_msg, MQTT_RC_NOT_AUTHORIZED);
		}else if(rc == MOSQ_ERR_QUOTA_EXCEEDED){
			log__printf(NULL, MOSQ_LOG_DEBUG,
					"Rejected PUBLISH from %s, quota exceeded.", context->id);

			return process_bad_message(context, base_msg, MQTT_RC_QUOTA_EXCEEDED);
		}else if(rc != MOSQ_ERR_SUCCESS){
			db__msg_store_free(base_msg);
			return rc;
		}
	}

	if(base_msg->data.qos > 0){
		db__message_store_find(context, base_msg->data.source_mid, &cmsg_stored);
	}

	if(cmsg_stored && base_msg->data.source_mid != 0 &&
			(cmsg_stored->base_msg->data.qos != base_msg->data.qos
			|| cmsg_stored->base_msg->data.payloadlen != base_msg->data.payloadlen
			|| strcmp(cmsg_stored->base_msg->data.topic, base_msg->data.topic)
			|| (base_msg->data.payloadlen > 0 && memcmp(cmsg_stored->base_msg->data.payload, base_msg->data.payload, base_msg->data.payloadlen)))){

		log__printf(NULL, MOSQ_LOG_WARNING, "Reused message ID %u from %s detected. Clearing from storage.", base_msg->data.source_mid, context->id);
		db__message_remove_incoming(context, base_msg->data.source_mid);
		cmsg_stored = NULL;
	}

	if(!cmsg_stored){
		if(base_msg->data.qos > 0 && context->msgs_in.inflight_maximum != 0 && context->msgs_in.inflight_quota == 0){
			log__printf(NULL, MOSQ_LOG_WARNING, "Client %s has exceeded its receive-maximum quota. This behaviour must be fixed on the client.", context->id);
#if 0
			/* Badly behaving clients like on the esp32 fall foul of this
			 * check, so report it for now but don't disconnect, to give chance
			 * for the bad behaviour to be fixed. */
			/* Client isn't allowed any more incoming messages, so fail early */
			db__msg_store_free(base_msg);
			return MOSQ_ERR_RECEIVE_MAXIMUM_EXCEEDED;
#endif
		}

		if(base_msg->data.qos == 0
				|| db__ready_for_flight(context, mosq_md_in, base_msg->data.qos)
				){

			dup = 0;
			rc = db__message_store(context, base_msg, message_expiry_interval, mosq_mo_client);
			if(rc){
				return rc;
			}
		}else{
			/* Client isn't allowed any more incoming messages, so fail early */
			return process_bad_message(context, base_msg, MQTT_RC_QUOTA_EXCEEDED);
		}
		stored = base_msg;
		base_msg = NULL;
		dup = 0;
	}else{
		db__msg_store_free(base_msg);
		base_msg = NULL;
		stored = cmsg_stored->base_msg;
		cmsg_stored->data.dup++;
		dup = cmsg_stored->data.dup;
	}

	switch(stored->data.qos){
		case 0:
			rc2 = sub__messages_queue(context->id, stored->data.qos, &stored);
			if(rc2 > 0){
				rc = rc2;
			}
			break;
		case 1:
			util__decrement_receive_quota(context);
			rc2 = sub__messages_queue(context->id, stored->data.qos, &stored);
			/* stored may now be free, so don't refer to it */
			if(rc2 == MOSQ_ERR_SUCCESS || context->protocol != mosq_p_mqtt5){
				rc2 = send__puback(context, mid, 0, NULL);
				if(rc2){
					rc = rc2;
				}
			}else if(rc2 == MOSQ_ERR_NO_SUBSCRIBERS){
				rc2 = send__puback(context, mid, MQTT_RC_NO_MATCHING_SUBSCRIBERS, NULL);
				if(rc2){
					rc = rc2;
				}
			}else{
				rc = rc2;
			}
			break;
		case 2:
			{
				int res;
				if(dup == 0){
					res = db__message_insert_incoming(context, 0, stored, true);
				}else{
					res = 0;
				}

				/* db__message_insert() returns 2 to indicate dropped message
				 * due to queue. This isn't an error so don't disconnect them. */
				/* FIXME - this is no longer necessary due to failing early above */
				if(!res){
					if(dup == 0 || dup == 1){
						rc2 = send__pubrec(context, stored->data.source_mid, 0, NULL);
						if(rc2){
							rc = rc2;
						}
					}else{
						log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s: PUBLISH with dup = %d.", context->id, dup);
						return MOSQ_ERR_PROTOCOL;
					}
				}else{
					rc = res;
				}
				break;
			}
	}

	db__message_write_queued_in(context);
	return rc;
}


int handle__publish(struct mosquitto *context)
{
	uint8_t dup;
	int rc = 0;
	uint8_t header = context->in_packet.command;
	struct mosquitto__base_msg *base_msg;
	size_t len;
	uint16_t slen;
	char *topic_mount;
	mosquitto_property *properties = NULL;
	uint32_t message_expiry_interval = MSG_EXPIRY_INFINITE;
	int topic_alias = -1;
	uint16_t mid = 0;

	if(context->state != mosq_cs_active){
		log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s: PUBLISH before session is active.", context->id);
		return MOSQ_ERR_PROTOCOL;
	}

	context->stats.messages_received++;

	base_msg = mosquitto_calloc(1, sizeof(struct mosquitto__base_msg));
	if(base_msg == NULL){
		return MOSQ_ERR_NOMEM;
	}

	dup = (header & 0x08)>>3;
	base_msg->data.qos = (header & 0x06)>>1;
	if(dup == 1 && base_msg->data.qos == 0){
		log__printf(NULL, MOSQ_LOG_INFO,
				"Invalid PUBLISH (QoS=0 and DUP=1) from %s, disconnecting.", context->id);
		db__msg_store_free(base_msg);
		return MOSQ_ERR_MALFORMED_PACKET;
	}
	if(base_msg->data.qos == 3){
		log__printf(NULL, MOSQ_LOG_INFO,
				"Invalid QoS in PUBLISH from %s, disconnecting.", context->id);
		db__msg_store_free(base_msg);
		return MOSQ_ERR_MALFORMED_PACKET;
	}
	if(base_msg->data.qos > context->max_qos){
		log__printf(NULL, MOSQ_LOG_INFO,
				"Too high QoS in PUBLISH from %s, disconnecting.", context->id);
		db__msg_store_free(base_msg);
		return MOSQ_ERR_QOS_NOT_SUPPORTED;
	}
	base_msg->data.retain = (header & 0x01);

	if(base_msg->data.retain && db.config->retain_available == false){
		db__msg_store_free(base_msg);
		return MOSQ_ERR_RETAIN_NOT_SUPPORTED;
	}

	if(packet__read_string(&context->in_packet, &base_msg->data.topic, &slen)){
		db__msg_store_free(base_msg);
		return MOSQ_ERR_MALFORMED_PACKET;
	}
	if(!slen && context->protocol != mosq_p_mqtt5){
		/* Invalid publish topic, disconnect client. */
		db__msg_store_free(base_msg);
		return MOSQ_ERR_MALFORMED_PACKET;
	}

	if(base_msg->data.qos > 0){
		if(packet__read_uint16(&context->in_packet, &mid)){
			db__msg_store_free(base_msg);
			return MOSQ_ERR_MALFORMED_PACKET;
		}
		if(mid == 0){
			db__msg_store_free(base_msg);
			log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s: PUBLISH packet with mid = 0.", context->id);
			return MOSQ_ERR_PROTOCOL;
		}
		/* It is important to have a separate copy of mid, because msg may be
		 * freed before we want to send a PUBACK/PUBREC. */
		base_msg->data.source_mid = mid;
	}

	/* Handle properties */
	if(context->protocol == mosq_p_mqtt5){
		rc = property__read_all(CMD_PUBLISH, &context->in_packet, &properties);
		if(rc){
			db__msg_store_free(base_msg);
			return rc;
		}

		rc = property__process_publish(base_msg, &properties, &topic_alias, &message_expiry_interval, context->bridge);
		if(rc){
			mosquitto_property_free_all(&properties);
			db__msg_store_free(base_msg);
			return MOSQ_ERR_PROTOCOL;
		}
	}
	mosquitto_property_free_all(&properties);

	if(topic_alias == 0 || (context->listener && topic_alias > context->listener->max_topic_alias)){
		db__msg_store_free(base_msg);
		return MOSQ_ERR_TOPIC_ALIAS_INVALID;
	}else if(topic_alias > 0){
		if(base_msg->data.topic){
			rc = alias__add_r2l(context, base_msg->data.topic, (uint16_t)topic_alias);
			if(rc){
				db__msg_store_free(base_msg);
				return rc;
			}
		}else{
			rc = alias__find_by_alias(context, ALIAS_DIR_R2L, (uint16_t)topic_alias, &base_msg->data.topic);
			if(rc){
				db__msg_store_free(base_msg);
				log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s: PUBLISH invalid topic alias (%d).",
						context->id, topic_alias);
				return MOSQ_ERR_PROTOCOL;
			}
		}
	}

#ifdef WITH_BRIDGE
	rc = bridge__remap_topic_in(context, &base_msg->data.topic);
	if(rc){
		db__msg_store_free(base_msg);
		return rc;
	}

#endif
	if(mosquitto_pub_topic_check(base_msg->data.topic) != MOSQ_ERR_SUCCESS){
		/* Invalid publish topic, just swallow it. */
		db__msg_store_free(base_msg);
		return MOSQ_ERR_MALFORMED_PACKET;
	}

	base_msg->data.payloadlen = context->in_packet.remaining_length - context->in_packet.pos;
	metrics__int_inc(mosq_counter_pub_bytes_received, base_msg->data.payloadlen);
	if(context->listener && context->listener->mount_point){
		len = strlen(context->listener->mount_point) + strlen(base_msg->data.topic) + 1;
		topic_mount = mosquitto_malloc(len+1);
		if(!topic_mount){
			db__msg_store_free(base_msg);
			return MOSQ_ERR_NOMEM;
		}
		snprintf(topic_mount, len, "%s%s", context->listener->mount_point, base_msg->data.topic);
		topic_mount[len] = '\0';

		mosquitto_FREE(base_msg->data.topic);
		base_msg->data.topic = topic_mount;
	}

	if(base_msg->data.payloadlen){
		if(db.config->message_size_limit && base_msg->data.payloadlen > db.config->message_size_limit){
			log__printf(NULL, MOSQ_LOG_DEBUG, "Dropped too large PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, base_msg->data.qos, base_msg->data.retain, base_msg->data.source_mid, base_msg->data.topic, (long)base_msg->data.payloadlen);
			return process_bad_message(context, base_msg, MQTT_RC_PACKET_TOO_LARGE);
		}
		base_msg->data.payload = mosquitto_malloc(base_msg->data.payloadlen+1);
		if(base_msg->data.payload == NULL){
			db__msg_store_free(base_msg);
			return MOSQ_ERR_NOMEM;
		}
		/* Ensure payload is always zero terminated, this is the reason for the extra byte above */
		((uint8_t *)base_msg->data.payload)[base_msg->data.payloadlen] = 0;

		if(packet__read_bytes(&context->in_packet, base_msg->data.payload, base_msg->data.payloadlen)){
			db__msg_store_free(base_msg);
			return MOSQ_ERR_MALFORMED_PACKET;
		}
	}

	/* Check for topic access */
	rc = mosquitto_acl_check(context,
			base_msg->data.topic, base_msg->data.payloadlen, base_msg->data.payload,
			base_msg->data.qos, base_msg->data.retain, base_msg->data.properties,
			MOSQ_ACL_WRITE);
	if(rc == MOSQ_ERR_ACL_DENIED){
		log__printf(NULL, MOSQ_LOG_DEBUG,
				"Denied PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))",
				context->id, dup, base_msg->data.qos, base_msg->data.retain, base_msg->data.source_mid, base_msg->data.topic,
				(long)base_msg->data.payloadlen);
		return process_bad_message(context, base_msg, MQTT_RC_NOT_AUTHORIZED);
	}else if(rc != MOSQ_ERR_SUCCESS){
		db__msg_store_free(base_msg);
		return rc;
	}

	log__printf(NULL, MOSQ_LOG_DEBUG, "Received PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, base_msg->data.qos, base_msg->data.retain, base_msg->data.source_mid, base_msg->data.topic, (long)base_msg->data.payloadlen);

	if(!strncmp(base_msg->data.topic, "$CONTROL/", 9)){
#ifdef WITH_CONTROL
		rc = control__process(context, base_msg);
		db__msg_store_free(base_msg);
		return rc;
#else
		return process_bad_message(context, base_msg, MQTT_RC_IMPLEMENTATION_SPECIFIC);
#endif
	}

	return handle__accepted_publish(context, base_msg, mid, dup, &message_expiry_interval);
}
