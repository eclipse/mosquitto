/*
Copyright (c) 2010-2018 Roger Light <roger@atchoo.org>

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

#include <string.h>

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt3_protocol.h"
#include "net_mosq.h"
#include "send_mosq.h"
#include "util_mosq.h"


int mosquitto_publish(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain)
{
	struct mosquitto_message_all *message;
	uint16_t local_mid;
	int queue_status;

	if(!mosq || !topic || qos<0 || qos>2) return MOSQ_ERR_INVAL;
	if(STREMPTY(topic)) return MOSQ_ERR_INVAL;
	if(mosquitto_validate_utf8(topic, strlen(topic))) return MOSQ_ERR_MALFORMED_UTF8;
	if(payloadlen < 0 || payloadlen > MQTT_MAX_PAYLOAD) return MOSQ_ERR_PAYLOAD_SIZE;

	if(mosquitto_pub_topic_check(topic) != MOSQ_ERR_SUCCESS){
		return MOSQ_ERR_INVAL;
	}

	local_mid = mosquitto__mid_generate(mosq);
	if(mid){
		*mid = local_mid;
	}

	if(qos == 0){
		return send__publish(mosq, local_mid, topic, payloadlen, payload, qos, retain, false);
	}else{
		message = mosquitto__calloc(1, sizeof(struct mosquitto_message_all));
		if(!message) return MOSQ_ERR_NOMEM;

		message->next = NULL;
		message->timestamp = mosquitto_time();
		message->msg.mid = local_mid;
		message->msg.topic = mosquitto__strdup(topic);
		if(!message->msg.topic){
			message__cleanup(&message);
			return MOSQ_ERR_NOMEM;
		}
		if(payloadlen){
			message->msg.payloadlen = payloadlen;
			message->msg.payload = mosquitto__malloc(payloadlen*sizeof(uint8_t));
			if(!message->msg.payload){
				message__cleanup(&message);
				return MOSQ_ERR_NOMEM;
			}
			memcpy(message->msg.payload, payload, payloadlen*sizeof(uint8_t));
		}else{
			message->msg.payloadlen = 0;
			message->msg.payload = NULL;
		}
		message->msg.qos = qos;
		message->msg.retain = retain;
		message->dup = false;

		pthread_mutex_lock(&mosq->out_message_mutex);
		queue_status = message__queue(mosq, message, mosq_md_out);
		switch(queue_status){
			case 0:
				if(qos == 1){
					message->state = mosq_ms_wait_for_puback;
				}else if(qos == 2){
					message->state = mosq_ms_wait_for_pubrec;
				}
				pthread_mutex_unlock(&mosq->out_message_mutex);
				return send__publish(mosq, message->msg.mid, message->msg.topic, message->msg.payloadlen, message->msg.payload, message->msg.qos, message->msg.retain, message->dup);
			case 1:
				message->state = mosq_ms_invalid;
				pthread_mutex_unlock(&mosq->out_message_mutex);
				return MOSQ_ERR_SUCCESS;
			case 2:
				pthread_mutex_unlock(&mosq->out_message_mutex);
				message__cleanup(&message);
				return MOSQ_ERR_QUEUE_LIMIT;
		}
	}
}


int mosquitto_subscribe(struct mosquitto *mosq, int *mid, const char *sub, int qos)
{
	if(!mosq) return MOSQ_ERR_INVAL;
	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;

	if(mosquitto_sub_topic_check(sub)) return MOSQ_ERR_INVAL;
	if(mosquitto_validate_utf8(sub, strlen(sub))) return MOSQ_ERR_MALFORMED_UTF8;

	return send__subscribe(mosq, mid, sub, qos);
}


int mosquitto_unsubscribe(struct mosquitto *mosq, int *mid, const char *sub)
{
	if(!mosq) return MOSQ_ERR_INVAL;
	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;

	if(mosquitto_sub_topic_check(sub)) return MOSQ_ERR_INVAL;
	if(mosquitto_validate_utf8(sub, strlen(sub))) return MOSQ_ERR_MALFORMED_UTF8;

	return send__unsubscribe(mosq, mid, sub);
}

