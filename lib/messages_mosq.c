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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <utlist.h>

#include "mosquitto_internal.h"
#include "mosquitto.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "send_mosq.h"
#include "time_mosq.h"
#include "util_mosq.h"

void message__cleanup(struct mosquitto_message_all **message)
{
	struct mosquitto_message_all *msg;

	if(!message || !*message) return;

	msg = *message;

	mosquitto__free(msg->msg.topic);
	mosquitto__free(msg->msg.payload);
	mosquitto_property_free_all(&msg->properties);
	mosquitto__free(msg);
}

void message__cleanup_all(struct mosquitto *mosq)
{
	struct mosquitto_message_all *tail, *tmp;

	assert(mosq);

	DL_FOREACH_SAFE(mosq->msgs_in.inflight, tail, tmp){
		DL_DELETE(mosq->msgs_in.inflight, tail);
		message__cleanup(&tail);
	}
	DL_FOREACH_SAFE(mosq->msgs_out.inflight, tail, tmp){
		DL_DELETE(mosq->msgs_out.inflight, tail);
		message__cleanup(&tail);
	}
}

int mosquitto_message_copy(struct mosquitto_message *dst, const struct mosquitto_message *src)
{
	if(!dst || !src) return MOSQ_ERR_INVAL;

	dst->mid = src->mid;
	dst->topic = mosquitto__strdup(src->topic);
	if(!dst->topic) return MOSQ_ERR_NOMEM;
	dst->qos = src->qos;
	dst->retain = src->retain;
	if(src->payloadlen){
		dst->payload = mosquitto__calloc((unsigned int)src->payloadlen+1, sizeof(uint8_t));
		if(!dst->payload){
			mosquitto__free(dst->topic);
			return MOSQ_ERR_NOMEM;
		}
		memcpy(dst->payload, src->payload, (unsigned int)src->payloadlen);
		dst->payloadlen = src->payloadlen;
	}else{
		dst->payloadlen = 0;
		dst->payload = NULL;
	}
	return MOSQ_ERR_SUCCESS;
}

int message__delete(struct mosquitto *mosq, uint16_t mid, enum mosquitto_msg_direction dir, int qos)
{
	struct mosquitto_message_all *message;
	int rc;
	assert(mosq);

	rc = message__remove(mosq, mid, dir, &message, qos);
	if(rc == MOSQ_ERR_SUCCESS){
		message__cleanup(&message);
	}
	return rc;
}

void mosquitto_message_free(struct mosquitto_message **message)
{
	struct mosquitto_message *msg;

	if(!message || !*message) return;

	msg = *message;

	mosquitto__free(msg->topic);
	mosquitto__free(msg->payload);
	mosquitto__free(msg);
}

void mosquitto_message_free_contents(struct mosquitto_message *message)
{
	if(!message) return;

	mosquitto__free(message->topic);
	mosquitto__free(message->payload);
}

int message__queue(struct mosquitto *mosq, struct mosquitto_message_all *message, enum mosquitto_msg_direction dir)
{
	/* mosq->*_message_mutex should be locked before entering this function */
	assert(mosq);
	assert(message);
	assert(message->msg.qos != 0);

	if(dir == mosq_md_out){
		DL_APPEND(mosq->msgs_out.inflight, message);
		mosq->msgs_out.queue_len++;
	}else{
		DL_APPEND(mosq->msgs_in.inflight, message);
		mosq->msgs_in.queue_len++;
	}

	return message__release_to_inflight(mosq, dir);
}

void message__reconnect_reset(struct mosquitto *mosq)
{
	struct mosquitto_message_all *message, *tmp;
	assert(mosq);

	pthread_mutex_lock(&mosq->msgs_in.mutex);
	mosq->msgs_in.inflight_quota = mosq->msgs_in.inflight_maximum;
	mosq->msgs_in.queue_len = 0;
	DL_FOREACH_SAFE(mosq->msgs_in.inflight, message, tmp){
		mosq->msgs_in.queue_len++;
		message->timestamp = 0;
		if(message->msg.qos != 2){
			DL_DELETE(mosq->msgs_in.inflight, message);
			message__cleanup(&message);
		}else{
			/* Message state can be preserved here because it should match
			* whatever the client has got. */
			util__decrement_receive_quota(mosq);
		}
	}
	pthread_mutex_unlock(&mosq->msgs_in.mutex);


	pthread_mutex_lock(&mosq->msgs_out.mutex);
	mosq->msgs_out.inflight_quota = mosq->msgs_out.inflight_maximum;
	mosq->msgs_out.queue_len = 0;
	DL_FOREACH_SAFE(mosq->msgs_out.inflight, message, tmp){
		mosq->msgs_out.queue_len++;

		message->timestamp = 0;
		if(mosq->msgs_out.inflight_quota != 0){
			util__decrement_send_quota(mosq);
			if(message->msg.qos == 1){
				message->state = mosq_ms_publish_qos1;
			}else if(message->msg.qos == 2){
				if(message->state == mosq_ms_wait_for_pubrec){
					message->state = mosq_ms_publish_qos2;
				}else if(message->state == mosq_ms_wait_for_pubcomp){
					message->state = mosq_ms_resend_pubrel;
				}
				/* Should be able to preserve state. */
			}
		}else{
			message->state = mosq_ms_invalid;
		}
	}
	pthread_mutex_unlock(&mosq->msgs_out.mutex);
}


int message__release_to_inflight(struct mosquitto *mosq, enum mosquitto_msg_direction dir)
{
	/* mosq->*_message_mutex should be locked before entering this function */
	struct mosquitto_message_all *cur, *tmp;
	int rc = MOSQ_ERR_SUCCESS;

	if(dir == mosq_md_out){
		DL_FOREACH_SAFE(mosq->msgs_out.inflight, cur, tmp){
			if(mosq->msgs_out.inflight_quota > 0){
				if(cur->msg.qos > 0 && cur->state == mosq_ms_invalid){
					if(cur->msg.qos == 1){
						cur->state = mosq_ms_wait_for_puback;
					}else if(cur->msg.qos == 2){
						cur->state = mosq_ms_wait_for_pubrec;
					}
					rc = send__publish(mosq, (uint16_t)cur->msg.mid, cur->msg.topic, (uint32_t)cur->msg.payloadlen, cur->msg.payload, (uint8_t)cur->msg.qos, cur->msg.retain, cur->dup, cur->properties, NULL, 0);
					if(rc){
						return rc;
					}
					util__decrement_send_quota(mosq);
				}
			}else{
				return MOSQ_ERR_SUCCESS;
			}
		}
	}

	return rc;
}


int message__remove(struct mosquitto *mosq, uint16_t mid, enum mosquitto_msg_direction dir, struct mosquitto_message_all **message, int qos)
{
	struct mosquitto_message_all *cur, *tmp;
	bool found = false;
	assert(mosq);
	assert(message);

	if(dir == mosq_md_out){
		pthread_mutex_lock(&mosq->msgs_out.mutex);

		DL_FOREACH_SAFE(mosq->msgs_out.inflight, cur, tmp){
			if(found == false && cur->msg.mid == mid){
				if(cur->msg.qos != qos){
					pthread_mutex_unlock(&mosq->msgs_out.mutex);
					return MOSQ_ERR_PROTOCOL;
				}
				DL_DELETE(mosq->msgs_out.inflight, cur);

				*message = cur;
				mosq->msgs_out.queue_len--;
				found = true;
				break;
			}
		}
		pthread_mutex_unlock(&mosq->msgs_out.mutex);
		if(found){
			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_NOT_FOUND;
		}
	}else{
		pthread_mutex_lock(&mosq->msgs_in.mutex);
		DL_FOREACH_SAFE(mosq->msgs_in.inflight, cur, tmp){
			if(cur->msg.mid == mid){
				if(cur->msg.qos != qos){
					pthread_mutex_unlock(&mosq->msgs_in.mutex);
					return MOSQ_ERR_PROTOCOL;
				}
				DL_DELETE(mosq->msgs_in.inflight, cur);
				*message = cur;
				mosq->msgs_in.queue_len--;
				found = true;
				break;
			}
		}

		pthread_mutex_unlock(&mosq->msgs_in.mutex);
		if(found){
			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_NOT_FOUND;
		}
	}
}

void message__retry_check(struct mosquitto *mosq)
{
	struct mosquitto_message_all *msg;
	time_t now = mosquitto_time();
	assert(mosq);

#ifdef WITH_THREADING
	pthread_mutex_lock(&mosq->msgs_out.mutex);
#endif

	DL_FOREACH(mosq->msgs_out.inflight, msg){
		switch(msg->state){
			case mosq_ms_publish_qos1:
			case mosq_ms_publish_qos2:
				msg->timestamp = now;
				msg->dup = true;
				send__publish(mosq, (uint16_t)msg->msg.mid, msg->msg.topic, (uint32_t)msg->msg.payloadlen, msg->msg.payload, (uint8_t)msg->msg.qos, msg->msg.retain, msg->dup, msg->properties, NULL, 0);
				break;
			case mosq_ms_wait_for_pubrel:
				msg->timestamp = now;
				msg->dup = true;
				send__pubrec(mosq, (uint16_t)msg->msg.mid, 0, NULL);
				break;
			case mosq_ms_resend_pubrel:
			case mosq_ms_wait_for_pubcomp:
				msg->timestamp = now;
				msg->dup = true;
				send__pubrel(mosq, (uint16_t)msg->msg.mid, NULL);
				break;
			default:
				break;
		}
	}
#ifdef WITH_THREADING
	pthread_mutex_unlock(&mosq->msgs_out.mutex);
#endif
}


void mosquitto_message_retry_set(struct mosquitto *mosq, unsigned int message_retry)
{
	UNUSED(mosq);
	UNUSED(message_retry);
}

int message__out_update(struct mosquitto *mosq, uint16_t mid, enum mosquitto_msg_state state, int qos)
{
	struct mosquitto_message_all *message, *tmp;
	assert(mosq);

	pthread_mutex_lock(&mosq->msgs_out.mutex);
	DL_FOREACH_SAFE(mosq->msgs_out.inflight, message, tmp){
		if(message->msg.mid == mid){
			if(message->msg.qos != qos){
				pthread_mutex_unlock(&mosq->msgs_out.mutex);
				return MOSQ_ERR_PROTOCOL;
			}
			message->state = state;
			message->timestamp = mosquitto_time();
			pthread_mutex_unlock(&mosq->msgs_out.mutex);
			return MOSQ_ERR_SUCCESS;
		}
	}
	pthread_mutex_unlock(&mosq->msgs_out.mutex);
	return MOSQ_ERR_NOT_FOUND;
}

int mosquitto_max_inflight_messages_set(struct mosquitto *mosq, unsigned int max_inflight_messages)
{
	return mosquitto_int_option(mosq, MOSQ_OPT_SEND_MAXIMUM, (int)max_inflight_messages);
}

