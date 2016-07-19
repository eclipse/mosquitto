/*
Copyright (c) 2010-2015 Roger Light <roger@atchoo.org>

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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "mosquitto_internal.h"
#include "mosquitto.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "send_mosq.h"
#include "time_mosq.h"

void message__cleanup(struct mosquitto_message_all **message)
{
	struct mosquitto_message_all *msg;

	if(!message || !*message) return;

	msg = *message;

	mosquitto__free(msg->msg.topic);
	mosquitto__free(msg->msg.payload);
	mosquitto__free(msg);
}

void message__cleanup_all(struct mosquitto *mosq)
{
	struct mosquitto_message_all *tmp;

	assert(mosq);

	while(mosq->in_messages){
		tmp = mosq->in_messages->next;
		message__cleanup(&mosq->in_messages);
		mosq->in_messages = tmp;
	}
	while(mosq->out_messages){
		tmp = mosq->out_messages->next;
		message__cleanup(&mosq->out_messages);
		mosq->out_messages = tmp;
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
		dst->payload = mosquitto__calloc(src->payloadlen+1, sizeof(uint8_t));
		if(!dst->payload){
			mosquitto__free(dst->topic);
			return MOSQ_ERR_NOMEM;
		}
		memcpy(dst->payload, src->payload, src->payloadlen);
		dst->payloadlen = src->payloadlen;
	}else{
		dst->payloadlen = 0;
		dst->payload = NULL;
	}
	return MOSQ_ERR_SUCCESS;
}

int message__delete(struct mosquitto *mosq, uint16_t mid, enum mosquitto_msg_direction dir)
{
	struct mosquitto_message_all *message;
	int rc;
	assert(mosq);

	rc = message__remove(mosq, mid, dir, &message);
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
	int rc = 0;

	/* mosq->*_message_mutex should be locked before entering this function */
	assert(mosq);
	assert(message);

	if(dir == mosq_md_out){
		mosq->out_queue_len++;
		message->next = NULL;
		if(mosq->out_messages_last){
			mosq->out_messages_last->next = message;
		}else{
			mosq->out_messages = message;
		}
		mosq->out_messages_last = message;
		if(message->msg.qos > 0){
			if(mosq->max_inflight_messages == 0 || mosq->inflight_messages < mosq->max_inflight_messages){
				mosq->inflight_messages++;
			}else{
				rc = 1;
			}
		}
	}else{
		mosq->in_queue_len++;
		message->next = NULL;
		if(mosq->in_messages_last){
			mosq->in_messages_last->next = message;
		}else{
			mosq->in_messages = message;
		}
		mosq->in_messages_last = message;
	}
	return rc;
}

void message__reconnect_reset(struct mosquitto *mosq)
{
	struct mosquitto_message_all *message;
	struct mosquitto_message_all *prev = NULL;
	assert(mosq);

	pthread_mutex_lock(&mosq->in_message_mutex);
	message = mosq->in_messages;
	mosq->in_queue_len = 0;
	while(message){
		mosq->in_queue_len++;
		message->timestamp = 0;
		if(message->msg.qos != 2){
			if(prev){
				prev->next = message->next;
				message__cleanup(&message);
				message = prev;
			}else{
				mosq->in_messages = message->next;
				message__cleanup(&message);
				message = mosq->in_messages;
			}
		}else{
			/* Message state can be preserved here because it should match
			* whatever the client has got. */
		}
		prev = message;
		message = message->next;
	}
	mosq->in_messages_last = prev;
	pthread_mutex_unlock(&mosq->in_message_mutex);


	pthread_mutex_lock(&mosq->out_message_mutex);
	mosq->inflight_messages = 0;
	message = mosq->out_messages;
	mosq->out_queue_len = 0;
	while(message){
		mosq->out_queue_len++;
		message->timestamp = 0;

		if(mosq->max_inflight_messages == 0 || mosq->inflight_messages < mosq->max_inflight_messages){
			if(message->msg.qos > 0){
				mosq->inflight_messages++;
			}
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
		prev = message;
		message = message->next;
	}
	mosq->out_messages_last = prev;
	pthread_mutex_unlock(&mosq->out_message_mutex);
}

int message__remove(struct mosquitto *mosq, uint16_t mid, enum mosquitto_msg_direction dir, struct mosquitto_message_all **message)
{
	struct mosquitto_message_all *cur, *prev = NULL;
	bool found = false;
	int rc;
	assert(mosq);
	assert(message);

	if(dir == mosq_md_out){
		pthread_mutex_lock(&mosq->out_message_mutex);
		cur = mosq->out_messages;
		while(cur){
			if(cur->msg.mid == mid){
				if(prev){
					prev->next = cur->next;
				}else{
					mosq->out_messages = cur->next;
				}
				*message = cur;
				mosq->out_queue_len--;
				if(cur->next == NULL){
					mosq->out_messages_last = prev;
				}else if(!mosq->out_messages){
					mosq->out_messages_last = NULL;
				}
				if(cur->msg.qos > 0){
					mosq->inflight_messages--;
				}
				found = true;
				break;
			}
			prev = cur;
			cur = cur->next;
		}

		if(found){
			cur = mosq->out_messages;
			while(cur){
				if(mosq->max_inflight_messages == 0 || mosq->inflight_messages < mosq->max_inflight_messages){
					if(cur->msg.qos > 0 && cur->state == mosq_ms_invalid){
						mosq->inflight_messages++;
						if(cur->msg.qos == 1){
							cur->state = mosq_ms_wait_for_puback;
						}else if(cur->msg.qos == 2){
							cur->state = mosq_ms_wait_for_pubrec;
						}
						rc = send__publish(mosq, cur->msg.mid, cur->msg.topic, cur->msg.payloadlen, cur->msg.payload, cur->msg.qos, cur->msg.retain, cur->dup);
						if(rc){
							pthread_mutex_unlock(&mosq->out_message_mutex);
							return rc;
						}
					}
				}else{
					pthread_mutex_unlock(&mosq->out_message_mutex);
					return MOSQ_ERR_SUCCESS;
				}
				cur = cur->next;
			}
			pthread_mutex_unlock(&mosq->out_message_mutex);
			return MOSQ_ERR_SUCCESS;
		}else{
			pthread_mutex_unlock(&mosq->out_message_mutex);
			return MOSQ_ERR_NOT_FOUND;
		}
	}else{
		pthread_mutex_lock(&mosq->in_message_mutex);
		cur = mosq->in_messages;
		while(cur){
			if(cur->msg.mid == mid){
				if(prev){
					prev->next = cur->next;
				}else{
					mosq->in_messages = cur->next;
				}
				*message = cur;
				mosq->in_queue_len--;
				if(cur->next == NULL){
					mosq->in_messages_last = prev;
				}else if(!mosq->in_messages){
					mosq->in_messages_last = NULL;
				}
				found = true;
				break;
			}
			prev = cur;
			cur = cur->next;
		}

		pthread_mutex_unlock(&mosq->in_message_mutex);
		if(found){
			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_NOT_FOUND;
		}
	}
}

#ifdef WITH_THREADING
void message__retry_check_actual(struct mosquitto *mosq, struct mosquitto_message_all *messages, pthread_mutex_t *mutex)
#else
void message__retry_check_actual(struct mosquitto *mosq, struct mosquitto_message_all *messages)
#endif
{
	time_t now = mosquitto_time();
	assert(mosq);

#ifdef WITH_THREADING
	pthread_mutex_lock(mutex);
#endif

	while(messages){
		switch(messages->state){
			case mosq_ms_publish_qos1:
			case mosq_ms_publish_qos2:
				messages->timestamp = now;
				messages->dup = true;
				send__publish(mosq, messages->msg.mid, messages->msg.topic, messages->msg.payloadlen, messages->msg.payload, messages->msg.qos, messages->msg.retain, messages->dup);
				break;
			case mosq_ms_wait_for_pubrel:
				messages->timestamp = now;
				messages->dup = true;
				send__pubrec(mosq, messages->msg.mid);
				break;
			case mosq_ms_resend_pubrel:
			case mosq_ms_wait_for_pubcomp:
				messages->timestamp = now;
				messages->dup = true;
				send__pubrel(mosq, messages->msg.mid);
				break;
			default:
				break;
		}
		messages = messages->next;
	}
#ifdef WITH_THREADING
	pthread_mutex_unlock(mutex);
#endif
}

void message__retry_check(struct mosquitto *mosq)
{
#ifdef WITH_THREADING
	message__retry_check_actual(mosq, mosq->out_messages, &mosq->out_message_mutex);
#else
	message__retry_check_actual(mosq, mosq->out_messages);
#endif
}

void mosquitto_message_retry_set(struct mosquitto *mosq, unsigned int message_retry)
{
}

int message__out_update(struct mosquitto *mosq, uint16_t mid, enum mosquitto_msg_state state)
{
	struct mosquitto_message_all *message;
	assert(mosq);

	pthread_mutex_lock(&mosq->out_message_mutex);
	message = mosq->out_messages;
	while(message){
		if(message->msg.mid == mid){
			message->state = state;
			message->timestamp = mosquitto_time();
			pthread_mutex_unlock(&mosq->out_message_mutex);
			return MOSQ_ERR_SUCCESS;
		}
		message = message->next;
	}
	pthread_mutex_unlock(&mosq->out_message_mutex);
	return MOSQ_ERR_NOT_FOUND;
}

int mosquitto_max_inflight_messages_set(struct mosquitto *mosq, unsigned int max_inflight_messages)
{
	if(!mosq) return MOSQ_ERR_INVAL;

	mosq->max_inflight_messages = max_inflight_messages;

	return MOSQ_ERR_SUCCESS;
}

