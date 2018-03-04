/*
Copyright (c) 2009-2018 Roger Light <roger@atchoo.org>

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

#include <config.h>
#include <stdio.h>
#include <string.h>

#include <mosquitto_broker.h>
#include <memory_mosq.h>
#include <mqtt3_protocol.h>
#include <send_mosq.h>
#include <util_mosq.h>

int mqtt3_handle_connack(struct mosquitto_db *db, struct mosquitto *context)
{
	uint8_t byte;
	uint8_t rc;
	int i;
	char *notification_topic;
	int notification_topic_len;
	char notification_payload;

	if(!context){
		return MOSQ_ERR_INVAL;
	}
	_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Received CONNACK on connection %s.", context->id);
	if(_mosquitto_read_byte(&context->in_packet, &byte)) return 1; // Reserved byte, not used
	if(_mosquitto_read_byte(&context->in_packet, &rc)) return 1;
	switch(rc){
		case CONNACK_ACCEPTED:
			if(context->bridge){
				if(context->bridge->notifications){
					notification_payload = '1';
					if(context->bridge->notification_topic){
						if(_mosquitto_send_real_publish(context, _mosquitto_mid_generate(context),
								context->bridge->notification_topic, 1, &notification_payload, 1, true, 0)){

							return 1;
						}
						mqtt3_db_messages_easy_queue(db, context, context->bridge->notification_topic, 1, 1, &notification_payload, 1);
					}else{
						notification_topic_len = strlen(context->bridge->remote_clientid)+strlen("$SYS/broker/connection//state");
						notification_topic = _mosquitto_malloc(sizeof(char)*(notification_topic_len+1));
						if(!notification_topic) return MOSQ_ERR_NOMEM;

						snprintf(notification_topic, notification_topic_len+1, "$SYS/broker/connection/%s/state", context->bridge->remote_clientid);
						notification_payload = '1';
						if(_mosquitto_send_real_publish(context, _mosquitto_mid_generate(context),
								notification_topic, 1, &notification_payload, 1, true, 0)){

							_mosquitto_free(notification_topic);
							return 1;
						}
						mqtt3_db_messages_easy_queue(db, context, notification_topic, 1, 1, &notification_payload, 1);
						_mosquitto_free(notification_topic);
					}
				}
				for(i=0; i<context->bridge->topic_count; i++){
					if(context->bridge->topics[i].direction == bd_in || context->bridge->topics[i].direction == bd_both){
						if(_mosquitto_send_subscribe(context, NULL, context->bridge->topics[i].remote_topic, context->bridge->topics[i].qos)){
							return 1;
						}
					}else{
						if(context->bridge->attempt_unsubscribe){
							if(_mosquitto_send_unsubscribe(context, NULL, context->bridge->topics[i].remote_topic)){
								/* direction = inwards only. This means we should not be subscribed
								* to the topic. It is possible that we used to be subscribed to
								* this topic so unsubscribe. */
								return 1;
							}
						}
					}
				}
			}
			context->state = mosq_cs_connected;
			return MOSQ_ERR_SUCCESS;
		case CONNACK_REFUSED_PROTOCOL_VERSION:
			if(context->bridge){
				context->bridge->try_private_accepted = false;
			}
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Connection Refused: unacceptable protocol version");
			return 1;
		case CONNACK_REFUSED_IDENTIFIER_REJECTED:
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Connection Refused: identifier rejected");
			return 1;
		case CONNACK_REFUSED_SERVER_UNAVAILABLE:
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Connection Refused: broker unavailable");
			return 1;
		case CONNACK_REFUSED_BAD_USERNAME_PASSWORD:
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Connection Refused: broker unavailable");
			return 1;
		case CONNACK_REFUSED_NOT_AUTHORIZED:
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Connection Refused: not authorised");
			return 1;
		default:
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Connection Refused: unknown reason");
			return 1;
	}
	return 1;
}

