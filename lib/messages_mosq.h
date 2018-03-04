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
#ifndef _MESSAGES_MOSQ_H_
#define _MESSAGES_MOSQ_H_

#include <mosquitto_internal.h>
#include <mosquitto.h>

void _mosquitto_message_cleanup_all(struct mosquitto *mosq);
void _mosquitto_message_cleanup(struct mosquitto_message_all **message);
int _mosquitto_message_delete(struct mosquitto *mosq, uint16_t mid, enum mosquitto_msg_direction dir);
int _mosquitto_message_queue(struct mosquitto *mosq, struct mosquitto_message_all *message, enum mosquitto_msg_direction dir);
void _mosquitto_messages_reconnect_reset(struct mosquitto *mosq);
int _mosquitto_message_remove(struct mosquitto *mosq, uint16_t mid, enum mosquitto_msg_direction dir, struct mosquitto_message_all **message);
void _mosquitto_message_retry_check(struct mosquitto *mosq);
int _mosquitto_message_out_update(struct mosquitto *mosq, uint16_t mid, enum mosquitto_msg_state state);

#endif
