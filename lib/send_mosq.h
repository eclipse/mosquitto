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
#ifndef _SEND_MOSQ_H_
#define _SEND_MOSQ_H_

#include <mosquitto.h>

int _mosquitto_send_simple_command(struct mosquitto *mosq, uint8_t command);
int _mosquitto_send_command_with_mid(struct mosquitto *mosq, uint8_t command, uint16_t mid, bool dup);
int _mosquitto_send_real_publish(struct mosquitto *mosq, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, int qos, bool retain, bool dup);

int _mosquitto_send_connect(struct mosquitto *mosq, uint16_t keepalive, bool clean_session);
int _mosquitto_send_disconnect(struct mosquitto *mosq);
int _mosquitto_send_pingreq(struct mosquitto *mosq);
int _mosquitto_send_pingresp(struct mosquitto *mosq);
int _mosquitto_send_puback(struct mosquitto *mosq, uint16_t mid);
int _mosquitto_send_pubcomp(struct mosquitto *mosq, uint16_t mid);
int _mosquitto_send_publish(struct mosquitto *mosq, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, int qos, bool retain, bool dup);
int _mosquitto_send_pubrec(struct mosquitto *mosq, uint16_t mid);
int _mosquitto_send_pubrel(struct mosquitto *mosq, uint16_t mid);
int _mosquitto_send_subscribe(struct mosquitto *mosq, int *mid, const char *topic, uint8_t topic_qos);
int _mosquitto_send_unsubscribe(struct mosquitto *mosq, int *mid, const char *topic);

#endif
