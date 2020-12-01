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
#ifndef SEND_MOSQ_H
#define SEND_MOSQ_H

#include "mosquitto.h"
#include "property_mosq.h"

int send__simple_command(struct mosquitto *mosq, uint8_t command);
int send__command_with_mid(struct mosquitto *mosq, uint8_t command, uint16_t mid, bool dup, uint8_t reason_code, const mosquitto_property *properties);
int send__real_publish(struct mosquitto *mosq, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, uint8_t qos, bool retain, bool dup, const mosquitto_property *cmsg_props, const mosquitto_property *store_props, uint32_t expiry_interval);

int send__connect(struct mosquitto *mosq, uint16_t keepalive, bool clean_session, const mosquitto_property *properties);
int send__disconnect(struct mosquitto *mosq, uint8_t reason_code, const mosquitto_property *properties);
int send__pingreq(struct mosquitto *mosq);
int send__pingresp(struct mosquitto *mosq);
int send__puback(struct mosquitto *mosq, uint16_t mid, uint8_t reason_code, const mosquitto_property *properties);
int send__pubcomp(struct mosquitto *mosq, uint16_t mid, const mosquitto_property *properties);
int send__publish(struct mosquitto *mosq, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, uint8_t qos, bool retain, bool dup, const mosquitto_property *cmsg_props, const mosquitto_property *store_props, uint32_t expiry_interval);
int send__pubrec(struct mosquitto *mosq, uint16_t mid, uint8_t reason_code, const mosquitto_property *properties);
int send__pubrel(struct mosquitto *mosq, uint16_t mid, const mosquitto_property *properties);
int send__subscribe(struct mosquitto *mosq, int *mid, int topic_count, char *const *const topic, int topic_qos, const mosquitto_property *properties);
int send__unsubscribe(struct mosquitto *mosq, int *mid, int topic_count, char *const *const topic, const mosquitto_property *properties);

#endif
