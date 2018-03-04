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
#ifndef _READ_HANDLE_H_
#define _READ_HANDLE_H_

#include <mosquitto.h>
struct mosquitto_db;

int _mosquitto_packet_handle(struct mosquitto *mosq);
int _mosquitto_handle_connack(struct mosquitto *mosq);
int _mosquitto_handle_pingreq(struct mosquitto *mosq);
int _mosquitto_handle_pingresp(struct mosquitto *mosq);
#ifdef WITH_BROKER
int _mosquitto_handle_pubackcomp(struct mosquitto_db *db, struct mosquitto *mosq, const char *type);
#else
int _mosquitto_handle_pubackcomp(struct mosquitto *mosq, const char *type);
#endif
int _mosquitto_handle_publish(struct mosquitto *mosq);
int _mosquitto_handle_pubrec(struct mosquitto *mosq);
int _mosquitto_handle_pubrel(struct mosquitto_db *db, struct mosquitto *mosq);
int _mosquitto_handle_suback(struct mosquitto *mosq);
int _mosquitto_handle_unsuback(struct mosquitto *mosq);


#endif
