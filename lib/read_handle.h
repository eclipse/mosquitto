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
#ifndef READ_HANDLE_H
#define READ_HANDLE_H

#include "mosquitto.h"
struct mosquitto_db;

int handle__pingreq(struct mosquitto *mosq);
int handle__pingresp(struct mosquitto *mosq);
#ifdef WITH_BROKER
int handle__pubackcomp(struct mosquitto *mosq, const char *type);
#else
int handle__packet(struct mosquitto *mosq);
int handle__connack(struct mosquitto *mosq);
int handle__disconnect(struct mosquitto *mosq);
int handle__pubackcomp(struct mosquitto *mosq, const char *type);
int handle__publish(struct mosquitto *mosq);
int handle__auth(struct mosquitto *mosq);
#endif
int handle__pubrec(struct mosquitto *mosq);
int handle__pubrel(struct mosquitto *mosq);
int handle__suback(struct mosquitto *mosq);
int handle__unsuback(struct mosquitto *mosq);


#endif
