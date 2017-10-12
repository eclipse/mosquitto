/*
Copyright (c) 2009-2014 Roger Light <roger@atchoo.org>

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
#ifndef _UTIL_MOSQ_H_
#define _UTIL_MOSQ_H_

#include <stdio.h>

#include "tls_mosq.h"
#include "mosquitto.h"
#include "mosquitto_internal.h"
#ifdef WITH_BROKER
#  include "mosquitto_broker.h"
#endif

int _mosquitto_packet_alloc(struct _mosquitto_packet *packet);
#ifdef WITH_BROKER
void _mosquitto_check_keepalive(struct mosquitto_db *db, struct mosquitto *mosq);
#else
void _mosquitto_check_keepalive(struct mosquitto *mosq);
#endif
uint16_t _mosquitto_mid_generate(struct mosquitto *mosq);
FILE *_mosquitto_fopen(const char *path, const char *mode, bool restrict_read);

#ifdef REAL_WITH_TLS_PSK
int _mosquitto_hex2bin(const char *hex, unsigned char *bin, int bin_max_len);
#endif

#endif
