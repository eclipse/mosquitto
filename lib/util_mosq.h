/*
Copyright (c) 2009-2015 Roger Light <roger@atchoo.org>

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
#ifndef UTIL_MOSQ_H
#define UTIL_MOSQ_H

#include <stdio.h>

#include "tls_mosq.h"
#include "mosquitto.h"
#include "mosquitto_internal.h"
#ifdef WITH_BROKER
#  include "mosquitto_broker.h"
#endif

#ifdef WITH_BROKER
void mosquitto__check_keepalive(struct mosquitto_db *db, struct mosquitto *mosq);
#else
void mosquitto__check_keepalive(struct mosquitto *mosq);
#endif
uint16_t mosquitto__mid_generate(struct mosquitto *mosq);
FILE *mosquitto__fopen(const char *path, const char *mode);

#ifdef REAL_WITH_TLS_PSK
int mosquitto__hex2bin(const char *hex, unsigned char *bin, int bin_max_len);
#endif

#endif
