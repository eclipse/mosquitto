/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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
#ifndef UTIL_MOSQ_H
#define UTIL_MOSQ_H

#include <stdio.h>

#include "tls_mosq.h"
#include "mosquitto.h"
#include "mosquitto_internal.h"
#ifdef WITH_BROKER
#  include "mosquitto_broker_internal.h"
#endif

int mosquitto__check_keepalive(struct mosquitto *mosq);
uint16_t mosquitto__mid_generate(struct mosquitto *mosq);

int mosquitto__set_state(struct mosquitto *mosq, enum mosquitto_client_state state);
enum mosquitto_client_state mosquitto__get_state(struct mosquitto *mosq);

#ifdef WITH_TLS
int mosquitto__hex2bin_sha1(const char *hex, unsigned char **bin);
int mosquitto__hex2bin(const char *hex, unsigned char *bin, int bin_max_len);
#endif

int util__random_bytes(void *bytes, int count);

void util__increment_receive_quota(struct mosquitto *mosq);
void util__increment_send_quota(struct mosquitto *mosq);
void util__decrement_receive_quota(struct mosquitto *mosq);
void util__decrement_send_quota(struct mosquitto *mosq);


#endif
