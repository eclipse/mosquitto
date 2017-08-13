/*
Copyright (c) 2010-2016 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
   Tatsuzo Osawa - Add mqtt version 5.   
*/
#ifndef PACKET_MOSQ_H
#define PACKET_MOSQ_H

#include "mosquitto_internal.h"
#include "mosquitto.h"

#ifdef WITH_BROKER
struct mosquitto_db;
#endif

int packet__alloc(struct mosquitto__packet *packet);
void packet__cleanup(struct mosquitto__packet *packet);
int packet__queue(struct mosquitto *mosq, struct mosquitto__packet *packet);

int packet__read_byte(struct mosquitto__packet *packet, uint8_t *byte);
int packet__read_bytes(struct mosquitto__packet *packet, void *bytes, uint32_t count);
int packet__read_string(struct mosquitto__packet *packet, char **str);
int packet__read_uint16(struct mosquitto__packet *packet, uint16_t *word);
int packet__read_variable(struct mosquitto__packet *packet, int *variable);
int packet__read_property(struct mosquitto *mosq, struct mosquitto__packet *packet, struct mosquitto_v5_property *property, int command);

void packet__write_byte(struct mosquitto__packet *packet, uint8_t byte);
void packet__write_bytes(struct mosquitto__packet *packet, const void *bytes, uint32_t count);
void packet__write_string(struct mosquitto__packet *packet, const char *str, uint16_t length);
void packet__write_uint16(struct mosquitto__packet *packet, uint16_t word);
void packet__write_variable(struct mosquitto__packet *packet, int variable);
void packet__write_property(struct mosquitto *mosq, struct mosquitto__packet *packet, struct mosquitto_v5_property *property, int command);

size_t variable_len(varint_t variable);
varint_t packet__property_len(struct mosquitto_v5_property *property);
void packet__property_content_free(struct mosquitto_v5_property *property);
int packet__payload_convert(struct mosquitto *mosq, uint8_t src_version, uint8_t dst_version, uint32_t src_payloadlen, const void *src_payload, uint32_t *dst_payloadlen, void **dst_payload);

int packet__write(struct mosquitto *mosq);
#ifdef WITH_BROKER
int packet__read(struct mosquitto_db *db, struct mosquitto *mosq);
#else
int packet__read(struct mosquitto *mosq);
#endif

#endif

