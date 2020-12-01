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

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <string.h>

#ifdef WITH_BROKER
#  include "mosquitto_broker_internal.h"
#  ifdef WITH_WEBSOCKETS
#    include <libwebsockets.h>
#  endif
#else
#  include "read_handle.h"
#endif

#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"
#ifdef WITH_BROKER
#  include "sys_tree.h"
#else
#  define G_BYTES_RECEIVED_INC(A)
#  define G_BYTES_SENT_INC(A)
#  define G_MSGS_SENT_INC(A)
#  define G_PUB_MSGS_SENT_INC(A)
#endif


int packet__read_byte(struct mosquitto__packet *packet, uint8_t *byte)
{
	assert(packet);
	if(packet->pos+1 > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

	*byte = packet->payload[packet->pos];
	packet->pos++;

	return MOSQ_ERR_SUCCESS;
}


void packet__write_byte(struct mosquitto__packet *packet, uint8_t byte)
{
	assert(packet);
	assert(packet->pos+1 <= packet->packet_length);

	packet->payload[packet->pos] = byte;
	packet->pos++;
}


int packet__read_bytes(struct mosquitto__packet *packet, void *bytes, uint32_t count)
{
	assert(packet);
	if(packet->pos+count > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

	memcpy(bytes, &(packet->payload[packet->pos]), count);
	packet->pos += count;

	return MOSQ_ERR_SUCCESS;
}


void packet__write_bytes(struct mosquitto__packet *packet, const void *bytes, uint32_t count)
{
	assert(packet);
	assert(packet->pos+count <= packet->packet_length);

	memcpy(&(packet->payload[packet->pos]), bytes, count);
	packet->pos += count;
}


int packet__read_binary(struct mosquitto__packet *packet, uint8_t **data, uint16_t *length)
{
	uint16_t slen;
	int rc;

	assert(packet);
	rc = packet__read_uint16(packet, &slen);
	if(rc) return rc;

	if(slen == 0){
		*data = NULL;
		*length = 0;
		return MOSQ_ERR_SUCCESS;
	}

	if(packet->pos+slen > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

	*data = mosquitto__malloc(slen+1U);
	if(*data){
		memcpy(*data, &(packet->payload[packet->pos]), slen);
		((uint8_t *)(*data))[slen] = '\0';
		packet->pos += slen;
	}else{
		return MOSQ_ERR_NOMEM;
	}

	*length = slen;
	return MOSQ_ERR_SUCCESS;
}


int packet__read_string(struct mosquitto__packet *packet, char **str, uint16_t *length)
{
	int rc;

	rc = packet__read_binary(packet, (uint8_t **)str, length);
	if(rc) return rc;
	if(*length == 0) return MOSQ_ERR_SUCCESS;

	if(mosquitto_validate_utf8(*str, *length)){
		mosquitto__free(*str);
		*str = NULL;
		*length = 0;
		return MOSQ_ERR_MALFORMED_UTF8;
	}

	return MOSQ_ERR_SUCCESS;
}


void packet__write_string(struct mosquitto__packet *packet, const char *str, uint16_t length)
{
	assert(packet);
	packet__write_uint16(packet, length);
	packet__write_bytes(packet, str, length);
}


int packet__read_uint16(struct mosquitto__packet *packet, uint16_t *word)
{
	uint8_t msb, lsb;

	assert(packet);
	if(packet->pos+2 > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

	msb = packet->payload[packet->pos];
	packet->pos++;
	lsb = packet->payload[packet->pos];
	packet->pos++;

	*word = (uint16_t)((msb<<8) + lsb);

	return MOSQ_ERR_SUCCESS;
}


void packet__write_uint16(struct mosquitto__packet *packet, uint16_t word)
{
	packet__write_byte(packet, MOSQ_MSB(word));
	packet__write_byte(packet, MOSQ_LSB(word));
}


int packet__read_uint32(struct mosquitto__packet *packet, uint32_t *word)
{
	uint32_t val = 0;
	int i;

	assert(packet);
	if(packet->pos+4 > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

	for(i=0; i<4; i++){
		val = (val << 8) + packet->payload[packet->pos];
		packet->pos++;
	}

	*word = val;

	return MOSQ_ERR_SUCCESS;
}


void packet__write_uint32(struct mosquitto__packet *packet, uint32_t word)
{
	packet__write_byte(packet, (uint8_t)((word & 0xFF000000) >> 24));
	packet__write_byte(packet, (uint8_t)((word & 0x00FF0000) >> 16));
	packet__write_byte(packet, (uint8_t)((word & 0x0000FF00) >> 8));
	packet__write_byte(packet, (uint8_t)((word & 0x000000FF)));
}


int packet__read_varint(struct mosquitto__packet *packet, uint32_t *word, uint8_t *bytes)
{
	int i;
	uint8_t byte;
	unsigned int remaining_mult = 1;
	uint32_t lword = 0;
	uint8_t lbytes = 0;

	for(i=0; i<4; i++){
		if(packet->pos < packet->remaining_length){
			lbytes++;
			byte = packet->payload[packet->pos];
			lword += (byte & 127) * remaining_mult;
			remaining_mult *= 128;
			packet->pos++;
			if((byte & 128) == 0){
				if(lbytes > 1 && byte == 0){
					/* Catch overlong encodings */
					return MOSQ_ERR_PROTOCOL;
				}else{
					*word = lword;
					if(bytes) (*bytes) = lbytes;
					return MOSQ_ERR_SUCCESS;
				}
			}
		}else{
			return MOSQ_ERR_PROTOCOL;
		}
	}
	return MOSQ_ERR_PROTOCOL;
}


int packet__write_varint(struct mosquitto__packet *packet, uint32_t word)
{
	uint8_t byte;
	int count = 0;

	do{
		byte = (uint8_t)(word % 128);
		word = word / 128;
		/* If there are more digits to encode, set the top bit of this digit */
		if(word > 0){
			byte = byte | 0x80;
		}
		packet__write_byte(packet, byte);
		count++;
	}while(word > 0 && count < 5);

	if(count == 5){
		return MOSQ_ERR_PROTOCOL;
	}
	return MOSQ_ERR_SUCCESS;
}


unsigned int packet__varint_bytes(uint32_t word)
{
	if(word < 128){
		return 1;
	}else if(word < 16384){
		return 2;
	}else if(word < 2097152){
		return 3;
	}else if(word < 268435456){
		return 4;
	}else{
		return 5;
	}
}
