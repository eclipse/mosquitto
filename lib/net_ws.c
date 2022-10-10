/*
Copyright (c) 2021 Roger Light <roger@atchoo.org>

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

#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_BUILTIN
#ifndef WITH_TLS
#  error "Builtin websockets support requires WITH_TLS=yes and openssl to be available"
#endif

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "base64_mosq.h"
#include "mosquitto_internal.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "util_mosq.h"


void ws__context_init(struct mosquitto *mosq)
{
	mosq->transport = mosq_t_ws;
	mosq->state = mosq_cs_new;
}


void ws__prepare_packet(struct mosquitto *mosq, struct mosquitto__packet *packet)
{
	uint8_t opcode;
	uint32_t masking_offset = mosq->wsd.is_client?4:0;

	packet->next = NULL;

	if(mosq->wsd.opcode == UINT8_MAX){
		opcode = WS_BINARY;
	}else if(mosq->wsd.opcode == WS_PING){
		opcode = WS_PONG;
	}else{
		opcode = mosq->wsd.opcode;
	}
	if(packet->packet_length - WS_PACKET_OFFSET < 126){
		if(mosq->wsd.is_client){
			packet->payload[WS_PACKET_OFFSET-masking_offset-1] = (uint8_t)(packet->packet_length-WS_PACKET_OFFSET) | 0x80;
		}else{
			packet->payload[WS_PACKET_OFFSET-masking_offset-1] = (uint8_t)(packet->packet_length-WS_PACKET_OFFSET);
		}
		packet->payload[WS_PACKET_OFFSET - masking_offset-2] = 0x80 | opcode;
		packet->pos = WS_PACKET_OFFSET - masking_offset - 2;
		packet->to_process = packet->packet_length - WS_PACKET_OFFSET + masking_offset + 2;
	}else if(packet->packet_length - WS_PACKET_OFFSET < 65536){
		uint16_t plen = (uint16_t )(packet->packet_length - WS_PACKET_OFFSET);

		packet->payload[WS_PACKET_OFFSET-masking_offset-1] = MOSQ_LSB(plen);
		packet->payload[WS_PACKET_OFFSET-masking_offset-2] = MOSQ_MSB(plen);;
		if(mosq->wsd.is_client){
			packet->payload[WS_PACKET_OFFSET-masking_offset-3] = 126 | 0x80;
		}else{
			packet->payload[WS_PACKET_OFFSET-masking_offset-3] = 126;
		}
		packet->payload[WS_PACKET_OFFSET-masking_offset-4] = 0x80 | opcode;
		packet->pos = WS_PACKET_OFFSET-masking_offset - 4;
		packet->to_process = packet->packet_length - WS_PACKET_OFFSET + masking_offset + 4;
	}else{
		uint64_t plen = packet->packet_length - WS_PACKET_OFFSET;

		packet->payload[WS_PACKET_OFFSET-masking_offset-1] = (uint8_t)((plen & 0x00000000000000FF) >> 0);
		packet->payload[WS_PACKET_OFFSET-masking_offset-2] = (uint8_t)((plen & 0x000000000000FF00) >> 8);
		packet->payload[WS_PACKET_OFFSET-masking_offset-3] = (uint8_t)((plen & 0x0000000000FF0000) >> WS_PACKET_OFFSET);
		packet->payload[WS_PACKET_OFFSET-masking_offset-4] = (uint8_t)((plen & 0x00000000FF000000) >> 24);
		packet->payload[WS_PACKET_OFFSET-masking_offset-5] = (uint8_t)((plen & 0x000000FF00000000) >> 32);
		packet->payload[WS_PACKET_OFFSET-masking_offset-6] = (uint8_t)((plen & 0x0000FF0000000000) >> 40);
		packet->payload[WS_PACKET_OFFSET-masking_offset-7] = (uint8_t)((plen & 0x00FF000000000000) >> 48);
		packet->payload[WS_PACKET_OFFSET-masking_offset-8] = (uint8_t)((plen & 0xFF00000000000000) >> 56);
		if(mosq->wsd.is_client){
			packet->payload[WS_PACKET_OFFSET-masking_offset-9] = 127 | 0x80;
		}else{
			packet->payload[WS_PACKET_OFFSET-masking_offset-9] = 127;
		}
		packet->payload[WS_PACKET_OFFSET-masking_offset-10] = 0x80 | opcode;
		packet->pos = WS_PACKET_OFFSET-masking_offset - 10;
		packet->to_process = packet->packet_length - WS_PACKET_OFFSET + masking_offset + 10;
	}
	if(mosq->wsd.is_client){
		util__random_bytes(&packet->payload[WS_PACKET_OFFSET-sizeof(uint32_t)], sizeof(uint32_t));
		for(uint32_t i=0; i<packet->packet_length - WS_PACKET_OFFSET; i++){
			packet->payload[WS_PACKET_OFFSET + i] ^= packet->payload[WS_PACKET_OFFSET-sizeof(uint32_t)+(i%4)];
		}
	}
}


static ssize_t read_ws_opcode(struct mosquitto *mosq)
{
	ssize_t len;
	uint8_t opcode;
	uint8_t fin;
	uint8_t hbuf;

	mosq->wsd.mask_bytes = 4;
	mosq->wsd.pos = 0;
	mosq->wsd.mask = UINT8_MAX;
	mosq->wsd.payloadlen_bytes = UINT8_MAX;

	len = net__read(mosq, &hbuf, 1);
	if(len <= 0) return len;

	if((hbuf & 0x70) != 0x00){
		mosq->wsd.disconnect_reason = 0xEA;
		errno = EPROTO;
		return -1;
	}
	opcode = (hbuf & 0x0F);
	fin = (hbuf & 0x80);
	switch(opcode){
		case WS_CONTINUATION:
		case WS_BINARY:
		case WS_PING:
		case WS_PONG:
		case WS_CLOSE:
			mosq->wsd.opcode = opcode;
			break;

		case WS_TEXT:
			mosq->wsd.disconnect_reason = 0xEB;
			errno = EPROTO;
			return -1;

		default:
			mosq->wsd.disconnect_reason = 0xEA;
			errno = EPROTO;
			return -1;
			break;
	}
	if((opcode & 0x08) && fin == 0){
		/* Control packets may not be fragmented */
		mosq->wsd.disconnect_reason = 0xEA;
		errno = EPROTO;
		return -1;
	}

	return len;
}


static ssize_t read_ws_payloadlen_short(struct mosquitto *mosq)
{
	ssize_t len;
	uint8_t hbuf;
	uint8_t plen;

	len = net__read(mosq, &hbuf, 1);
	if(len <= 0) return len;

	mosq->wsd.mask = (hbuf & 0x80) >> 7;
	plen = hbuf & 0x7F;

	if(plen == 126){
		mosq->wsd.payloadlen_bytes = 2;
		mosq->wsd.payloadlen = 0;
	}else if(plen == 127){
		mosq->wsd.payloadlen_bytes = 8;
		mosq->wsd.payloadlen = 0;
	}else{
		mosq->wsd.payloadlen_bytes = 0;
		mosq->wsd.payloadlen = plen;
	}

	return len;
}


static ssize_t read_ws_payloadlen_extended(struct mosquitto *mosq)
{
	uint8_t hbuf[8];
	ssize_t len;

	len = net__read(mosq, hbuf, mosq->wsd.payloadlen_bytes);
	if(len <= 0) return len;
	for(ssize_t i=0; i<len; i++){
		mosq->wsd.payloadlen = (mosq->wsd.payloadlen << 8) + hbuf[i];
	}
	mosq->wsd.payloadlen_bytes -= (uint8_t)len;

	return len;
}


static ssize_t read_ws_mask(struct mosquitto *mosq)
{
	ssize_t len;

	len = net__read(mosq, &mosq->wsd.maskingkey[4-mosq->wsd.mask_bytes], mosq->wsd.mask_bytes);
	if(len <= 0) return len;
	mosq->wsd.mask_bytes -= (uint8_t)len;
	if(mosq->wsd.mask_bytes > 0){
		errno = EAGAIN;
		return -1;
	}

	return len;
}


ssize_t net__read_ws(struct mosquitto *mosq, void *buf, size_t count)
{
	ssize_t len = 0;

	if(mosq->wsd.payloadlen == 0){
		if(mosq->wsd.opcode == UINT8_MAX){
			len = read_ws_opcode(mosq);
			if(len <= 0) return len;
		}

		if(mosq->wsd.mask == UINT8_MAX){
			len = read_ws_payloadlen_short(mosq);
			if(len <= 0) return len;
		}

		if(mosq->wsd.payloadlen_bytes > 0){
			len = read_ws_payloadlen_extended(mosq);
			if(len <= 0) return len;
		}

		if(mosq->wsd.mask == 1 && mosq->wsd.mask_bytes > 0){
			len = read_ws_mask(mosq);
			if(len <= 0) return len;
		}

		if(mosq->wsd.opcode == WS_CLOSE && mosq->wsd.payloadlen == 1){
			mosq->wsd.disconnect_reason = 0xEA;
			errno = EPROTO;
			return -1;
		}else if(mosq->wsd.payloadlen > 125 && mosq->wsd.opcode != WS_BINARY && mosq->wsd.opcode != WS_CONTINUATION){
			mosq->wsd.disconnect_reason = 0xEA;
			errno = EPROTO;
			return -1;
		}

		if(mosq->wsd.payloadlen > MQTT_MAX_PAYLOAD){
			errno = EPROTO;
			return -1;
		}

#ifndef WS_TESTING
		if(mosq->wsd.opcode == WS_PING || (mosq->wsd.opcode == WS_CLOSE && mosq->wsd.payloadlen >= 2))
		/* Always allocate payload for testing case, otherwise just for pings */
#endif
		{
			mosq->wsd.out_packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet) + WS_PACKET_OFFSET + mosq->wsd.payloadlen + 1);
			if(mosq->wsd.out_packet == NULL){
				errno = ENOMEM;
				return -1;
			}
			mosq->wsd.out_packet->packet_length = (uint32_t)mosq->wsd.payloadlen + WS_PACKET_OFFSET;
		}
	}

	if(mosq->wsd.out_packet){
		/* This means we are either dealing with protocol level messages (and
		 * hence won't be returning MQTT data to the context), or we are
		 * testing and should be echoing data back to the client.
		 * So ignore what data is being asked for, and try and read the whole
		 * lot at once. */
		count = mosq->wsd.payloadlen - (uint64_t)mosq->wsd.pos;
		buf = &mosq->wsd.out_packet->payload[WS_PACKET_OFFSET + mosq->wsd.pos];
	}

	if(mosq->wsd.payloadlen > 0){
		if(count > mosq->wsd.payloadlen - (uint64_t)mosq->wsd.pos){
			count = mosq->wsd.payloadlen - (uint64_t)mosq->wsd.pos;
		}
		len = net__read(mosq, buf, count);
		if(len > 0){
			for(ssize_t i=0; i<len; i++){
				((uint8_t *)buf)[i] ^= mosq->wsd.maskingkey[(i+mosq->wsd.pos)%4];
			}
			mosq->wsd.pos += len;
		}
	}

	if(mosq->wsd.pos == (ssize_t)mosq->wsd.payloadlen){
		if(mosq->wsd.opcode == WS_CLOSE){
			mosquitto__FREE(mosq->wsd.out_packet);

			/* Testing or PING - so we haven't read any data for the application yet. */
			len = -1;
			errno = EAGAIN;
		}else if(mosq->wsd.opcode == WS_PONG){
			mosquitto__FREE(mosq->wsd.out_packet);
			/* Testing or PING - so we haven't read any data for the application yet. */
			len = -1;
			errno = EAGAIN;
		}else if(mosq->wsd.out_packet){
			packet__queue(mosq, mosq->wsd.out_packet);
			mosq->wsd.out_packet = NULL;

			/* Testing or PING - so we haven't read any data for the application yet.
			* Simulate that situation. This has to be done *after* the call to
			* packet__queue. */
			len = -1;
			errno = EAGAIN;
		}
		mosq->wsd.payloadlen = 0;
		mosq->wsd.opcode = UINT8_MAX;
		mosq->wsd.mask = UINT8_MAX;
	}else if(mosq->wsd.out_packet){
		/* Testing or PING - so we haven't read any data for the application yet.
		* Simulate that situation.*/
		len = -1;
		errno = EAGAIN;
	}
	return len;
}

int ws__create_accept_key(const char *client_key, size_t client_key_len, char **encoded)
{
	const EVP_MD *digest;
	EVP_MD_CTX *evp;
	uint8_t accept_key_hash[EVP_MAX_MD_SIZE];
	unsigned int accept_key_hash_len;

	digest = EVP_get_digestbyname("sha1");
	if(!digest){
		return MOSQ_ERR_UNKNOWN;
	}

	evp = EVP_MD_CTX_new();
	if(EVP_DigestInit_ex(evp, digest, NULL) == 0){
		EVP_MD_CTX_free(evp);
		return MOSQ_ERR_UNKNOWN;
	}
	if(EVP_DigestUpdate(evp, client_key, client_key_len) == 0){
		EVP_MD_CTX_free(evp);
		return MOSQ_ERR_UNKNOWN;
	}
	if(EVP_DigestUpdate(evp, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11",
				strlen("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) == 0){

		EVP_MD_CTX_free(evp);
		return MOSQ_ERR_UNKNOWN;
	}
	if(EVP_DigestFinal_ex(evp, accept_key_hash, &accept_key_hash_len) == 0){
		EVP_MD_CTX_free(evp);
		return MOSQ_ERR_UNKNOWN;
	}
	EVP_MD_CTX_free(evp);

	return base64__encode(accept_key_hash, accept_key_hash_len, encoded);
}


#endif
