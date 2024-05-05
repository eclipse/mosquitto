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

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "mosquitto_internal.h"
#include "http_client.h"
#include "mosquitto/mqtt_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "util_mosq.h"
#include "picohttpparser.h"


static int create_request_key(char **encoded)
{
	uint8_t bytes[16];
	mosquitto_getrandom(bytes, sizeof(bytes));
	return mosquitto_base64_encode(bytes, sizeof(bytes), encoded);
}


int http_c__context_init(struct mosquitto *context)
{
	struct mosquitto__packet *packet;
	char *key;
	const char *path;

	context->transport = mosq_t_http;
	context->http_request = mosquitto_calloc(1, (size_t)context->wsd.http_header_size + 1);
	if(context->http_request == NULL){
		return MOSQ_ERR_NOMEM;
	}

	if(create_request_key(&key)){
		return MOSQ_ERR_UNKNOWN;
	}
	if(ws__create_accept_key(key, strlen(key), &context->wsd.accept_key)){
		return MOSQ_ERR_UNKNOWN;
	}

	packet = mosquitto_calloc(1, sizeof(struct mosquitto__packet) + 1024 + WS_PACKET_OFFSET);
	if(!packet) return MOSQ_ERR_NOMEM;

	path = context->wsd.http_path?context->wsd.http_path:"/mqtt";

	packet->packet_length = (uint32_t )snprintf((char *)&packet->payload[WS_PACKET_OFFSET], 1024,
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Protocol: mqtt\r\n"
        "Sec-WebSocket-Version: 13\r\n"
		"\r\n", path, context->host, key);
	mosquitto_FREE(key);
	packet->packet_length += WS_PACKET_OFFSET;
	packet->to_process = packet->packet_length;
	context->http_request[0] = '\0';
	return packet__queue(context, packet);
}


int http_c__context_cleanup(struct mosquitto *context)
{
	mosquitto_FREE(context->wsd.accept_key);
	mosquitto_FREE(context->http_request);
	return MOSQ_ERR_SUCCESS;
}


int http_c__read(struct mosquitto *mosq)
{
	ssize_t read_length;
	enum mosquitto_client_state state;
	size_t hlen;
	int http_status;
	const char *http_msg;
	size_t http_msg_len;
	int http_minor_version;
	size_t http_header_count = 100;
	struct phr_header http_headers[100];
	const char *client_key = NULL;
	size_t client_key_len = 0;
	size_t i;
	bool header_have_upgrade;
	bool header_have_connection;
	bool header_have_subprotocol;
	int rc = MOSQ_ERR_SUCCESS;

	if(!mosq){
		return MOSQ_ERR_INVAL;
	}
	if(mosq->sock == INVALID_SOCKET){
		return MOSQ_ERR_NO_CONN;
	}

	state = mosquitto__get_state(mosq);
	if(state == mosq_cs_connect_pending){
		return MOSQ_ERR_SUCCESS;
	}

	hlen = strlen(mosq->http_request);
	read_length = net__read(mosq, &mosq->http_request[hlen], (size_t)mosq->wsd.http_header_size-hlen);
	if(read_length <= 0){
		if(read_length == 0){
			return MOSQ_ERR_CONN_LOST; /* EOF */
		}
#ifdef WIN32
		errno = WSAGetLastError();
#endif
		if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
			return MOSQ_ERR_SUCCESS;
		}else{
			switch(errno){
				case COMPAT_ECONNRESET:
					return MOSQ_ERR_CONN_LOST;
				case COMPAT_EINTR:
					return MOSQ_ERR_SUCCESS;
				default:
					return MOSQ_ERR_ERRNO;
			}
		}
	}
	hlen += (size_t)read_length;
	mosq->http_request[hlen] = '\0';

	read_length = phr_parse_response(mosq->http_request, hlen,
			&http_minor_version, &http_status,
			&http_msg, &http_msg_len,
			http_headers, &http_header_count,
			0);
	if(read_length == -2){
		// Partial read
		return MOSQ_ERR_SUCCESS;
	}else if(read_length == -1){
		// Error
		return MOSQ_ERR_UNKNOWN;
	}

	if(http_status != 101){
		mosquitto_FREE(mosq->http_request);
		/* FIXME Not supported - send 501 response */
		return MOSQ_ERR_UNKNOWN;
	}

	header_have_upgrade = false;
	header_have_connection = false;
	header_have_subprotocol = false;

	for(i=0; i<http_header_count; i++){
		if(!strncasecmp(http_headers[i].name, "Upgrade", http_headers[i].name_len)){
			if(!strncasecmp(http_headers[i].value, "websocket", http_headers[i].value_len)){
				header_have_upgrade = true;
			}
		}else if(!strncasecmp(http_headers[i].name, "Connection", http_headers[i].name_len)){
			/* Check for "upgrade" */
			const char *str = http_headers[i].value;
			size_t start = 0;
			size_t j = 0;
			for(j=0; j<http_headers[i].value_len; j++){
				if(str[j] == ','){
					if(!strncasecmp(&str[start], "upgrade", http_headers[i].value_len-j)){
						header_have_connection = true;
						break;
					}else{
						start = j+1;
					}
				}else if(str[j] == ' '){
					start = j+1;
				}
			}
			if(!strncasecmp(&str[start], "upgrade", http_headers[i].value_len-j)){
				header_have_connection = true;
			}
		}else if(!strncasecmp(http_headers[i].name, "Sec-WebSocket-Accept", http_headers[i].name_len)){
			client_key = http_headers[i].value;
			client_key_len = http_headers[i].value_len;
		}else if(!strncasecmp(http_headers[i].name, "Sec-WebSocket-Version", http_headers[i].name_len)){
			/* Check for "13" */
			if(http_headers[i].value_len != 2
					|| http_headers[i].value[0] != '1'
					|| http_headers[i].value[1] != '3'
					){

				/* FIXME - not supported */
				return MOSQ_ERR_NOT_SUPPORTED;
			}
		}else if(!strncasecmp(http_headers[i].name, "Sec-WebSocket-Protocol", http_headers[i].name_len)){
			/* Check for "mqtt" */
			if(!strncmp(http_headers[i].value, "mqtt", http_headers[i].value_len)){
				header_have_subprotocol = true;
			}
		}else{
			/* Unknown header */
		}
	}

	if(header_have_upgrade == false || header_have_connection == false || header_have_subprotocol == false
			|| client_key == NULL || client_key_len == 0){

		// FIXME - 404
		return MOSQ_ERR_UNKNOWN;
	}
	if(strncmp(mosq->wsd.accept_key, client_key, client_key_len)){
		// FIXME - 50x
		return MOSQ_ERR_UNKNOWN;
	}

	http_c__context_cleanup(mosq);
	ws__context_init(mosq);

	//* FIXME outgoing properites
	rc = send__connect(mosq, mosq->keepalive, mosq->clean_start, NULL);
	if(rc){
		packet__cleanup_all(mosq);
		net__socket_close(mosq);
		mosquitto__set_state(mosq, mosq_cs_new);
	}
	return rc;
}

#endif
