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

#include "mosquitto_broker_internal.h"
#include "base64_mosq.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "sys_tree.h"
#include "util_mosq.h"
#include "picohttpparser.h"


int http__context_init(struct mosquitto *context)
{
	context->transport = mosq_t_http;
	context->http_request = mosquitto__calloc(1, db.config->websockets_headers_size);
	if(context->http_request == NULL){
		return MOSQ_ERR_NOMEM;
	}

	return MOSQ_ERR_SUCCESS;
}


int http__context_cleanup(struct mosquitto *context)
{
	mosquitto__FREE(context->http_request);
	return MOSQ_ERR_SUCCESS;
}


int http__write(struct mosquitto *mosq)
{
	return packet__write(mosq);
}


static int first_entry(const char *s, int len)
{
	int i;

	for(i=0; i<len; i++){
		if(s[i] == '\0' || s[i] == ','){
			return i;
		}
	}
	return len;
}

int http__read(struct mosquitto *mosq)
{
	ssize_t read_length;
	enum mosquitto_client_state state;
	size_t hlen;
	const char *http_method, *http_path;
	size_t http_method_len, http_path_len;
	int http_minor_version;
	size_t http_header_count = 100;
	struct phr_header http_headers[100];
	const char *client_key = NULL;
	size_t client_key_len = 0;
	char *accept_key;
	size_t i;
	bool header_have_upgrade;
	bool header_have_connection;
	struct mosquitto__packet *packet;
	int rc;
	const char *subprotocol = NULL;
	int subprotocol_len;
	const char *forwarded_for = NULL;
	int forwarded_for_len;

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
	read_length = net__read(mosq, &mosq->http_request[hlen], db.config->websockets_headers_size-hlen);
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

	mosq->http_request[db.config->websockets_headers_size-1] = '\0'; /* Always 0 terminate */
	read_length = phr_parse_request(mosq->http_request, strlen(mosq->http_request),
			&http_method, &http_method_len,
			&http_path, &http_path_len,
			&http_minor_version,
			http_headers, &http_header_count,
			0);
	// FIXME - deal with partial read !
	if(read_length == -2){
		// Partial read
		return MOSQ_ERR_SUCCESS;
	}else if(read_length == -1){
		// Error
		return MOSQ_ERR_UNKNOWN;
	}

	if(strncmp(http_method, "GET", http_method_len) && strncmp(http_method, "HEAD", http_method_len)){
		mosquitto__FREE(mosq->http_request);
		/* FIXME Not supported - send 501 response */
		return MOSQ_ERR_UNKNOWN;
	}

	header_have_upgrade = false;
	header_have_connection = false;
	subprotocol = NULL;

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
		}else if(!strncasecmp(http_headers[i].name, "Sec-WebSocket-Key", http_headers[i].name_len)){
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
			if(!strncmp(http_headers[i].value, "mqtt", http_headers[i].value_len)
					|| !strncmp(http_headers[i].value, "mqttv3.1", http_headers[i].value_len)){

				subprotocol = http_headers[i].value;
				subprotocol_len = (int)http_headers[i].value_len;
			}
		}else if(!strncasecmp(http_headers[i].name, "X-Forwarded-For", http_headers[i].name_len)){
			forwarded_for = http_headers[i].value;
			forwarded_for_len = first_entry(forwarded_for, (int)http_headers[i].value_len);

			mosquitto__FREE(mosq->address);
			mosq->address = mosquitto__malloc((size_t)forwarded_for_len+1);
			if(!mosq->address){
				return MOSQ_ERR_NOMEM;
			}
			strncpy(mosq->address, forwarded_for, (size_t)forwarded_for_len);
			mosq->address[forwarded_for_len] = '\0';
		}else if(!strncasecmp(http_headers[i].name, "Origin", http_headers[i].name_len)){
			if(mosq->listener){
				bool have_match = false;
				for(int j=0; j<mosq->listener->ws_origin_count; j++){
					if(!strncmp(mosq->listener->ws_origins[j], http_headers[i].value, http_headers[i].value_len)){
						have_match = true;
						break;
					}
				}
				if(!have_match && mosq->listener->ws_origin_count > 0){
					return MOSQ_ERR_HTTP_BAD_ORIGIN;
				}
			}
		}else{
			/* Unknown header */
		}
	}

	if(subprotocol == NULL){
		// FIXME ?
		return MOSQ_ERR_UNKNOWN;
	}

	if(header_have_upgrade == false || header_have_connection == false
			|| client_key == NULL || client_key_len == 0){

		// FIXME - 404
		return MOSQ_ERR_UNKNOWN;
	}

	if(ws__create_accept_key(client_key, client_key_len, &accept_key)){
		return MOSQ_ERR_UNKNOWN;
	}

	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet) + 1024 + WS_PACKET_OFFSET);
	if(!packet){
		SAFE_FREE(accept_key);
		return MOSQ_ERR_NOMEM;
	}
	packet->packet_length = (uint32_t )snprintf((char *)&packet->payload[WS_PACKET_OFFSET], 1024,
			"HTTP/1.1 101 Switching Protocols\r\n"
			"Upgrade: WebSocket\r\n"
			"Connection: Upgrade\r\n"
			"Sec-WebSocket-Accept: %s\r\n"
			"Sec-WebSocket-Protocol: %.*s\r\n"
			"\r\n", accept_key, subprotocol_len, subprotocol) + WS_PACKET_OFFSET;
	SAFE_FREE(accept_key);
	packet->to_process = packet->packet_length;

	memset(mosq->http_request, 0, db.config->websockets_headers_size);
	rc = packet__queue(mosq, packet);
	http__context_cleanup(mosq);
	ws__context_init(mosq);
	return rc;
}
#endif
