/*
Copyright (c) 2014-2018 Roger Light <roger@atchoo.org>

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

#include <errno.h>
#include <string.h>

#include "mosquitto_internal.h"
#include "memory_mosq.h"
#include "net_mosq.h"
#include "send_mosq.h"

#define SOCKS_AUTH_NONE 0x00
#define SOCKS_AUTH_GSS 0x01
#define SOCKS_AUTH_USERPASS 0x02
#define SOCKS_AUTH_NO_ACCEPTABLE 0xFF

#define SOCKS_ATYPE_IP_V4 1 /* four bytes */
#define SOCKS_ATYPE_DOMAINNAME 3 /* one byte length, followed by fqdn no null, 256 max chars */
#define SOCKS_ATYPE_IP_V6 4 /* 16 bytes */

#define SOCKS_REPLY_SUCCEEDED 0x00
#define SOCKS_REPLY_GENERAL_FAILURE 0x01
#define SOCKS_REPLY_CONNECTION_NOT_ALLOWED 0x02
#define SOCKS_REPLY_NETWORK_UNREACHABLE 0x03
#define SOCKS_REPLY_HOST_UNREACHABLE 0x04
#define SOCKS_REPLY_CONNECTION_REFUSED 0x05
#define SOCKS_REPLY_TTL_EXPIRED 0x06
#define SOCKS_REPLY_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED 0x08

int mosquitto_socks5_set(struct mosquitto *mosq, const char *host, int port, const char *username, const char *password)
{
#ifdef WITH_SOCKS
	if(!mosq) return MOSQ_ERR_INVAL;
	if(!host || strlen(host) > 256) return MOSQ_ERR_INVAL;
	if(port < 1 || port > 65535) return MOSQ_ERR_INVAL;

	if(mosq->socks5_host){
		_mosquitto_free(mosq->socks5_host);
	}

	mosq->socks5_host = _mosquitto_strdup(host);
	if(!mosq->socks5_host){
		return MOSQ_ERR_NOMEM;
	}

	mosq->socks5_port = port;

	if(mosq->socks5_username){
		_mosquitto_free(mosq->socks5_username);
	}
	if(mosq->socks5_password){
		_mosquitto_free(mosq->socks5_password);
	}

	if(username){
		mosq->socks5_username = _mosquitto_strdup(username);
		if(!mosq->socks5_username){
			return MOSQ_ERR_NOMEM;
		}

		if(password){
			mosq->socks5_password = _mosquitto_strdup(password);
			if(!mosq->socks5_password){
				_mosquitto_free(mosq->socks5_username);
				return MOSQ_ERR_NOMEM;
			}
		}
	}

	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}

#ifdef WITH_SOCKS
int mosquitto__socks5_send(struct mosquitto *mosq)
{
	struct _mosquitto_packet *packet;
	int slen;
	int ulen, plen;

	if(mosq->state == mosq_cs_socks5_new){
		packet = _mosquitto_calloc(1, sizeof(struct _mosquitto_packet));
		if(!packet) return MOSQ_ERR_NOMEM;

		if(mosq->socks5_username){
			packet->packet_length = 4;
		}else{
			packet->packet_length = 3;
		}
		packet->payload = _mosquitto_malloc(sizeof(uint8_t)*packet->packet_length);

		packet->payload[0] = 0x05;
		if(mosq->socks5_username){
			packet->payload[1] = 2;
			packet->payload[2] = SOCKS_AUTH_NONE;
			packet->payload[3] = SOCKS_AUTH_USERPASS;
		}else{
			packet->payload[1] = 1;
			packet->payload[2] = SOCKS_AUTH_NONE;
		}

		pthread_mutex_lock(&mosq->state_mutex);
		mosq->state = mosq_cs_socks5_start;
		pthread_mutex_unlock(&mosq->state_mutex);

		mosq->in_packet.pos = 0;
		mosq->in_packet.packet_length = 2;
		mosq->in_packet.to_process = 2;
		mosq->in_packet.payload = _mosquitto_malloc(sizeof(uint8_t)*2);
		if(!mosq->in_packet.payload){
			_mosquitto_free(packet->payload);
			_mosquitto_free(packet);
			return MOSQ_ERR_NOMEM;
		}

		return _mosquitto_packet_queue(mosq, packet);
	}else if(mosq->state == mosq_cs_socks5_auth_ok){
		packet = _mosquitto_calloc(1, sizeof(struct _mosquitto_packet));
		if(!packet) return MOSQ_ERR_NOMEM;

		packet->packet_length = 7+strlen(mosq->host);
		packet->payload = _mosquitto_malloc(sizeof(uint8_t)*packet->packet_length);

		slen = strlen(mosq->host);

		packet->payload[0] = 0x05;
		packet->payload[1] = 1;
		packet->payload[2] = 0;
		packet->payload[3] = SOCKS_ATYPE_DOMAINNAME;
		packet->payload[4] = slen;
		memcpy(&(packet->payload[5]), mosq->host, slen);
		packet->payload[5+slen] = MOSQ_MSB(mosq->port);
		packet->payload[6+slen] = MOSQ_LSB(mosq->port);

		pthread_mutex_lock(&mosq->state_mutex);
		mosq->state = mosq_cs_socks5_request;
		pthread_mutex_unlock(&mosq->state_mutex);

		mosq->in_packet.pos = 0;
		mosq->in_packet.packet_length = 5;
		mosq->in_packet.to_process = 5;
		mosq->in_packet.payload = _mosquitto_malloc(sizeof(uint8_t)*5);
		if(!mosq->in_packet.payload){
			_mosquitto_free(packet->payload);
			_mosquitto_free(packet);
			return MOSQ_ERR_NOMEM;
		}

		return _mosquitto_packet_queue(mosq, packet);
	}else if(mosq->state == mosq_cs_socks5_send_userpass){
		packet = _mosquitto_calloc(1, sizeof(struct _mosquitto_packet));
		if(!packet) return MOSQ_ERR_NOMEM;

		ulen = strlen(mosq->socks5_username);
		plen = strlen(mosq->socks5_password);
		packet->packet_length = 3 + ulen + plen;
		packet->payload = _mosquitto_malloc(sizeof(uint8_t)*packet->packet_length);


		packet->payload[0] = 0x01;
		packet->payload[1] = ulen;
		memcpy(&(packet->payload[2]), mosq->socks5_username, ulen);
		packet->payload[2+ulen] = plen;
		memcpy(&(packet->payload[3+ulen]), mosq->socks5_password, plen);

		pthread_mutex_lock(&mosq->state_mutex);
		mosq->state = mosq_cs_socks5_userpass_reply;
		pthread_mutex_unlock(&mosq->state_mutex);

		mosq->in_packet.pos = 0;
		mosq->in_packet.packet_length = 2;
		mosq->in_packet.to_process = 2;
		mosq->in_packet.payload = _mosquitto_malloc(sizeof(uint8_t)*2);
		if(!mosq->in_packet.payload){
			_mosquitto_free(packet->payload);
			_mosquitto_free(packet);
			return MOSQ_ERR_NOMEM;
		}

		return _mosquitto_packet_queue(mosq, packet);
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto__socks5_read(struct mosquitto *mosq)
{
	ssize_t len;
	uint8_t *payload;
	uint8_t i;

	if(mosq->state == mosq_cs_socks5_start){
		while(mosq->in_packet.to_process > 0){
			len = _mosquitto_net_read(mosq, &(mosq->in_packet.payload[mosq->in_packet.pos]), mosq->in_packet.to_process);
			if(len > 0){
				mosq->in_packet.pos += len;
				mosq->in_packet.to_process -= len;
			}else{
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
					return MOSQ_ERR_SUCCESS;
				}else{
					_mosquitto_packet_cleanup(&mosq->in_packet);
					switch(errno){
						case 0:
							return MOSQ_ERR_PROXY;
						case COMPAT_ECONNRESET:
							return MOSQ_ERR_CONN_LOST;
						default:
							return MOSQ_ERR_ERRNO;
					}
				}
			}
		}
		if(mosq->in_packet.payload[0] != 5){
			_mosquitto_packet_cleanup(&mosq->in_packet);
			return MOSQ_ERR_PROXY;
		}
		switch(mosq->in_packet.payload[1]){
			case SOCKS_AUTH_NONE:
				_mosquitto_packet_cleanup(&mosq->in_packet);
				mosq->state = mosq_cs_socks5_auth_ok;
				return mosquitto__socks5_send(mosq);
			case SOCKS_AUTH_USERPASS:
				_mosquitto_packet_cleanup(&mosq->in_packet);
				mosq->state = mosq_cs_socks5_send_userpass;
				return mosquitto__socks5_send(mosq);
			default:
				_mosquitto_packet_cleanup(&mosq->in_packet);
				return MOSQ_ERR_AUTH;
		}
	}else if(mosq->state == mosq_cs_socks5_userpass_reply){
		while(mosq->in_packet.to_process > 0){
			len = _mosquitto_net_read(mosq, &(mosq->in_packet.payload[mosq->in_packet.pos]), mosq->in_packet.to_process);
			if(len > 0){
				mosq->in_packet.pos += len;
				mosq->in_packet.to_process -= len;
			}else{
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
					return MOSQ_ERR_SUCCESS;
				}else{
					_mosquitto_packet_cleanup(&mosq->in_packet);
					switch(errno){
						case 0:
							return MOSQ_ERR_PROXY;
						case COMPAT_ECONNRESET:
							return MOSQ_ERR_CONN_LOST;
						default:
							return MOSQ_ERR_ERRNO;
					}
				}
			}
		}
		if(mosq->in_packet.payload[0] != 1){
			_mosquitto_packet_cleanup(&mosq->in_packet);
			return MOSQ_ERR_PROXY;
		}
		if(mosq->in_packet.payload[1] == 0){
			_mosquitto_packet_cleanup(&mosq->in_packet);
			mosq->state = mosq_cs_socks5_auth_ok;
			return mosquitto__socks5_send(mosq);
		}else{
			i = mosq->in_packet.payload[1];
			_mosquitto_packet_cleanup(&mosq->in_packet);
			switch(i){
				case SOCKS_REPLY_CONNECTION_NOT_ALLOWED:
					return MOSQ_ERR_AUTH;

				case SOCKS_REPLY_NETWORK_UNREACHABLE:
				case SOCKS_REPLY_HOST_UNREACHABLE:
				case SOCKS_REPLY_CONNECTION_REFUSED:
					return MOSQ_ERR_NO_CONN;

				case SOCKS_REPLY_GENERAL_FAILURE:
				case SOCKS_REPLY_TTL_EXPIRED:
				case SOCKS_REPLY_COMMAND_NOT_SUPPORTED:
				case SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED:
					return MOSQ_ERR_PROXY;

				default:
					return MOSQ_ERR_INVAL;
			}
			return MOSQ_ERR_PROXY;
		}
	}else if(mosq->state == mosq_cs_socks5_request){
		while(mosq->in_packet.to_process > 0){
			len = _mosquitto_net_read(mosq, &(mosq->in_packet.payload[mosq->in_packet.pos]), mosq->in_packet.to_process);
			if(len > 0){
				mosq->in_packet.pos += len;
				mosq->in_packet.to_process -= len;
			}else{
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
					return MOSQ_ERR_SUCCESS;
				}else{
					_mosquitto_packet_cleanup(&mosq->in_packet);
					switch(errno){
						case 0:
							return MOSQ_ERR_PROXY;
						case COMPAT_ECONNRESET:
							return MOSQ_ERR_CONN_LOST;
						default:
							return MOSQ_ERR_ERRNO;
					}
				}
			}
		}

		if(mosq->in_packet.packet_length == 5){
			/* First part of the packet has been received, we now know what else to expect. */
			if(mosq->in_packet.payload[3] == SOCKS_ATYPE_IP_V4){
				mosq->in_packet.to_process += 4+2-1; /* 4 bytes IPv4, 2 bytes port, -1 byte because we've already read the first byte */
				mosq->in_packet.packet_length += 4+2-1;
			}else if(mosq->in_packet.payload[3] == SOCKS_ATYPE_IP_V6){
				mosq->in_packet.to_process += 16+2-1; /* 16 bytes IPv6, 2 bytes port, -1 byte because we've already read the first byte */
				mosq->in_packet.packet_length += 16+2-1;
			}else if(mosq->in_packet.payload[3] == SOCKS_ATYPE_DOMAINNAME){
				if(mosq->in_packet.payload[4] > 0 && mosq->in_packet.payload[4] <= 255){
					mosq->in_packet.to_process += mosq->in_packet.payload[4];
					mosq->in_packet.packet_length += mosq->in_packet.payload[4];
				}
			}else{
				_mosquitto_packet_cleanup(&mosq->in_packet);
				return MOSQ_ERR_PROTOCOL;
			}
			payload = _mosquitto_realloc(mosq->in_packet.payload, mosq->in_packet.packet_length);
			if(payload){
				mosq->in_packet.payload = payload;
			}else{
				_mosquitto_packet_cleanup(&mosq->in_packet);
				return MOSQ_ERR_NOMEM;
			}
			return MOSQ_ERR_SUCCESS;
		}

		/* Entire packet is now read. */
		if(mosq->in_packet.payload[0] != 5){
			_mosquitto_packet_cleanup(&mosq->in_packet);
			return MOSQ_ERR_PROXY;
		}
		if(mosq->in_packet.payload[1] == 0){
			/* Auth passed */
			_mosquitto_packet_cleanup(&mosq->in_packet);
			mosq->state = mosq_cs_new;
			return _mosquitto_send_connect(mosq, mosq->keepalive, mosq->clean_session);
		}else{
			i = mosq->in_packet.payload[1];
			_mosquitto_packet_cleanup(&mosq->in_packet);
			mosq->state = mosq_cs_socks5_new;
			switch(i){
				case SOCKS_REPLY_CONNECTION_NOT_ALLOWED:
					return MOSQ_ERR_AUTH;

				case SOCKS_REPLY_NETWORK_UNREACHABLE:
				case SOCKS_REPLY_HOST_UNREACHABLE:
				case SOCKS_REPLY_CONNECTION_REFUSED:
					return MOSQ_ERR_NO_CONN;

				case SOCKS_REPLY_GENERAL_FAILURE:
				case SOCKS_REPLY_TTL_EXPIRED:
				case SOCKS_REPLY_COMMAND_NOT_SUPPORTED:
				case SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED:
					return MOSQ_ERR_PROXY;

				default:
					return MOSQ_ERR_INVAL;
			}
		}
	}else{
		return _mosquitto_packet_read(mosq);
	}
	return MOSQ_ERR_SUCCESS;
}
#endif
