/*
Copyright (c) 2014-2020 Roger Light <roger@atchoo.org>

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

#include <errno.h>
#include <string.h>
#include <limits.h>
#ifdef WIN32
#  include <ws2tcpip.h>
#elif __QNX__
#  include <sys/socket.h>
#  include <arpa/inet.h>
#  include <netinet/in.h>
#else
#  include <arpa/inet.h>
#endif
#if defined(__FreeBSD__) || defined(__OpenBSD__)
#  include <sys/socket.h>
#  include <netinet/in.h>
#endif

#include "mosquitto_internal.h"
#include "memory_mosq.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "send_mosq.h"
#include "util_mosq.h"

#define SOCKS_AUTH_NONE 0x00U
#define SOCKS_AUTH_GSS 0x01U
#define SOCKS_AUTH_USERPASS 0x02U
#define SOCKS_AUTH_NO_ACCEPTABLE 0xFFU

#define SOCKS_ATYPE_IP_V4 1U /* four bytes */
#define SOCKS_ATYPE_DOMAINNAME 3U /* one byte length, followed by fqdn no null, 256 max chars */
#define SOCKS_ATYPE_IP_V6 4U /* 16 bytes */

#define SOCKS_REPLY_SUCCEEDED 0x00U
#define SOCKS_REPLY_GENERAL_FAILURE 0x01U
#define SOCKS_REPLY_CONNECTION_NOT_ALLOWED 0x02U
#define SOCKS_REPLY_NETWORK_UNREACHABLE 0x03U
#define SOCKS_REPLY_HOST_UNREACHABLE 0x04U
#define SOCKS_REPLY_CONNECTION_REFUSED 0x05U
#define SOCKS_REPLY_TTL_EXPIRED 0x06U
#define SOCKS_REPLY_COMMAND_NOT_SUPPORTED 0x07U
#define SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED 0x08U

int mosquitto_socks5_set(struct mosquitto *mosq, const char *host, int port, const char *username, const char *password)
{
#ifdef WITH_SOCKS
	if(!mosq) return MOSQ_ERR_INVAL;
	if(!host || strlen(host) > 256) return MOSQ_ERR_INVAL;
	if(port < 1 || port > UINT16_MAX) return MOSQ_ERR_INVAL;

	mosquitto__free(mosq->socks5_host);
	mosq->socks5_host = NULL;

	mosq->socks5_host = mosquitto__strdup(host);
	if(!mosq->socks5_host){
		return MOSQ_ERR_NOMEM;
	}

	mosq->socks5_port = (uint16_t)port;

	mosquitto__free(mosq->socks5_username);
	mosq->socks5_username = NULL;

	mosquitto__free(mosq->socks5_password);
	mosq->socks5_password = NULL;

	if(username){
		if(strlen(username) > UINT8_MAX){
			return MOSQ_ERR_INVAL;
		}
		mosq->socks5_username = mosquitto__strdup(username);
		if(!mosq->socks5_username){
			return MOSQ_ERR_NOMEM;
		}

		if(password){
			if(strlen(password) > UINT8_MAX){
				return MOSQ_ERR_INVAL;
			}
			mosq->socks5_password = mosquitto__strdup(password);
			if(!mosq->socks5_password){
				mosquitto__free(mosq->socks5_username);
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
int socks5__send(struct mosquitto *mosq)
{
	struct mosquitto__packet *packet;
	size_t slen;
	uint8_t ulen, plen;

	struct in_addr addr_ipv4;
	struct in6_addr addr_ipv6;
	int ipv4_pton_result;
	int ipv6_pton_result;
	enum mosquitto_client_state state;

	state = mosquitto__get_state(mosq);

	if(state == mosq_cs_socks5_new){
		packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
		if(!packet) return MOSQ_ERR_NOMEM;

		if(mosq->socks5_username){
			packet->packet_length = 4;
		}else{
			packet->packet_length = 3;
		}
		packet->payload = mosquitto__malloc(sizeof(uint8_t)*packet->packet_length);

		packet->payload[0] = 0x05;
		if(mosq->socks5_username){
			packet->payload[1] = 2;
			packet->payload[2] = SOCKS_AUTH_NONE;
			packet->payload[3] = SOCKS_AUTH_USERPASS;
		}else{
			packet->payload[1] = 1;
			packet->payload[2] = SOCKS_AUTH_NONE;
		}

		mosquitto__set_state(mosq, mosq_cs_socks5_start);

		mosq->in_packet.pos = 0;
		mosq->in_packet.packet_length = 2;
		mosq->in_packet.to_process = 2;
		mosq->in_packet.payload = mosquitto__malloc(sizeof(uint8_t)*2);
		if(!mosq->in_packet.payload){
			mosquitto__free(packet->payload);
			mosquitto__free(packet);
			return MOSQ_ERR_NOMEM;
		}

		return packet__queue(mosq, packet);
	}else if(state == mosq_cs_socks5_auth_ok){
		packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
		if(!packet) return MOSQ_ERR_NOMEM;

		ipv4_pton_result = inet_pton(AF_INET, mosq->host, &addr_ipv4);
		ipv6_pton_result = inet_pton(AF_INET6, mosq->host, &addr_ipv6);

		if(ipv4_pton_result == 1){
			packet->packet_length = 10;
			packet->payload = mosquitto__malloc(sizeof(uint8_t)*packet->packet_length);
			if(!packet->payload){
				mosquitto__free(packet);
				return MOSQ_ERR_NOMEM;
			}
			packet->payload[3] = SOCKS_ATYPE_IP_V4;
			memcpy(&(packet->payload[4]), (const void*)&addr_ipv4, 4);
			packet->payload[4+4] = MOSQ_MSB(mosq->port);
			packet->payload[4+4+1] = MOSQ_LSB(mosq->port);

		}else if(ipv6_pton_result == 1){
			packet->packet_length = 22;
			packet->payload = mosquitto__malloc(sizeof(uint8_t)*packet->packet_length);
			if(!packet->payload){
				mosquitto__free(packet);
				return MOSQ_ERR_NOMEM;
			}
			packet->payload[3] = SOCKS_ATYPE_IP_V6;
			memcpy(&(packet->payload[4]), (const void*)&addr_ipv6, 16);
			packet->payload[4+16] = MOSQ_MSB(mosq->port);
			packet->payload[4+16+1] = MOSQ_LSB(mosq->port);

		}else{
			slen = strlen(mosq->host);
			if(slen > UCHAR_MAX){
				mosquitto__free(packet);
				return MOSQ_ERR_NOMEM;
			}
			packet->packet_length = 7U + (uint32_t)slen;
			packet->payload = mosquitto__malloc(sizeof(uint8_t)*packet->packet_length);
			if(!packet->payload){
				mosquitto__free(packet);
				return MOSQ_ERR_NOMEM;
			}
			packet->payload[3] = SOCKS_ATYPE_DOMAINNAME;
			packet->payload[4] = (uint8_t)slen;
			memcpy(&(packet->payload[5]), mosq->host, slen);
			packet->payload[5+slen] = MOSQ_MSB(mosq->port);
			packet->payload[6+slen] = MOSQ_LSB(mosq->port);
		}
		packet->payload[0] = 0x05;
		packet->payload[1] = 0x01;
		packet->payload[2] = 0x00;

		mosquitto__set_state(mosq, mosq_cs_socks5_request);

		mosq->in_packet.pos = 0;
		mosq->in_packet.packet_length = 5;
		mosq->in_packet.to_process = 5;
		mosq->in_packet.payload = mosquitto__malloc(sizeof(uint8_t)*5);
		if(!mosq->in_packet.payload){
			mosquitto__free(packet->payload);
			mosquitto__free(packet);
			return MOSQ_ERR_NOMEM;
		}

		return packet__queue(mosq, packet);
	}else if(state == mosq_cs_socks5_send_userpass){
		packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
		if(!packet) return MOSQ_ERR_NOMEM;

		ulen = (uint8_t)strlen(mosq->socks5_username);
		plen = (uint8_t)strlen(mosq->socks5_password);
		packet->packet_length = 3U + ulen + plen;
		packet->payload = mosquitto__malloc(sizeof(uint8_t)*packet->packet_length);


		packet->payload[0] = 0x01;
		packet->payload[1] = ulen;
		memcpy(&(packet->payload[2]), mosq->socks5_username, ulen);
		packet->payload[2+ulen] = plen;
		memcpy(&(packet->payload[3+ulen]), mosq->socks5_password, plen);

		mosquitto__set_state(mosq, mosq_cs_socks5_userpass_reply);

		mosq->in_packet.pos = 0;
		mosq->in_packet.packet_length = 2;
		mosq->in_packet.to_process = 2;
		mosq->in_packet.payload = mosquitto__malloc(sizeof(uint8_t)*2);
		if(!mosq->in_packet.payload){
			mosquitto__free(packet->payload);
			mosquitto__free(packet);
			return MOSQ_ERR_NOMEM;
		}

		return packet__queue(mosq, packet);
	}
	return MOSQ_ERR_SUCCESS;
}

int socks5__read(struct mosquitto *mosq)
{
	ssize_t len;
	uint8_t *payload;
	uint8_t i;
	enum mosquitto_client_state state;

	state = mosquitto__get_state(mosq);
	if(state == mosq_cs_socks5_start){
		while(mosq->in_packet.to_process > 0){
			len = net__read(mosq, &(mosq->in_packet.payload[mosq->in_packet.pos]), mosq->in_packet.to_process);
			if(len > 0){
				mosq->in_packet.pos += (uint32_t)len;
				mosq->in_packet.to_process -= (uint32_t)len;
			}else{
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
					return MOSQ_ERR_SUCCESS;
				}else{
					packet__cleanup(&mosq->in_packet);
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
			packet__cleanup(&mosq->in_packet);
			return MOSQ_ERR_PROXY;
		}
		switch(mosq->in_packet.payload[1]){
			case SOCKS_AUTH_NONE:
				packet__cleanup(&mosq->in_packet);
				mosquitto__set_state(mosq, mosq_cs_socks5_auth_ok);
				return socks5__send(mosq);
			case SOCKS_AUTH_USERPASS:
				packet__cleanup(&mosq->in_packet);
				mosquitto__set_state(mosq, mosq_cs_socks5_send_userpass);
				return socks5__send(mosq);
			default:
				packet__cleanup(&mosq->in_packet);
				return MOSQ_ERR_AUTH;
		}
	}else if(state == mosq_cs_socks5_userpass_reply){
		while(mosq->in_packet.to_process > 0){
			len = net__read(mosq, &(mosq->in_packet.payload[mosq->in_packet.pos]), mosq->in_packet.to_process);
			if(len > 0){
				mosq->in_packet.pos += (uint32_t)len;
				mosq->in_packet.to_process -= (uint32_t)len;
			}else{
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
					return MOSQ_ERR_SUCCESS;
				}else{
					packet__cleanup(&mosq->in_packet);
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
			packet__cleanup(&mosq->in_packet);
			return MOSQ_ERR_PROXY;
		}
		if(mosq->in_packet.payload[1] == 0){
			packet__cleanup(&mosq->in_packet);
			mosquitto__set_state(mosq, mosq_cs_socks5_auth_ok);
			return socks5__send(mosq);
		}else{
			i = mosq->in_packet.payload[1];
			packet__cleanup(&mosq->in_packet);
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
	}else if(state == mosq_cs_socks5_request){
		while(mosq->in_packet.to_process > 0){
			len = net__read(mosq, &(mosq->in_packet.payload[mosq->in_packet.pos]), mosq->in_packet.to_process);
			if(len > 0){
				mosq->in_packet.pos += (uint32_t)len;
				mosq->in_packet.to_process -= (uint32_t)len;
			}else{
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
					return MOSQ_ERR_SUCCESS;
				}else{
					packet__cleanup(&mosq->in_packet);
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
				if(mosq->in_packet.payload[4] > 0){
					mosq->in_packet.to_process += mosq->in_packet.payload[4];
					mosq->in_packet.packet_length += mosq->in_packet.payload[4];
				}
			}else{
				packet__cleanup(&mosq->in_packet);
				return MOSQ_ERR_PROTOCOL;
			}
			payload = mosquitto__realloc(mosq->in_packet.payload, mosq->in_packet.packet_length);
			if(payload){
				mosq->in_packet.payload = payload;
			}else{
				packet__cleanup(&mosq->in_packet);
				return MOSQ_ERR_NOMEM;
			}
			return MOSQ_ERR_SUCCESS;
		}

		/* Entire packet is now read. */
		if(mosq->in_packet.payload[0] != 5){
			packet__cleanup(&mosq->in_packet);
			return MOSQ_ERR_PROXY;
		}
		if(mosq->in_packet.payload[1] == 0){
			/* Auth passed */
			packet__cleanup(&mosq->in_packet);
			mosquitto__set_state(mosq, mosq_cs_new);
			if(mosq->socks5_host){
				int rc = net__socket_connect_step3(mosq, mosq->host);
				if(rc) return rc;
			}
			return send__connect(mosq, mosq->keepalive, mosq->clean_start, NULL);
		}else{
			i = mosq->in_packet.payload[1];
			packet__cleanup(&mosq->in_packet);
			mosquitto__set_state(mosq, mosq_cs_socks5_new);
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
		return packet__read(mosq);
	}
	return MOSQ_ERR_SUCCESS;
}
#endif
