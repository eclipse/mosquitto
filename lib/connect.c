/*
Copyright (c) 2010-2020 Roger Light <roger@atchoo.org>

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

#include <string.h>

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "logging_mosq.h"
#include "messages_mosq.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "mqtt_protocol.h"
#include "net_mosq.h"
#include "send_mosq.h"
#include "socks_mosq.h"
#include "util_mosq.h"

static char alphanum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

static int mosquitto__reconnect(struct mosquitto *mosq, bool blocking);
static int mosquitto__connect_init(struct mosquitto *mosq, const char *host, int port, int keepalive);


static int mosquitto__connect_init(struct mosquitto *mosq, const char *host, int port, int keepalive)
{
	int i;
	int rc;

	if(!mosq) return MOSQ_ERR_INVAL;
	if(!host || port < 0 || port > UINT16_MAX) return MOSQ_ERR_INVAL;
	if(keepalive != 0 && (keepalive < 5 || keepalive > UINT16_MAX)) return MOSQ_ERR_INVAL;

	/* Only MQTT v3.1 requires a client id to be sent */
	if(mosq->id == NULL && (mosq->protocol == mosq_p_mqtt31)){
		mosq->id = (char *)mosquitto__calloc(24, sizeof(char));
		if(!mosq->id){
			return MOSQ_ERR_NOMEM;
		}
		mosq->id[0] = 'm';
		mosq->id[1] = 'o';
		mosq->id[2] = 's';
		mosq->id[3] = 'q';
		mosq->id[4] = '-';

		rc = util__random_bytes(&mosq->id[5], 18);
		if(rc) return rc;

		for(i=5; i<23; i++){
			mosq->id[i] = alphanum[(mosq->id[i]&0x7F)%(sizeof(alphanum)-1)];
		}
	}

	mosquitto__free(mosq->host);
	mosq->host = mosquitto__strdup(host);
	if(!mosq->host) return MOSQ_ERR_NOMEM;
	mosq->port = (uint16_t)port;

	mosq->keepalive = (uint16_t)keepalive;
	mosq->msgs_in.inflight_quota = mosq->msgs_in.inflight_maximum;
	mosq->msgs_out.inflight_quota = mosq->msgs_out.inflight_maximum;
	mosq->retain_available = 1;

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_connect(struct mosquitto *mosq, const char *host, int port, int keepalive)
{
	return mosquitto_connect_bind(mosq, host, port, keepalive, NULL);
}


int mosquitto_connect_bind(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address)
{
	return mosquitto_connect_bind_v5(mosq, host, port, keepalive, bind_address, NULL);
}

int mosquitto_connect_bind_v5(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address, const mosquitto_property *properties)
{
	int rc;

	rc = mosquitto_string_option(mosq, MOSQ_OPT_BIND_ADDRESS, bind_address);
	if(rc) return rc;

	mosquitto_property_free_all(&mosq->connect_properties);
	if(properties){
		rc = mosquitto_property_check_all(CMD_CONNECT, properties);
		if(rc) return rc;

		rc = mosquitto_property_copy_all(&mosq->connect_properties, properties);
		if(rc) return rc;
		mosq->connect_properties->client_generated = true;
	}

	rc = mosquitto__connect_init(mosq, host, port, keepalive);
	if(rc) return rc;

	mosquitto__set_state(mosq, mosq_cs_new);

	return mosquitto__reconnect(mosq, true);
}


int mosquitto_connect_async(struct mosquitto *mosq, const char *host, int port, int keepalive)
{
	return mosquitto_connect_bind_async(mosq, host, port, keepalive, NULL);
}


int mosquitto_connect_bind_async(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address)
{
	int rc;

	rc = mosquitto_string_option(mosq, MOSQ_OPT_BIND_ADDRESS, bind_address);
	if(rc) return rc;

	rc = mosquitto__connect_init(mosq, host, port, keepalive);
	if(rc) return rc;

	return mosquitto__reconnect(mosq, false);
}


int mosquitto_reconnect_async(struct mosquitto *mosq)
{
	return mosquitto__reconnect(mosq, false);
}


int mosquitto_reconnect(struct mosquitto *mosq)
{
	return mosquitto__reconnect(mosq, true);
}


static int mosquitto__reconnect(struct mosquitto *mosq, bool blocking)
{
	const mosquitto_property *outgoing_properties = NULL;
	mosquitto_property local_property;
	int rc;

	if(!mosq) return MOSQ_ERR_INVAL;
	if(!mosq->host) return MOSQ_ERR_INVAL;

	if(mosq->connect_properties){
		if(mosq->protocol != mosq_p_mqtt5) return MOSQ_ERR_NOT_SUPPORTED;

		if(mosq->connect_properties->client_generated){
			outgoing_properties = mosq->connect_properties;
		}else{
			memcpy(&local_property, mosq->connect_properties, sizeof(mosquitto_property));
			local_property.client_generated = true;
			local_property.next = NULL;
			outgoing_properties = &local_property;
		}
		rc = mosquitto_property_check_all(CMD_CONNECT, outgoing_properties);
		if(rc) return rc;
	}

	pthread_mutex_lock(&mosq->msgtime_mutex);
	mosq->last_msg_in = mosquitto_time();
	mosq->next_msg_out = mosq->last_msg_in + mosq->keepalive;
	pthread_mutex_unlock(&mosq->msgtime_mutex);

	mosq->ping_t = 0;

	packet__cleanup(&mosq->in_packet);

	packet__cleanup_all(mosq);

	message__reconnect_reset(mosq);

	if(mosq->sock != INVALID_SOCKET){
        net__socket_close(mosq); //close socket
    }

#ifdef WITH_SOCKS
	if(mosq->socks5_host){
		rc = net__socket_connect(mosq, mosq->socks5_host, mosq->socks5_port, mosq->bind_address, blocking);
	}else
#endif
	{
		rc = net__socket_connect(mosq, mosq->host, mosq->port, mosq->bind_address, blocking);
	}
	if(rc>0){
		mosquitto__set_state(mosq, mosq_cs_connect_pending);
		return rc;
	}

#ifdef WITH_SOCKS
	if(mosq->socks5_host){
		mosquitto__set_state(mosq, mosq_cs_socks5_new);
		return socks5__send(mosq);
	}else
#endif
	{
		mosquitto__set_state(mosq, mosq_cs_connected);
		rc = send__connect(mosq, mosq->keepalive, mosq->clean_start, outgoing_properties);
		if(rc){
			packet__cleanup_all(mosq);
			net__socket_close(mosq);
			mosquitto__set_state(mosq, mosq_cs_new);
		}
		return rc;
	}
}


int mosquitto_disconnect(struct mosquitto *mosq)
{
	return mosquitto_disconnect_v5(mosq, 0, NULL);
}

int mosquitto_disconnect_v5(struct mosquitto *mosq, int reason_code, const mosquitto_property *properties)
{
	const mosquitto_property *outgoing_properties = NULL;
	mosquitto_property local_property;
	int rc;
	if(!mosq) return MOSQ_ERR_INVAL;
	if(mosq->protocol != mosq_p_mqtt5 && properties) return MOSQ_ERR_NOT_SUPPORTED;
	if(reason_code < 0 || reason_code > UINT8_MAX) return MOSQ_ERR_INVAL;

	if(properties){
		if(properties->client_generated){
			outgoing_properties = properties;
		}else{
			memcpy(&local_property, properties, sizeof(mosquitto_property));
			local_property.client_generated = true;
			local_property.next = NULL;
			outgoing_properties = &local_property;
		}
		rc = mosquitto_property_check_all(CMD_DISCONNECT, outgoing_properties);
		if(rc) return rc;
	}

	mosquitto__set_state(mosq, mosq_cs_disconnected);
	if(mosq->sock == INVALID_SOCKET){
		return MOSQ_ERR_NO_CONN;
	}else{
		return send__disconnect(mosq, (uint8_t)reason_code, outgoing_properties);
	}
}


void do_client_disconnect(struct mosquitto *mosq, int reason_code, const mosquitto_property *properties)
{
	mosquitto__set_state(mosq, mosq_cs_disconnected);
	net__socket_close(mosq);

	/* Free data and reset values */
	pthread_mutex_lock(&mosq->out_packet_mutex);
	mosq->current_out_packet = mosq->out_packet;
	if(mosq->out_packet){
		mosq->out_packet = mosq->out_packet->next;
		if(!mosq->out_packet){
			mosq->out_packet_last = NULL;
		}
	}
	pthread_mutex_unlock(&mosq->out_packet_mutex);

	pthread_mutex_lock(&mosq->msgtime_mutex);
	mosq->next_msg_out = mosquitto_time() + mosq->keepalive;
	pthread_mutex_unlock(&mosq->msgtime_mutex);

	pthread_mutex_lock(&mosq->callback_mutex);
	if(mosq->on_disconnect){
		mosq->in_callback = true;
		mosq->on_disconnect(mosq, mosq->userdata, reason_code);
		mosq->in_callback = false;
	}
	if(mosq->on_disconnect_v5){
		mosq->in_callback = true;
		mosq->on_disconnect_v5(mosq, mosq->userdata, reason_code, properties);
		mosq->in_callback = false;
	}
	pthread_mutex_unlock(&mosq->callback_mutex);
	pthread_mutex_unlock(&mosq->current_out_packet_mutex);
}

