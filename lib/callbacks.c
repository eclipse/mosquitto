/*
Copyright (c) 2010-2021 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include "callbacks.h"
#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "net_mosq.h"


void mosquitto_connect_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_connect on_connect)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_connect = on_connect;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void mosquitto_connect_with_flags_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_connect_with_flags on_connect)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_connect_with_flags = on_connect;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void mosquitto_connect_v5_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_connect_v5 on_connect)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_connect_v5 = on_connect;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void mosquitto_pre_connect_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_pre_connect on_pre_connect)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_pre_connect = on_pre_connect;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void mosquitto_transport_open_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_transport_open on_transport_open)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_transport_open = on_transport_open;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void mosquitto_transport_close_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_transport_close on_transport_close)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_transport_close = on_transport_close;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void mosquitto_disconnect_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_disconnect on_disconnect)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_disconnect = on_disconnect;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void mosquitto_disconnect_v5_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_disconnect_v5 on_disconnect)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_disconnect_v5 = on_disconnect;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void mosquitto_publish_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_publish on_publish)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_publish = on_publish;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void mosquitto_publish_v5_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_publish_v5 on_publish)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_publish_v5 = on_publish;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void mosquitto_message_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_message on_message)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_message = on_message;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void mosquitto_message_v5_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_message_v5 on_message)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_message_v5 = on_message;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void mosquitto_subscribe_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_subscribe on_subscribe)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_subscribe = on_subscribe;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void mosquitto_subscribe_v5_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_subscribe_v5 on_subscribe)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_subscribe_v5 = on_subscribe;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void mosquitto_unsubscribe_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_unsubscribe on_unsubscribe)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_unsubscribe = on_unsubscribe;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void mosquitto_unsubscribe_v5_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_unsubscribe_v5 on_unsubscribe)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_unsubscribe_v5 = on_unsubscribe;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void mosquitto_unsubscribe2_v5_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_unsubscribe2_v5 on_unsubscribe)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_unsubscribe2_v5 = on_unsubscribe;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void mosquitto_log_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_log on_log)
{
	COMPAT_pthread_mutex_lock(&mosq->log_callback_mutex);
	mosq->on_log = on_log;
	COMPAT_pthread_mutex_unlock(&mosq->log_callback_mutex);
}


void mosquitto_ext_auth_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_ext_auth on_ext_auth)
{
	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_ext_auth = on_ext_auth;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);
}


void callback__on_pre_connect(struct mosquitto *mosq)
{
	LIBMOSQ_CB_pre_connect on_pre_connect;

	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	on_pre_connect = mosq->on_pre_connect;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);

	mosq->callback_depth++;
	if(on_pre_connect){
		on_pre_connect(mosq, mosq->userdata);
	}
	mosq->callback_depth--;
}


int callback__on_transport_open(struct mosquitto *mosq, int *sock)
{
	LIBMOSQ_CB_transport_open on_transport_open;
	int rc;

	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	on_transport_open = mosq->on_transport_open;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);

	if(!on_transport_open){
		return MOSQ_ERR_INVAL;
	}
	mosq->callback_depth++;
	rc = on_transport_open(mosq, mosq->userdata, sock);
	mosq->callback_depth--;
	return rc;
}


int callback__on_transport_close(struct mosquitto *mosq, int sock)
{
	LIBMOSQ_CB_transport_close on_transport_close;
	int rc;

	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	on_transport_close = mosq->on_transport_close;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);

	if(!on_transport_close){
		return COMPAT_CLOSE(sock);
	}
	mosq->callback_depth++;
	rc = on_transport_close(mosq, mosq->userdata, sock);
	mosq->callback_depth--;
	return rc;
}


void callback__on_connect(struct mosquitto *mosq, uint8_t reason_code, uint8_t connect_flags, const mosquitto_property *properties)
{
	LIBMOSQ_CB_connect on_connect;
	LIBMOSQ_CB_connect_with_flags on_connect_with_flags;
	LIBMOSQ_CB_connect_v5 on_connect_v5;

	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	on_connect = mosq->on_connect;
	on_connect_with_flags = mosq->on_connect_with_flags;
	on_connect_v5 = mosq->on_connect_v5;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);

	mosq->callback_depth++;
	if(on_connect){
		on_connect(mosq, mosq->userdata, reason_code);
	}
	if(on_connect_with_flags){
		on_connect_with_flags(mosq, mosq->userdata, reason_code, connect_flags);
	}
	if(on_connect_v5){
		on_connect_v5(mosq, mosq->userdata, reason_code, connect_flags, properties);
	}
	mosq->callback_depth--;
}


void callback__on_publish(struct mosquitto *mosq, int mid, int reason_code, const mosquitto_property *properties)
{
	LIBMOSQ_CB_publish on_publish;
	LIBMOSQ_CB_publish_v5 on_publish_v5;

	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	on_publish = mosq->on_publish;
	on_publish_v5 = mosq->on_publish_v5;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);

	mosq->callback_depth++;
	if(on_publish){
		on_publish(mosq, mosq->userdata, mid);
	}
	if(on_publish_v5){
		on_publish_v5(mosq, mosq->userdata, mid, reason_code, properties);
	}
	mosq->callback_depth--;
}


void callback__on_message(struct mosquitto *mosq, const struct mosquitto_message *message, const mosquitto_property *properties)
{
	LIBMOSQ_CB_message on_message;
	LIBMOSQ_CB_message_v5 on_message_v5;

	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	on_message = mosq->on_message;
	on_message_v5 = mosq->on_message_v5;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);

	mosq->callback_depth++;
	if(on_message){
		on_message(mosq, mosq->userdata, message);
	}
	if(on_message_v5){
		on_message_v5(mosq, mosq->userdata, message, properties);
	}
	mosq->callback_depth--;
}


void callback__on_subscribe(struct mosquitto *mosq, int mid, int qos_count, const int *granted_qos, const mosquitto_property *properties)
{
	LIBMOSQ_CB_subscribe on_subscribe;
	LIBMOSQ_CB_subscribe_v5 on_subscribe_v5;

	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	on_subscribe = mosq->on_subscribe;
	on_subscribe_v5 = mosq->on_subscribe_v5;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);

	mosq->callback_depth++;
	if(on_subscribe){
		on_subscribe(mosq, mosq->userdata, mid, qos_count, granted_qos);
	}
	if(on_subscribe_v5){
		on_subscribe_v5(mosq, mosq->userdata, mid, qos_count, granted_qos, properties);
	}
	mosq->callback_depth--;
}


void callback__on_unsubscribe(struct mosquitto *mosq, int mid, int reason_code_count, const int *reason_codes, const mosquitto_property *properties)
{
	LIBMOSQ_CB_unsubscribe on_unsubscribe;
	LIBMOSQ_CB_unsubscribe_v5 on_unsubscribe_v5;
	LIBMOSQ_CB_unsubscribe2_v5 on_unsubscribe2_v5;

	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	on_unsubscribe = mosq->on_unsubscribe;
	on_unsubscribe_v5 = mosq->on_unsubscribe_v5;
	on_unsubscribe2_v5 = mosq->on_unsubscribe2_v5;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);

	mosq->callback_depth++;
	if(on_unsubscribe){
		on_unsubscribe(mosq, mosq->userdata, mid);
	}
	if(on_unsubscribe_v5){
		on_unsubscribe_v5(mosq, mosq->userdata, mid, properties);
	}
	if(on_unsubscribe2_v5){
		on_unsubscribe2_v5(mosq, mosq->userdata, mid, reason_code_count, reason_codes, properties);
	}
	mosq->callback_depth--;
}


void callback__on_disconnect(struct mosquitto *mosq, int rc, const mosquitto_property *properties)
{
	LIBMOSQ_CB_disconnect on_disconnect;
	LIBMOSQ_CB_disconnect_v5 on_disconnect_v5;

	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	on_disconnect = mosq->on_disconnect;
	on_disconnect_v5 = mosq->on_disconnect_v5;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);

	mosq->callback_depth++;
	if(on_disconnect){
		on_disconnect(mosq, mosq->userdata, rc);
	}
	if(on_disconnect_v5){
		on_disconnect_v5(mosq, mosq->userdata, rc, properties);
	}
	mosq->callback_depth--;
}


int callback__on_ext_auth(struct mosquitto *mosq, const char *auth_method, uint16_t auth_data_len, const void *auth_data, const mosquitto_property *properties)
{
	int rc = MOSQ_ERR_AUTH;
	LIBMOSQ_CB_ext_auth on_ext_auth;

	COMPAT_pthread_mutex_lock(&mosq->callback_mutex);
	on_ext_auth = mosq->on_ext_auth;
	COMPAT_pthread_mutex_unlock(&mosq->callback_mutex);

	mosq->callback_depth++;
	if(on_ext_auth){
		rc = on_ext_auth(mosq, mosq->userdata, auth_method, auth_data_len, auth_data, properties);
	}
	mosq->callback_depth--;
	return rc;
}
