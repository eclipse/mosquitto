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


void mosquitto_connect_callback_set(struct mosquitto *mosq, void (*on_connect)(struct mosquitto *, void *, int))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_connect = on_connect;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_connect_with_flags_callback_set(struct mosquitto *mosq, void (*on_connect)(struct mosquitto *, void *, int, int))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_connect_with_flags = on_connect;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_connect_v5_callback_set(struct mosquitto *mosq, void (*on_connect)(struct mosquitto *, void *, int, int, const mosquitto_property *))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_connect_v5 = on_connect;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_pre_connect_callback_set(struct mosquitto *mosq, void (*on_pre_connect)(struct mosquitto *, void *))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_pre_connect = on_pre_connect;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_disconnect_callback_set(struct mosquitto *mosq, void (*on_disconnect)(struct mosquitto *, void *, int))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_disconnect = on_disconnect;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_disconnect_v5_callback_set(struct mosquitto *mosq, void (*on_disconnect)(struct mosquitto *, void *, int, const mosquitto_property *))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_disconnect_v5 = on_disconnect;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_publish_callback_set(struct mosquitto *mosq, void (*on_publish)(struct mosquitto *, void *, int))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_publish = on_publish;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_publish_v5_callback_set(struct mosquitto *mosq, void (*on_publish)(struct mosquitto *, void *, int, int, const mosquitto_property *props))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_publish_v5 = on_publish;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_message_callback_set(struct mosquitto *mosq, void (*on_message)(struct mosquitto *, void *, const struct mosquitto_message *))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_message = on_message;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_message_v5_callback_set(struct mosquitto *mosq, void (*on_message)(struct mosquitto *, void *, const struct mosquitto_message *, const mosquitto_property *props))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_message_v5 = on_message;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_subscribe_callback_set(struct mosquitto *mosq, void (*on_subscribe)(struct mosquitto *, void *, int, int, const int *))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_subscribe = on_subscribe;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_subscribe_v5_callback_set(struct mosquitto *mosq, void (*on_subscribe)(struct mosquitto *, void *, int, int, const int *, const mosquitto_property *props))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_subscribe_v5 = on_subscribe;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_unsubscribe_callback_set(struct mosquitto *mosq, void (*on_unsubscribe)(struct mosquitto *, void *, int))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_unsubscribe = on_unsubscribe;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_unsubscribe_v5_callback_set(struct mosquitto *mosq, void (*on_unsubscribe)(struct mosquitto *, void *, int, const mosquitto_property *props))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_unsubscribe_v5 = on_unsubscribe;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_log_callback_set(struct mosquitto *mosq, void (*on_log)(struct mosquitto *, void *, int, const char *))
{
	pthread_mutex_lock(&mosq->log_callback_mutex);
	mosq->on_log = on_log;
	pthread_mutex_unlock(&mosq->log_callback_mutex);
}


void callback__on_pre_connect(struct mosquitto *mosq)
{
	void (*on_pre_connect)(struct mosquitto *, void *userdata);

	pthread_mutex_lock(&mosq->callback_mutex);
	on_pre_connect = mosq->on_pre_connect;
	pthread_mutex_unlock(&mosq->callback_mutex);

	mosq->callback_depth++;
	if(on_pre_connect){
		on_pre_connect(mosq, mosq->userdata);
	}
	mosq->callback_depth--;
}


void callback__on_connect(struct mosquitto *mosq, uint8_t reason_code, uint8_t connect_flags, const mosquitto_property *properties)
{
	void (*on_connect)(struct mosquitto *, void *userdata, int rc);
	void (*on_connect_with_flags)(struct mosquitto *, void *userdata, int rc, int flags);
	void (*on_connect_v5)(struct mosquitto *, void *userdata, int rc, int flags, const mosquitto_property *props);

	pthread_mutex_lock(&mosq->callback_mutex);
	on_connect = mosq->on_connect;
	on_connect_with_flags = mosq->on_connect_with_flags;
	on_connect_v5 = mosq->on_connect_v5;
	pthread_mutex_unlock(&mosq->callback_mutex);

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
	void (*on_publish)(struct mosquitto *, void *userdata, int mid);
	void (*on_publish_v5)(struct mosquitto *, void *userdata, int mid, int reason_code, const mosquitto_property *props);

	pthread_mutex_lock(&mosq->callback_mutex);
	on_publish = mosq->on_publish;
	on_publish_v5 = mosq->on_publish_v5;
	pthread_mutex_unlock(&mosq->callback_mutex);

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
	void (*on_message)(struct mosquitto *, void *userdata, const struct mosquitto_message *message);
	void (*on_message_v5)(struct mosquitto *, void *userdata, const struct mosquitto_message *message, const mosquitto_property *props);

	pthread_mutex_lock(&mosq->callback_mutex);
	on_message = mosq->on_message;
	on_message_v5 = mosq->on_message_v5;
	pthread_mutex_unlock(&mosq->callback_mutex);

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
	void (*on_subscribe)(struct mosquitto *, void *userdata, int mid, int qos_count, const int *granted_qos) = NULL;
	void (*on_subscribe_v5)(struct mosquitto *, void *userdata, int mid, int qos_count, const int *granted_qos, const mosquitto_property *props) = NULL;

	pthread_mutex_lock(&mosq->callback_mutex);
	on_subscribe = mosq->on_subscribe;
	on_subscribe_v5 = mosq->on_subscribe_v5;
	pthread_mutex_unlock(&mosq->callback_mutex);

	mosq->callback_depth++;
	if(on_subscribe){
		on_subscribe(mosq, mosq->userdata, mid, qos_count, granted_qos);
	}
	if(on_subscribe_v5){
		on_subscribe_v5(mosq, mosq->userdata, mid, qos_count, granted_qos, properties);
	}
	mosq->callback_depth--;
}


void callback__on_unsubscribe(struct mosquitto *mosq, int mid, const mosquitto_property *properties)
{
	void (*on_unsubscribe)(struct mosquitto *, void *userdata, int mid) = NULL;
	void (*on_unsubscribe_v5)(struct mosquitto *, void *userdata, int mid, const mosquitto_property *props) = NULL;

	pthread_mutex_lock(&mosq->callback_mutex);
	on_unsubscribe = mosq->on_unsubscribe;
	on_unsubscribe_v5 = mosq->on_unsubscribe_v5;
	pthread_mutex_unlock(&mosq->callback_mutex);

	mosq->callback_depth++;
	if(on_unsubscribe){
		on_unsubscribe(mosq, mosq->userdata, mid);
	}
	if(on_unsubscribe_v5){
		on_unsubscribe_v5(mosq, mosq->userdata, mid, properties);
	}
	mosq->callback_depth--;
}


void callback__on_disconnect(struct mosquitto *mosq, int rc, const mosquitto_property *properties)
{
	void (*on_disconnect)(struct mosquitto *, void *, int) = NULL;
	void (*on_disconnect_v5)(struct mosquitto *, void *, int, const mosquitto_property *) = NULL;

	pthread_mutex_lock(&mosq->callback_mutex);
	on_disconnect = mosq->on_disconnect;
	on_disconnect_v5 = mosq->on_disconnect_v5;
	pthread_mutex_unlock(&mosq->callback_mutex);

	mosq->callback_depth++;
	if(on_disconnect){
		on_disconnect(mosq, mosq->userdata, rc);
	}
	if(on_disconnect_v5){
		on_disconnect_v5(mosq, mosq->userdata, rc, properties);
	}
	mosq->callback_depth--;
}
