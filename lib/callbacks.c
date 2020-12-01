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

