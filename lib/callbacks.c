/*
Copyright (c) 2010-2019 Roger Light <roger@atchoo.org>

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

#include "config.h"

#include "mosquitto.h"
#include "mosquitto_internal.h"


void mosquitto_connect_callback_set(struct mosquitto *mosq, void (*on_connect)(struct mosquitto *, void *, int))
{
	mosquitto_mutex_lock(&mosq->callback_mutex);
	mosq->on_connect = on_connect;
	mosquitto_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_connect_with_flags_callback_set(struct mosquitto *mosq, void (*on_connect)(struct mosquitto *, void *, int, int))
{
	mosquitto_mutex_lock(&mosq->callback_mutex);
	mosq->on_connect_with_flags = on_connect;
	mosquitto_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_connect_v5_callback_set(struct mosquitto *mosq, void (*on_connect)(struct mosquitto *, void *, int, int, const mosquitto_property *))
{
	mosquitto_mutex_lock(&mosq->callback_mutex);
	mosq->on_connect_v5 = on_connect;
	mosquitto_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_disconnect_callback_set(struct mosquitto *mosq, void (*on_disconnect)(struct mosquitto *, void *, int))
{
	mosquitto_mutex_lock(&mosq->callback_mutex);
	mosq->on_disconnect = on_disconnect;
	mosquitto_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_disconnect_v5_callback_set(struct mosquitto *mosq, void (*on_disconnect)(struct mosquitto *, void *, int, const mosquitto_property *))
{
	mosquitto_mutex_lock(&mosq->callback_mutex);
	mosq->on_disconnect_v5 = on_disconnect;
	mosquitto_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_publish_callback_set(struct mosquitto *mosq, void (*on_publish)(struct mosquitto *, void *, int))
{
	mosquitto_mutex_lock(&mosq->callback_mutex);
	mosq->on_publish = on_publish;
	mosquitto_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_publish_v5_callback_set(struct mosquitto *mosq, void (*on_publish)(struct mosquitto *, void *, int, int, const mosquitto_property *props))
{
	mosquitto_mutex_lock(&mosq->callback_mutex);
	mosq->on_publish_v5 = on_publish;
	mosquitto_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_message_callback_set(struct mosquitto *mosq, void (*on_message)(struct mosquitto *, void *, const struct mosquitto_message *))
{
	mosquitto_mutex_lock(&mosq->callback_mutex);
	mosq->on_message = on_message;
	mosquitto_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_message_v5_callback_set(struct mosquitto *mosq, void (*on_message)(struct mosquitto *, void *, const struct mosquitto_message *, const mosquitto_property *props))
{
	mosquitto_mutex_lock(&mosq->callback_mutex);
	mosq->on_message_v5 = on_message;
	mosquitto_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_subscribe_callback_set(struct mosquitto *mosq, void (*on_subscribe)(struct mosquitto *, void *, int, int, const int *))
{
	mosquitto_mutex_lock(&mosq->callback_mutex);
	mosq->on_subscribe = on_subscribe;
	mosquitto_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_subscribe_v5_callback_set(struct mosquitto *mosq, void (*on_subscribe)(struct mosquitto *, void *, int, int, const int *, const mosquitto_property *props))
{
	mosquitto_mutex_lock(&mosq->callback_mutex);
	mosq->on_subscribe_v5 = on_subscribe;
	mosquitto_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_unsubscribe_callback_set(struct mosquitto *mosq, void (*on_unsubscribe)(struct mosquitto *, void *, int))
{
	mosquitto_mutex_lock(&mosq->callback_mutex);
	mosq->on_unsubscribe = on_unsubscribe;
	mosquitto_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_unsubscribe_v5_callback_set(struct mosquitto *mosq, void (*on_unsubscribe)(struct mosquitto *, void *, int, const mosquitto_property *props))
{
	mosquitto_mutex_lock(&mosq->callback_mutex);
	mosq->on_unsubscribe_v5 = on_unsubscribe;
	mosquitto_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_log_callback_set(struct mosquitto *mosq, void (*on_log)(struct mosquitto *, void *, int, const char *))
{
	mosquitto_mutex_lock(&mosq->log_callback_mutex);
	mosq->on_log = on_log;
	mosquitto_mutex_unlock(&mosq->log_callback_mutex);
}

