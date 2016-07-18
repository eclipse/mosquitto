/*
Copyright (c) 2009-2015 Roger Light <roger@atchoo.org>

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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "mosquitto.h"
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt3_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "util_mosq.h"
#ifdef WITH_BROKER
#include "mosquitto_broker.h"
#endif


int handle__unsuback(struct mosquitto *mosq)
{
	uint16_t mid;
	int rc;

	assert(mosq);
#ifdef WITH_BROKER
	log__printf(NULL, MOSQ_LOG_DEBUG, "Received UNSUBACK from %s", mosq->id);
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s received UNSUBACK", mosq->id);
#endif
	rc = packet__read_uint16(&mosq->in_packet, &mid);
	if(rc) return rc;
#ifndef WITH_BROKER
	pthread_mutex_lock(&mosq->callback_mutex);
	if(mosq->on_unsubscribe){
		mosq->in_callback = true;
		mosq->on_unsubscribe(mosq, mosq->userdata, mid);
		mosq->in_callback = false;
	}
	pthread_mutex_unlock(&mosq->callback_mutex);
#endif

	return MOSQ_ERR_SUCCESS;
}

