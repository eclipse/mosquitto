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

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "packet_mosq.h"

#ifdef WITH_BROKER
#  include "mosquitto_broker.h"
#endif


int handle__suback(struct mosquitto *mosq)
{
	uint16_t mid;
	uint8_t qos;
	int *granted_qos;
	int qos_count;
	int i = 0;
	int rc;

	assert(mosq);
#ifdef WITH_BROKER
	log__printf(NULL, MOSQ_LOG_DEBUG, "Received SUBACK from %s", mosq->id);
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s received SUBACK", mosq->id);
#endif
	rc = packet__read_uint16(&mosq->in_packet, &mid);
	if(rc) return rc;

	qos_count = mosq->in_packet.remaining_length - mosq->in_packet.pos;
	granted_qos = mosquitto__malloc(qos_count*sizeof(int));
	if(!granted_qos) return MOSQ_ERR_NOMEM;
	while(mosq->in_packet.pos < mosq->in_packet.remaining_length){
		rc = packet__read_byte(&mosq->in_packet, &qos);
		if(rc){
			mosquitto__free(granted_qos);
			return rc;
		}
		granted_qos[i] = (int)qos;
		i++;
	}
#ifndef WITH_BROKER
	pthread_mutex_lock(&mosq->callback_mutex);
	if(mosq->on_subscribe){
		mosq->in_callback = true;
		mosq->on_subscribe(mosq, mosq->userdata, mid, qos_count, granted_qos);
		mosq->in_callback = false;
	}
	pthread_mutex_unlock(&mosq->callback_mutex);
#endif
	mosquitto__free(granted_qos);

	return MOSQ_ERR_SUCCESS;
}

