/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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

#include <assert.h>

#ifdef WITH_BROKER
#  include "mosquitto_broker_internal.h"
#endif

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "util_mosq.h"


int handle__suback(struct mosquitto *mosq)
{
	uint16_t mid;
	uint8_t qos;
	int *granted_qos;
	int qos_count;
	int i = 0;
	int rc;
	mosquitto_property *properties = NULL;

	assert(mosq);

	if(mosquitto__get_state(mosq) != mosq_cs_active){
		return MOSQ_ERR_PROTOCOL;
	}

#ifdef WITH_BROKER
	log__printf(NULL, MOSQ_LOG_DEBUG, "Received SUBACK from %s", mosq->id);
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s received SUBACK", mosq->id);
#endif
	rc = packet__read_uint16(&mosq->in_packet, &mid);
	if(rc) return rc;
	if(mid == 0) return MOSQ_ERR_PROTOCOL;

	if(mosq->protocol == mosq_p_mqtt5){
		rc = property__read_all(CMD_SUBACK, &mosq->in_packet, &properties);
		if(rc) return rc;
	}

	qos_count = (int)(mosq->in_packet.remaining_length - mosq->in_packet.pos);
	granted_qos = mosquitto__malloc((size_t)qos_count*sizeof(int));
	if(!granted_qos){
#ifdef WITH_BROKER
		mosquitto_property_free_all(&properties);
#endif
		return MOSQ_ERR_NOMEM;
	}
	while(mosq->in_packet.pos < mosq->in_packet.remaining_length){
		rc = packet__read_byte(&mosq->in_packet, &qos);
		if(rc){
			mosquitto__free(granted_qos);
#ifdef WITH_BROKER
			mosquitto_property_free_all(&properties);
#endif
			return rc;
		}
		granted_qos[i] = (int)qos;
		i++;
	}
#ifdef WITH_BROKER
	/* Immediately free, we don't do anything with Reason String or User Property at the moment */
	mosquitto_property_free_all(&properties);
#else
	pthread_mutex_lock(&mosq->callback_mutex);
	if(mosq->on_subscribe){
		mosq->in_callback = true;
		mosq->on_subscribe(mosq, mosq->userdata, mid, qos_count, granted_qos);
		mosq->in_callback = false;
	}
	if(mosq->on_subscribe_v5){
		mosq->in_callback = true;
		mosq->on_subscribe_v5(mosq, mosq->userdata, mid, qos_count, granted_qos, properties);
		mosq->in_callback = false;
	}
	pthread_mutex_unlock(&mosq->callback_mutex);
	mosquitto_property_free_all(&properties);
#endif
	mosquitto__free(granted_qos);

	return MOSQ_ERR_SUCCESS;
}

