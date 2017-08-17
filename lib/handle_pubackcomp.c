/*
Copyright (c) 2009-2016 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

Contributors:
   Roger Light - initial implementation and documentation.
   Tatsuzo Osawa - Add mqtt version 5.
*/

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "mosquitto.h"
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt3_protocol.h"
#include "mqtt5_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "util_mosq.h"

#ifdef WITH_BROKER
#  include "mosquitto_broker_internal.h"
#endif


#ifdef WITH_BROKER
int handle__pubackcomp(struct mosquitto_db *db, struct mosquitto *mosq, const char *type)
#else
int handle__pubackcomp(struct mosquitto *mosq, const char *type)
#endif
{
	uint16_t mid;
	int rc;
	uint8_t result = 0;

	assert(mosq);
	rc = packet__read_uint16(&mosq->in_packet, &mid);
	if(rc) return rc;

	if(mosq->protocol == mosq_p_mqtt5){
		if(mosq->in_packet.remaining_length > 2){
			rc = packet__read_byte(&mosq->in_packet, &result);
			if(rc) return rc;
		}
		if(mosq->in_packet.remaining_length >= 4){
			/* Skip v5 property so far. Should be implimented in the future. */
			rc = packet__read_property(mosq, &mosq->in_packet);
			if(rc) return rc;
		}
	}
#ifdef WITH_BROKER
	if(mosq->protocol == mosq_p_mqtt5){
		log__printf(NULL, MOSQ_LOG_DEBUG, "Received %s from %s (Mid: %d) (%d)", type, mosq->id, mid, result);
	}else{
		log__printf(NULL, MOSQ_LOG_DEBUG, "Received %s from %s (Mid: %d)", type, mosq->id, mid);
	}

	if(mid){
		rc = db__message_delete(db, mosq, mid, mosq_md_out);
		if(rc == MOSQ_ERR_NOT_FOUND){
			log__printf(mosq, MOSQ_LOG_WARNING, "Warning: Received %s from %s for an unknown packet identifier %d.", type, mosq->id, mid);
			return MOSQ_ERR_SUCCESS;
		}else{
			return rc;
		}
	}
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s received %s (Mid: %d)", mosq->id, type, mid);

	if(!message__delete(mosq, mid, mosq_md_out)){
		/* Only inform the client the message has been sent once. */
		pthread_mutex_lock(&mosq->callback_mutex);
		if(mosq->on_publish){
			mosq->in_callback = true;
			mosq->on_publish(mosq, mosq->userdata, mid);
			mosq->in_callback = false;
		}
		pthread_mutex_unlock(&mosq->callback_mutex);
	}
#endif

	return MOSQ_ERR_SUCCESS;
}


