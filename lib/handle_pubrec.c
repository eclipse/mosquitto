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
#include "net_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "util_mosq.h"
#ifdef WITH_BROKER
#include "mosquitto_broker_internal.h"
#endif


int handle__pubrec(struct mosquitto *mosq)
{
	uint16_t mid;
	int rc;
	uint8_t result = 0;
	struct mosquitto_v5_property property;

	assert(mosq);
	rc = packet__read_uint16(&mosq->in_packet, &mid);
	if(rc) return rc;

	// Read and parse pubrec reason code and v5 property. (So far, read only.)
	if(mosq->protocol == mosq_p_mqtt5){
		rc = packet__read_byte(&mosq->in_packet, &result);
		if(rc) return rc;
		if(result){
			// Prevent warning.
		}

		memset(&property, 0, sizeof(struct mosquitto_v5_property));
		rc = packet__read_property(mosq, &mosq->in_packet, &property, PUBREC);
		if(rc != MQTT5_RC_SUCCESS){
			packet__property_content_free(&property);
			return rc;
		}
		packet__property_content_free(&property);
	}

#ifdef WITH_BROKER
	log__printf(NULL, MOSQ_LOG_DEBUG, "Received PUBREC from %s (Mid: %d)", mosq->id, mid);

	rc = db__message_update(mosq, mid, mosq_md_out, mosq_ms_wait_for_pubcomp);
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s received PUBREC (Mid: %d)", mosq->id, mid);

	rc = message__out_update(mosq, mid, mosq_ms_wait_for_pubcomp);
#endif
	if(rc == MOSQ_ERR_NOT_FOUND){
		log__printf(mosq, MOSQ_LOG_WARNING, "Warning: Received PUBREC from %s for an unknown packet identifier %d.", mosq->id, mid);
	}else if(rc != MOSQ_ERR_SUCCESS){
		return rc;
	}
	rc = send__pubrel(mosq, mid);
	if(rc) return rc;

	return MOSQ_ERR_SUCCESS;
}


