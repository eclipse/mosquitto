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

#include <stdio.h>
#include <string.h>

#include "logging_mosq.h"
#include "mqtt_protocol.h"
#include "memory_mosq.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "send_mosq.h"
#include "util_mosq.h"

int handle__disconnect(struct mosquitto *mosq)
{
	int rc;
	uint8_t reason_code;
	mosquitto_property *properties = NULL;

	if(!mosq){
		return MOSQ_ERR_INVAL;
	}

	if(mosq->protocol != mosq_p_mqtt5){
		return MOSQ_ERR_PROTOCOL;
	}

	rc = packet__read_byte(&mosq->in_packet, &reason_code);
	if(rc) return rc;

	if(mosq->in_packet.remaining_length > 2){
		rc = property__read_all(CMD_DISCONNECT, &mosq->in_packet, &properties);
		if(rc) return rc;
		mosquitto_property_free_all(&properties);
	}

	log__printf(mosq, MOSQ_LOG_DEBUG, "Received DISCONNECT (%d)", reason_code);

	do_client_disconnect(mosq, reason_code, properties);

	mosquitto_property_free_all(&properties);

	return MOSQ_ERR_SUCCESS;
}

