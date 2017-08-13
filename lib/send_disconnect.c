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

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "logging_mosq.h"
#include "mqtt3_protocol.h"
#include "send_mosq.h"
#include "packet_mosq.h"
#include "memory_mosq.h"

#ifdef WITH_BROKER
#  include "mosquitto_broker_internal.h"
#endif


int send__disconnect(struct mosquitto *mosq)
{
	assert(mosq);
#ifdef WITH_BROKER
	// for version 5, broker can send reacon code and property.
	if(mosq->protocol == mosq_p_mqtt5){
		int rc;
		struct mosquitto__packet *packet = NULL;
		int len;

		if(mosq->listener){
			if(mosq->id){
				log__printf(NULL, MOSQ_LOG_DEBUG, "Sending DISCONNECT to %s (%d)", mosq->id, mosq->rc_current);
			}else{
				log__printf(NULL, MOSQ_LOG_DEBUG, "Sending DISCONNECT to %s (%d)", mosq->address, mosq->rc_current);
			}
		}
		packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
		if(!packet) return MOSQ_ERR_NOMEM;

		packet->command = DISCONNECT;
		len = packet__property_len(mosq->current_property);
		packet->remaining_length = 1 + variable_len(len) + len;
		rc = packet__alloc(packet);
		if(rc){
			mosquitto__free(packet);
			return rc;
		}
		packet__write_byte(packet, mosq->rc_current);
		packet__write_property(mosq, packet, mosq->current_property, DISCONNECT);

		return packet__queue(mosq, packet);
	} // even for version 5, bridge use version 3.x.

# ifdef WITH_BRIDGE
	log__printf(mosq, MOSQ_LOG_DEBUG, "Bridge %s sending DISCONNECT", mosq->id);
# endif
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending DISCONNECT", mosq->id);
#endif
	return send__simple_command(mosq, DISCONNECT);
}


