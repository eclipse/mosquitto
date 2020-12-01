/*
Copyright (c) 2018-2020 Roger Light <roger@atchoo.org>

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
#include <stdio.h>
#include <string.h>

#include "mosquitto_broker_internal.h"
#include "mqtt_protocol.h"
#include "property_mosq.h"

/* Process the incoming properties, we should be able to assume that only valid
 * properties for CONNECT are present here. */
int property__process_connect(struct mosquitto *context, mosquitto_property **props)
{
	mosquitto_property *p;

	p = *props;

	while(p){
		if(p->identifier == MQTT_PROP_SESSION_EXPIRY_INTERVAL){
			context->session_expiry_interval = p->value.i32;
		}else if(p->identifier == MQTT_PROP_RECEIVE_MAXIMUM){
			if(p->value.i16 == 0){
				return MOSQ_ERR_PROTOCOL;
			}

			context->msgs_out.inflight_maximum = p->value.i16;
			context->msgs_out.inflight_quota = context->msgs_out.inflight_maximum;
		}else if(p->identifier == MQTT_PROP_MAXIMUM_PACKET_SIZE){
			if(p->value.i32 == 0){
				return MOSQ_ERR_PROTOCOL;
			}
			context->maximum_packet_size = p->value.i32;
		}
		p = p->next;
	}

	return MOSQ_ERR_SUCCESS;
}


int property__process_will(struct mosquitto *context, struct mosquitto_message_all *msg, mosquitto_property **props)
{
	mosquitto_property *p, *p_prev;
	mosquitto_property *msg_properties, *msg_properties_last;

	p = *props;
	p_prev = NULL;
	msg_properties = NULL;
	msg_properties_last = NULL;
	while(p){
		switch(p->identifier){
			case MQTT_PROP_CONTENT_TYPE:
			case MQTT_PROP_CORRELATION_DATA:
			case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
			case MQTT_PROP_RESPONSE_TOPIC:
			case MQTT_PROP_USER_PROPERTY:
				if(msg_properties){
					msg_properties_last->next = p;
					msg_properties_last = p;
				}else{
					msg_properties = p;
					msg_properties_last = p;
				}
				if(p_prev){
					p_prev->next = p->next;
					p = p_prev->next;
				}else{
					*props = p->next;
					p = *props;
				}
				msg_properties_last->next = NULL;
				break;

			case MQTT_PROP_WILL_DELAY_INTERVAL:
				context->will_delay_interval = p->value.i32;
				p_prev = p;
				p = p->next;
				break;

			case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
				msg->expiry_interval = p->value.i32;
				p_prev = p;
				p = p->next;
				break;

			default:
				return MOSQ_ERR_PROTOCOL;
				break;
		}
	}

	msg->properties = msg_properties;
	return MOSQ_ERR_SUCCESS;
}


/* Process the incoming properties, we should be able to assume that only valid
 * properties for DISCONNECT are present here. */
int property__process_disconnect(struct mosquitto *context, mosquitto_property **props)
{
	mosquitto_property *p;

	p = *props;

	while(p){
		if(p->identifier == MQTT_PROP_SESSION_EXPIRY_INTERVAL){
			if(context->session_expiry_interval == 0 && p->value.i32 != 0){
				return MOSQ_ERR_PROTOCOL;
			}
			context->session_expiry_interval = p->value.i32;
		}
		p = p->next;
	}
	return MOSQ_ERR_SUCCESS;
}

