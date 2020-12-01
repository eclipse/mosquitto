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

#include <stdio.h>
#include <string.h>

#ifdef WITH_BROKER
#  include "mosquitto_broker_internal.h"
#endif

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "logging_mosq.h"
#include "messages_mosq.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "net_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "util_mosq.h"
#include "will_mosq.h"

int will__set(struct mosquitto *mosq, const char *topic, int payloadlen, const void *payload, int qos, bool retain, mosquitto_property *properties)
{
	int rc = MOSQ_ERR_SUCCESS;
	mosquitto_property *p;

	if(!mosq || !topic) return MOSQ_ERR_INVAL;
	if(payloadlen < 0 || payloadlen > MQTT_MAX_PAYLOAD) return MOSQ_ERR_PAYLOAD_SIZE;
	if(payloadlen > 0 && !payload) return MOSQ_ERR_INVAL;

	if(mosquitto_pub_topic_check(topic)) return MOSQ_ERR_INVAL;
	if(mosquitto_validate_utf8(topic, (uint16_t)strlen(topic))) return MOSQ_ERR_MALFORMED_UTF8;

	if(properties){
		if(mosq->protocol != mosq_p_mqtt5){
			return MOSQ_ERR_NOT_SUPPORTED;
		}
		p = properties;
		while(p){
			rc = mosquitto_property_check_command(CMD_WILL, p->identifier);
			if(rc) return rc;
			p = p->next;
		}
	}

	if(mosq->will){
		mosquitto__free(mosq->will->msg.topic);
		mosquitto__free(mosq->will->msg.payload);
		mosquitto_property_free_all(&mosq->will->properties);
		mosquitto__free(mosq->will);
	}

	mosq->will = mosquitto__calloc(1, sizeof(struct mosquitto_message_all));
	if(!mosq->will) return MOSQ_ERR_NOMEM;
	mosq->will->msg.topic = mosquitto__strdup(topic);
	if(!mosq->will->msg.topic){
		rc = MOSQ_ERR_NOMEM;
		goto cleanup;
	}
	mosq->will->msg.payloadlen = payloadlen;
	if(mosq->will->msg.payloadlen > 0){
		if(!payload){
			rc = MOSQ_ERR_INVAL;
			goto cleanup;
		}
		mosq->will->msg.payload = mosquitto__malloc(sizeof(char)*(unsigned int)mosq->will->msg.payloadlen);
		if(!mosq->will->msg.payload){
			rc = MOSQ_ERR_NOMEM;
			goto cleanup;
		}

		memcpy(mosq->will->msg.payload, payload, (unsigned int)payloadlen);
	}
	mosq->will->msg.qos = qos;
	mosq->will->msg.retain = retain;

	mosq->will->properties = properties;

	return MOSQ_ERR_SUCCESS;

cleanup:
	if(mosq->will){
		mosquitto__free(mosq->will->msg.topic);
		mosquitto__free(mosq->will->msg.payload);

		mosquitto__free(mosq->will);
		mosq->will = NULL;
	}

	return rc;
}

int will__clear(struct mosquitto *mosq)
{
	if(!mosq->will) return MOSQ_ERR_SUCCESS;

	mosquitto__free(mosq->will->msg.topic);
	mosq->will->msg.topic = NULL;

	mosquitto__free(mosq->will->msg.payload);
	mosq->will->msg.payload = NULL;

	mosquitto_property_free_all(&mosq->will->properties);

	mosquitto__free(mosq->will);
	mosq->will = NULL;
	mosq->will_delay_interval = 0;

	return MOSQ_ERR_SUCCESS;
}

