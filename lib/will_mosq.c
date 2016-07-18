/*
Copyright (c) 2010-2015 Roger Light <roger@atchoo.org>

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

#include <stdio.h>
#include <string.h>

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "logging_mosq.h"
#include "messages_mosq.h"
#include "memory_mosq.h"
#include "mqtt3_protocol.h"
#include "net_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "util_mosq.h"

int will__set(struct mosquitto *mosq, const char *topic, int payloadlen, const void *payload, int qos, bool retain)
{
	int rc = MOSQ_ERR_SUCCESS;

	if(!mosq || !topic) return MOSQ_ERR_INVAL;
	if(payloadlen < 0 || payloadlen > MQTT_MAX_PAYLOAD) return MOSQ_ERR_PAYLOAD_SIZE;
	if(payloadlen > 0 && !payload) return MOSQ_ERR_INVAL;

	if(mosquitto_pub_topic_check(topic)) return MOSQ_ERR_INVAL;
	if(mosquitto_validate_utf8(topic, strlen(topic))) return MOSQ_ERR_MALFORMED_UTF8;

	if(mosq->will){
		mosquitto__free(mosq->will->topic);
		mosquitto__free(mosq->will->payload);
		mosquitto__free(mosq->will);
	}

	mosq->will = mosquitto__calloc(1, sizeof(struct mosquitto_message));
	if(!mosq->will) return MOSQ_ERR_NOMEM;
	mosq->will->topic = mosquitto__strdup(topic);
	if(!mosq->will->topic){
		rc = MOSQ_ERR_NOMEM;
		goto cleanup;
	}
	mosq->will->payloadlen = payloadlen;
	if(mosq->will->payloadlen > 0){
		if(!payload){
			rc = MOSQ_ERR_INVAL;
			goto cleanup;
		}
		mosq->will->payload = mosquitto__malloc(sizeof(char)*mosq->will->payloadlen);
		if(!mosq->will->payload){
			rc = MOSQ_ERR_NOMEM;
			goto cleanup;
		}

		memcpy(mosq->will->payload, payload, payloadlen);
	}
	mosq->will->qos = qos;
	mosq->will->retain = retain;

	return MOSQ_ERR_SUCCESS;

cleanup:
	if(mosq->will){
		mosquitto__free(mosq->will->topic);
		mosquitto__free(mosq->will->payload);

		mosquitto__free(mosq->will);
		mosq->will = NULL;
	}

	return rc;
}

int will__clear(struct mosquitto *mosq)
{
	if(!mosq->will) return MOSQ_ERR_SUCCESS;

	mosquitto__free(mosq->will->topic);
	mosq->will->topic = NULL;

	mosquitto__free(mosq->will->payload);
	mosq->will->payload = NULL;

	mosquitto__free(mosq->will);
	mosq->will = NULL;

	return MOSQ_ERR_SUCCESS;
}

