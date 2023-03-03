/*
Copyright (c) 2010-2021 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include <inttypes.h>
#include <stdio.h>

#include "db_dump.h"
#include <mosquitto_broker_internal.h>
#include <memory_mosq.h>
#include <mqtt_protocol.h>
#include <persist.h>
#include <property_mosq.h>


static void print__properties(mosquitto_property *properties)
{
	int i;

	if(properties == NULL) return;

	printf("\tProperties:\n");

	while(properties){
		switch(properties->identifier){
			/* Only properties for base messages are valid for saving */
			case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
				printf("\t\tPayload format indicator: %d\n", properties->value.i8);
				break;

			case MQTT_PROP_CONTENT_TYPE:
				printf("\t\tContent type: %s\n", properties->value.s.v);
				break;

			case MQTT_PROP_RESPONSE_TOPIC:
				printf("\t\tResponse topic: %s\n", properties->value.s.v);
				break;

			case MQTT_PROP_CORRELATION_DATA:
				printf("\t\tCorrelation data: ");
				for(i=0; i<properties->value.bin.len; i++){
					printf("%02X", properties->value.bin.v[i]);
				}
				printf("\n");
				break;

			case MQTT_PROP_USER_PROPERTY:
				printf("\t\tUser property: %s , %s\n", properties->name.v, properties->value.s.v);
				break;

			default:
				printf("\t\tInvalid property type: %d\n", properties->identifier);
				break;
		}

		properties = properties->next;
	}
}


void print__client(struct P_client *chunk, uint32_t length)
{
	printf("DB_CHUNK_CLIENT:\n");
	printf("\tLength: %d\n", length);
	printf("\tClient ID: %s\n", chunk->clientid);
	if(chunk->username){
		printf("\tUsername: %s\n", chunk->username);
	}
	if(chunk->F.listener_port > 0){
		printf("\tListener port: %u\n", chunk->F.listener_port);
	}
	printf("\tLast MID: %d\n", chunk->F.last_mid);
	printf("\tSession expiry time: %" PRIu64 "\n", chunk->F.session_expiry_time);
	printf("\tSession expiry interval: %u\n", chunk->F.session_expiry_interval);
}


void print__client_msg(struct P_client_msg *chunk, uint32_t length)
{
	printf("DB_CHUNK_CLIENT_MSG:\n");
	printf("\tLength: %d\n", length);
	printf("\tClient ID: %s\n", chunk->clientid);
	printf("\tStore ID: %" PRIu64 "\n", chunk->F.store_id);
	printf("\tMID: %d\n", chunk->F.mid);
	printf("\tQoS: %d\n", chunk->F.qos);
	printf("\tRetain: %d\n", (chunk->F.retain_dup&0xF0)>>4);
	printf("\tDirection: %d\n", chunk->F.direction);
	printf("\tState: %d\n", chunk->F.state);
	printf("\tDup: %d\n", chunk->F.retain_dup&0x0F);
	if(chunk->subscription_identifier){
		printf("\tSubscription identifier: %d\n", chunk->subscription_identifier);
	}
}


void print__base_msg(struct P_base_msg *chunk, uint32_t length)
{
	uint8_t *payload;

	printf("DB_CHUNK_BASE_MSG:\n");
	printf("\tLength: %d\n", length);
	printf("\tStore ID: %" PRIu64 "\n", chunk->F.store_id);
	/* printf("\tSource ID: %s\n", chunk->source_id); */
	/* printf("\tSource Username: %s\n", chunk->source_username); */
	printf("\tSource Port: %d\n", chunk->F.source_port);
	printf("\tSource MID: %d\n", chunk->F.source_mid);
	printf("\tTopic: %s\n", chunk->topic);
	printf("\tQoS: %d\n", chunk->F.qos);
	printf("\tRetain: %d\n", chunk->F.retain);
	printf("\tPayload Length: %d\n", chunk->F.payloadlen);
	printf("\tExpiry Time: %" PRIu64 "\n", chunk->F.expiry_time);

	payload = chunk->payload;
	if(chunk->F.payloadlen < 256){
		/* Print payloads with UTF-8 data below an arbitrary limit of 256 bytes */
		if(mosquitto_validate_utf8((char *)payload, (uint16_t)chunk->F.payloadlen) == MOSQ_ERR_SUCCESS){
			printf("\tPayload: %s\n", payload);
		}
	}
	print__properties(chunk->properties);
}


void print__sub(struct P_sub *chunk, uint32_t length)
{
	printf("DB_CHUNK_SUB:\n");
	printf("\tLength: %u\n", length);
	printf("\tClient ID: %s\n", chunk->clientid);
	printf("\tTopic: %s\n", chunk->topic);
	printf("\tQoS: %d\n", chunk->F.qos);
	printf("\tSubscription ID: %d\n", chunk->F.identifier);
	printf("\tOptions: 0x%02X\n", chunk->F.options);
}


