/*
Copyright (c) 2010-2019 Roger Light <roger@atchoo.org>

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

#include <inttypes.h>
#include <stdio.h>

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
			case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
				printf("\t\tPayload format indicator: %d\n", properties->value.i8);
				break;
			case MQTT_PROP_REQUEST_PROBLEM_INFORMATION:
				printf("\t\tRequest problem information: %d\n", properties->value.i8);
				break;
			case MQTT_PROP_REQUEST_RESPONSE_INFORMATION:
				printf("\t\tRequest response information: %d\n", properties->value.i8);
				break;
			case MQTT_PROP_MAXIMUM_QOS:
				printf("\t\tMaximum QoS: %d\n", properties->value.i8);
				break;
			case MQTT_PROP_RETAIN_AVAILABLE:
				printf("\t\tRetain available: %d\n", properties->value.i8);
				break;
			case MQTT_PROP_WILDCARD_SUB_AVAILABLE:
				printf("\t\tWildcard sub available: %d\n", properties->value.i8);
				break;
			case MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE:
				printf("\t\tSubscription ID available: %d\n", properties->value.i8);
				break;
			case MQTT_PROP_SHARED_SUB_AVAILABLE:
				printf("\t\tShared subscription available: %d\n", properties->value.i8);
				break;

			case MQTT_PROP_SERVER_KEEP_ALIVE:
				printf("\t\tServer keep alive: %d\n", properties->value.i16);
				break;
			case MQTT_PROP_RECEIVE_MAXIMUM:
				printf("\t\tReceive maximum: %d\n", properties->value.i16);
				break;
			case MQTT_PROP_TOPIC_ALIAS_MAXIMUM:
				printf("\t\tTopic alias maximum: %d\n", properties->value.i16);
				break;
			case MQTT_PROP_TOPIC_ALIAS:
				printf("\t\tTopic alias: %d\n", properties->value.i16);
				break;

			case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
				printf("\t\tMessage expiry interval: %d\n", properties->value.i32);
				break;
			case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
				printf("\t\tSession expiry interval: %d\n", properties->value.i32);
				break;
			case MQTT_PROP_WILL_DELAY_INTERVAL:
				printf("\t\tWill delay interval: %d\n", properties->value.i32);
				break;
			case MQTT_PROP_MAXIMUM_PACKET_SIZE:
				printf("\t\tMaximum packet size: %d\n", properties->value.i32);
				break;

			case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
				printf("\t\tSubscription identifier: %d\n", properties->value.varint);
				break;

			case MQTT_PROP_CONTENT_TYPE:
				printf("\t\tContent type: %s\n", properties->value.s.v);
				break;
			case MQTT_PROP_RESPONSE_TOPIC:
				printf("\t\tResponse topic: %s\n", properties->value.s.v);
				break;
			case MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER:
				printf("\t\tAssigned client identifier: %s\n", properties->value.s.v);
				break;
			case MQTT_PROP_AUTHENTICATION_METHOD:
				printf("\t\tAuthentication method: %s\n", properties->value.s.v);
				break;
			case MQTT_PROP_RESPONSE_INFORMATION:
				printf("\t\tResponse information: %s\n", properties->value.s.v);
				break;
			case MQTT_PROP_SERVER_REFERENCE:
				printf("\t\tServer reference: %s\n", properties->value.s.v);
				break;
			case MQTT_PROP_REASON_STRING:
				printf("\t\tReason string: %s\n", properties->value.s.v);
				break;

			case MQTT_PROP_AUTHENTICATION_DATA:
				printf("\t\tAuthentication data: ");
				for(i=0; i<properties->value.bin.len; i++){
					printf("%02X", properties->value.bin.v[i]);
				}
				printf("\n");
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


void print__client(struct P_client *chunk, int length)
{
	printf("DB_CHUNK_CLIENT:\n");
	printf("\tLength: %d\n", length);
	printf("\tClient ID: %s\n", chunk->client_id);
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


void print__client_msg(struct P_client_msg *chunk, int length)
{
	printf("DB_CHUNK_CLIENT_MSG:\n");
	printf("\tLength: %d\n", length);
	printf("\tClient ID: %s\n", chunk->client_id);
	printf("\tStore ID: %" PRIu64 "\n", chunk->F.store_id);
	printf("\tMID: %d\n", chunk->F.mid);
	printf("\tQoS: %d\n", chunk->F.qos);
	printf("\tRetain: %d\n", (chunk->F.retain_dup&0xF0)>>4);
	printf("\tDirection: %d\n", chunk->F.direction);
	printf("\tState: %d\n", chunk->F.state);
	printf("\tDup: %d\n", chunk->F.retain_dup&0x0F);
	print__properties(chunk->properties);
}


void print__msg_store(struct P_msg_store *chunk, int length)
{
	printf("DB_CHUNK_MSG_STORE:\n");
	printf("\tLength: %d\n", length);
	printf("\tStore ID: %" PRIu64 "\n", chunk->F.store_id);
	//printf("\tSource ID: %s\n", chunk->source_id);
	//printf("\tSource Username: %s\n", chunk->source_username);
	printf("\tSource Port: %d\n", chunk->F.source_port);
	printf("\tSource MID: %d\n", chunk->F.source_mid);
	printf("\tTopic: %s\n", chunk->topic);
	printf("\tQoS: %d\n", chunk->F.qos);
	printf("\tRetain: %d\n", chunk->F.retain);
	printf("\tPayload Length: %d\n", chunk->F.payloadlen);
	printf("\tExpiry Time: %" PRIu64 "\n", chunk->F.expiry_time);

	uint8_t *payload;

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
	printf("\tClient ID: %s\n", chunk->client_id);
	printf("\tTopic: %s\n", chunk->topic);
	printf("\tQoS: %d\n", chunk->F.qos);
	printf("\tSubscription ID: %d\n", chunk->F.identifier);
	printf("\tOptions: 0x%02X\n", chunk->F.options);
}


