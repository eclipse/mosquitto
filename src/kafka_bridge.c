/*
Copyright (c) 2016 Markus Klostermann <mklostermann@student.tugraz.at>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Markus Klostermann - initial implementation and documentation.
*/

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "config.h"

#include "mosquitto.h"
#include "mosquitto_broker_internal.h"
#include "packet_mosq.h"
#include "memory_mosq.h"

#ifdef WITH_KAFKA_BRIDGE

#include <librdkafka/rdkafka.h>

#define KAFKA_BRIDGE_ID_PREFIX "kafka_bridge"

int kafka_bridge__new(struct mosquitto_db *db, struct kafka__bridge *kafka_bridge, int num)
{
	log__printf(NULL, MOSQ_LOG_DEBUG, "Creating new Kafka bridge %s", kafka_bridge->name);
	struct mosquitto *new_context = NULL;

	assert(db);
	assert(kafka_bridge);

	new_context = context__init(db, INVALID_SOCKET);
	if(!new_context){
		return MOSQ_ERR_NOMEM;
	}
	int len = strlen(KAFKA_BRIDGE_ID_PREFIX) + strlen(kafka_bridge->name) + 2;
	new_context->id = mosquitto__malloc(len);
	if(!new_context->id){
		return MOSQ_ERR_NOMEM;
	}
	snprintf(new_context->id, len, "%s.%s", KAFKA_BRIDGE_ID_PREFIX, kafka_bridge->name);

	HASH_ADD_KEYPTR(hh_id, db->contexts_by_id, new_context->id, strlen(new_context->id), new_context);
	new_context->kafka_bridge = kafka_bridge;
	db->kafka_bridge_count++;

	return kafka_bridge__connect(db, new_context, num);
}

/* Connects to Apache Kafka. The underlying library takes care of reconnecting after failure and much more. */
int kafka_bridge__connect(struct mosquitto_db *db, struct mosquitto *context, int num)
{
	int i;
	char errstr[512];

	// rd_kafka_new will destroy the conf object, so create a copy first
	rd_kafka_conf_t *kafka_conf = rd_kafka_conf_dup(context->kafka_bridge->conf);
	context->kafka_bridge->producer = rd_kafka_new(RD_KAFKA_PRODUCER, kafka_conf, errstr, sizeof(errstr));
	if (!context->kafka_bridge->producer){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Could not create Kafka producer: %s", errstr);
		return MOSQ_ERR_UNKNOWN;
	}

	context->state = mosq_cs_connected;
	context->sock = -2 - num; // fake fd
	context->keepalive = 0;
	HASH_ADD(hh_sock, db->contexts_by_sock, sock, sizeof(context->sock), context);

	// add topic subscriptions
	sub__clean_session(db, context);
	for(i=0; i<context->kafka_bridge->topic_count; i++){
		log__printf(NULL, MOSQ_LOG_INFO, "Kafka bridge %s doing local SUBSCRIBE on topic %s", context->id, context->kafka_bridge->topics[i]);
		if(sub__add(db, context, context->kafka_bridge->topics[i], 0, &db->subs)) return 1;
	}

	return MOSQ_ERR_SUCCESS;
}

/* Replace characters not allowed in Kafka topic names (allowed: [a-zA-Z0-9/_\-]). */
void kafka_bridge__convert_topic_name(char* mqtt_topic){
	char* ch = mqtt_topic;
	do{
		if(*ch == '/'){
			*ch = '.';
		} else if(*ch != '_' && *ch != '-'
				  && (*ch < 'a' || *ch > 'z') && (*ch < 'A' || *ch > 'Z') && (*ch < '0' || *ch > '9')){
			*ch = '-';
		}
	}while(*(++ch));
}

#endif
