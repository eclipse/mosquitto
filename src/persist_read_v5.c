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

#ifdef WITH_PERSISTENCE

#ifndef WIN32
#include <arpa/inet.h>
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "persist.h"
#include "property_mosq.h"
#include "time_mosq.h"
#include "util_mosq.h"


int persist__chunk_header_read_v56(FILE *db_fptr, uint32_t *chunk, uint32_t *length)
{
	size_t rlen;
	struct PF_header header;

	rlen = fread(&header, sizeof(struct PF_header), 1, db_fptr);
	if(rlen != 1) return 1;
	
	*chunk = ntohl(header.chunk);
	*length = ntohl(header.length);

	return MOSQ_ERR_SUCCESS;
}


int persist__chunk_cfg_read_v56(FILE *db_fptr, struct PF_cfg *chunk)
{
	if(fread(chunk, sizeof(struct PF_cfg), 1, db_fptr) != 1){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
		return 1;
	}

	return MOSQ_ERR_SUCCESS;
}


int persist__chunk_client_read_v56(FILE *db_fptr, struct P_client *chunk, uint32_t db_version)
{
	int rc;

	if(db_version == 6){
		read_e(db_fptr, &chunk->F, sizeof(struct PF_client));
		chunk->F.username_len = ntohs(chunk->F.username_len);
		chunk->F.listener_port = ntohs(chunk->F.listener_port);
	}else if(db_version == 5){
		read_e(db_fptr, &chunk->F, sizeof(struct PF_client_v5));
	}else{
		return 1;
	}
	
	chunk->F.session_expiry_interval = ntohl(chunk->F.session_expiry_interval);
	chunk->F.last_mid = ntohs(chunk->F.last_mid);
	chunk->F.id_len = ntohs(chunk->F.id_len);


	rc = persist__read_string_len(db_fptr, &chunk->client_id, chunk->F.id_len);
	if(rc){
		return 1;
	}else if(chunk->client_id == NULL){
		return -1;
	}

	if(chunk->F.username_len > 0){
		rc = persist__read_string_len(db_fptr, &chunk->username, chunk->F.username_len);
		if(rc || !chunk->username){
			mosquitto__free(chunk->client_id);
			return 1;
		}
	}

	return MOSQ_ERR_SUCCESS;
error:
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
	return 1;
}


int persist__chunk_client_msg_read_v56(FILE *db_fptr, struct P_client_msg *chunk, uint32_t length)
{
	mosquitto_property *properties = NULL;
	struct mosquitto__packet prop_packet;
	int rc;

	read_e(db_fptr, &chunk->F, sizeof(struct PF_client_msg));
	chunk->F.mid = ntohs(chunk->F.mid);
	chunk->F.id_len = ntohs(chunk->F.id_len);

	length -= (uint32_t)(sizeof(struct PF_client_msg) + chunk->F.id_len);

	rc = persist__read_string_len(db_fptr, &chunk->client_id, chunk->F.id_len);
	if(rc){
		return rc;
	}

	if(length > 0){
		memset(&prop_packet, 0, sizeof(struct mosquitto__packet));
		prop_packet.remaining_length = length;
		prop_packet.payload = mosquitto__malloc(length);
		if(!prop_packet.payload){
			return MOSQ_ERR_NOMEM;
		}
		read_e(db_fptr, prop_packet.payload, length);
		rc = property__read_all(CMD_PUBLISH, &prop_packet, &properties);
		mosquitto__free(prop_packet.payload);
		if(rc){
			return rc;
		}
	}
	chunk->properties = properties;

	return MOSQ_ERR_SUCCESS;
error:
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
	return 1;
}


int persist__chunk_msg_store_read_v56(FILE *db_fptr, struct P_msg_store *chunk, uint32_t length)
{
	int rc = 0;
	mosquitto_property *properties = NULL;
	struct mosquitto__packet prop_packet;

	memset(&prop_packet, 0, sizeof(struct mosquitto__packet));

	read_e(db_fptr, &chunk->F, sizeof(struct PF_msg_store));
	chunk->F.payloadlen = ntohl(chunk->F.payloadlen);
	if(chunk->F.payloadlen > MQTT_MAX_PAYLOAD){
		return MOSQ_ERR_INVAL;
	}
	chunk->F.source_mid = ntohs(chunk->F.source_mid);
	chunk->F.source_id_len = ntohs(chunk->F.source_id_len);
	chunk->F.source_username_len = ntohs(chunk->F.source_username_len);
	chunk->F.topic_len = ntohs(chunk->F.topic_len);
	chunk->F.source_port = ntohs(chunk->F.source_port);

	length -= (uint32_t)(sizeof(struct PF_msg_store) + chunk->F.payloadlen + chunk->F.source_id_len + chunk->F.source_username_len + chunk->F.topic_len);

	if(chunk->F.source_id_len){
		rc = persist__read_string_len(db_fptr, &chunk->source.id, chunk->F.source_id_len);
		if(rc){
			return rc;
		}
	}
	if(chunk->F.source_username_len){
		rc = persist__read_string_len(db_fptr, &chunk->source.username, chunk->F.source_username_len);
		if(rc){
			mosquitto__free(chunk->source.id);
			chunk->source.id = NULL;
			return rc;
		}
	}
	rc = persist__read_string_len(db_fptr, &chunk->topic, chunk->F.topic_len);
	if(rc){
		mosquitto__free(chunk->source.id);
		mosquitto__free(chunk->source.username);
		chunk->source.id = NULL;
		chunk->source.username = NULL;
		return rc;
	}

	if(chunk->F.payloadlen > 0){
		chunk->payload = mosquitto__malloc(chunk->F.payloadlen+1);
		if(chunk->payload == NULL){
			mosquitto__free(chunk->source.id);
			mosquitto__free(chunk->source.username);
			mosquitto__free(chunk->topic);
			chunk->source.id = NULL;
			chunk->source.username = NULL;
			chunk->topic = NULL;
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
		/* Ensure zero terminated regardless of contents */
		((uint8_t *)chunk->payload)[chunk->F.payloadlen] = 0;
		read_e(db_fptr, chunk->payload, chunk->F.payloadlen);
	}

	if(length > 0){
		prop_packet.remaining_length = length;
		prop_packet.payload = mosquitto__malloc(length);
		if(!prop_packet.payload){
			mosquitto__free(chunk->source.id);
			mosquitto__free(chunk->source.username);
			mosquitto__free(chunk->topic);
			return MOSQ_ERR_NOMEM;
		}
		read_e(db_fptr, prop_packet.payload, length);
		rc = property__read_all(CMD_PUBLISH, &prop_packet, &properties);
		mosquitto__free(prop_packet.payload);
		if(rc){
			mosquitto__free(chunk->source.id);
			mosquitto__free(chunk->source.username);
			mosquitto__free(chunk->topic);
			return rc;
		}
	}
	chunk->properties = properties;

	return MOSQ_ERR_SUCCESS;
error:
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
	mosquitto__free(chunk->source.id);
	mosquitto__free(chunk->source.username);
	mosquitto__free(chunk->topic);
	mosquitto__free(prop_packet.payload);
	return 1;
}


int persist__chunk_retain_read_v56(FILE *db_fptr, struct P_retain *chunk)
{
	if(fread(&chunk->F, sizeof(struct P_retain), 1, db_fptr) != 1){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
		return 1;
	}
	return MOSQ_ERR_SUCCESS;
}


int persist__chunk_sub_read_v56(FILE *db_fptr, struct P_sub *chunk)
{
	int rc;

	read_e(db_fptr, &chunk->F, sizeof(struct PF_sub));
	chunk->F.identifier = ntohl(chunk->F.identifier);
	chunk->F.id_len = ntohs(chunk->F.id_len);
	chunk->F.topic_len = ntohs(chunk->F.topic_len);

	rc = persist__read_string_len(db_fptr, &chunk->client_id, chunk->F.id_len);
	if(rc){
		return rc;
	}
	rc = persist__read_string_len(db_fptr, &chunk->topic, chunk->F.topic_len);
	if(rc){
		mosquitto__free(chunk->client_id);
		chunk->client_id = NULL;
		return rc;
	}

	return MOSQ_ERR_SUCCESS;
error:
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
	return 1;
}

#endif
