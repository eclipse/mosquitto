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


	rc = persist__read_string_len(db_fptr, &chunk->clientid, chunk->F.id_len);
	if(rc){
		return 1;
	}else if(chunk->clientid == NULL){
		return -1;
	}

	if(chunk->F.username_len > 0){
		rc = persist__read_string_len(db_fptr, &chunk->username, chunk->F.username_len);
		if(rc || !chunk->username){
			mosquitto__FREE(chunk->clientid);
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
	mosquitto_property *properties = NULL, *p;
	struct mosquitto__packet_in prop_packet;
	int rc;

	memset(&prop_packet, 0, sizeof(struct mosquitto__packet));

	read_e(db_fptr, &chunk->F, sizeof(struct PF_client_msg));
	chunk->F.mid = ntohs(chunk->F.mid);
	chunk->F.id_len = ntohs(chunk->F.id_len);

	length -= (uint32_t)(sizeof(struct PF_client_msg) + chunk->F.id_len);
	if(length > MQTT_MAX_PAYLOAD) goto error;

	rc = persist__read_string_len(db_fptr, &chunk->clientid, chunk->F.id_len);
	if(rc) return rc;

	if(length > 0){
		prop_packet.remaining_length = length;
		prop_packet.payload = mosquitto__malloc(length);
		if(!prop_packet.payload){
			errno = ENOMEM;
			goto error;
		}

		read_e(db_fptr, prop_packet.payload, length);
		rc = property__read_all(CMD_PUBLISH, &prop_packet, &properties);
		mosquitto__FREE(prop_packet.payload);
		if(rc){
			mosquitto__FREE(chunk->clientid);
			return rc;
		}

		if(properties){
			p = properties;
			while(p){
				if(p->identifier == MQTT_PROP_SUBSCRIPTION_IDENTIFIER){
					chunk->subscription_identifier = p->value.varint;
				}
				p = p->next;
			}
			mosquitto_property_free_all(&properties);
		}
	}

	return MOSQ_ERR_SUCCESS;
error:
	mosquitto__FREE(chunk->clientid);
	mosquitto__FREE(prop_packet.payload);
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
	return 1;
}


int persist__chunk_base_msg_read_v56(FILE *db_fptr, struct P_base_msg *chunk, uint32_t length)
{
	int rc = 0;
	mosquitto_property *properties = NULL;
	struct mosquitto__packet_in prop_packet;

	memset(&prop_packet, 0, sizeof(struct mosquitto__packet));

	read_e(db_fptr, &chunk->F, sizeof(struct PF_base_msg));
	chunk->F.payloadlen = ntohl(chunk->F.payloadlen);
	if(chunk->F.payloadlen > MQTT_MAX_PAYLOAD){
		return MOSQ_ERR_INVAL;
	}
	chunk->F.source_mid = ntohs(chunk->F.source_mid);
	chunk->F.source_id_len = ntohs(chunk->F.source_id_len);
	chunk->F.source_username_len = ntohs(chunk->F.source_username_len);
	chunk->F.topic_len = ntohs(chunk->F.topic_len);
	chunk->F.source_port = ntohs(chunk->F.source_port);

	length -= (uint32_t)(sizeof(struct PF_base_msg) + chunk->F.payloadlen + chunk->F.source_id_len + chunk->F.source_username_len + chunk->F.topic_len);
	if(length > MQTT_MAX_PAYLOAD) goto error;

	if(chunk->F.source_id_len){
		rc = persist__read_string_len(db_fptr, &chunk->source.id, chunk->F.source_id_len);
		if(rc) goto error;
	}
	if(chunk->F.source_username_len){
		rc = persist__read_string_len(db_fptr, &chunk->source.username, chunk->F.source_username_len);
		if(rc) goto error;
	}
	rc = persist__read_string_len(db_fptr, &chunk->topic, chunk->F.topic_len);
	if(rc) goto error;

	if(chunk->F.payloadlen > 0){
		chunk->payload = mosquitto__malloc(chunk->F.payloadlen+1);
		if(chunk->payload == NULL){
			rc = MOSQ_ERR_NOMEM;
			goto error;
		}
		read_e(db_fptr, chunk->payload, chunk->F.payloadlen);
		/* Ensure zero terminated regardless of contents */
		((uint8_t *)chunk->payload)[chunk->F.payloadlen] = 0;
	}

	if(length > 0){
		prop_packet.remaining_length = length;
		prop_packet.payload = mosquitto__malloc(length);
		if(!prop_packet.payload){
			rc = MOSQ_ERR_NOMEM;
			goto error;
		}
		read_e(db_fptr, prop_packet.payload, length);
		rc = property__read_all(CMD_PUBLISH, &prop_packet, &properties);
		mosquitto__FREE(prop_packet.payload);
		if(rc){
			rc = MOSQ_ERR_NOMEM;
			goto error;
		}
	}
	chunk->properties = properties;

	return MOSQ_ERR_SUCCESS;
error:
	mosquitto__FREE(chunk->payload);
	mosquitto__FREE(chunk->source.id);
	mosquitto__FREE(chunk->source.username);
	mosquitto__FREE(chunk->topic);
	mosquitto__FREE(prop_packet.payload);
	return rc;
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
	int rc = MOSQ_ERR_SUCCESS;

	read_e(db_fptr, &chunk->F, sizeof(struct PF_sub));
	chunk->F.identifier = ntohl(chunk->F.identifier);
	chunk->F.id_len = ntohs(chunk->F.id_len);
	chunk->F.topic_len = ntohs(chunk->F.topic_len);

	rc = persist__read_string_len(db_fptr, &chunk->clientid, chunk->F.id_len);
	if(rc) goto error;

	rc = persist__read_string_len(db_fptr, &chunk->topic, chunk->F.topic_len);
	if(rc) goto error;

	return MOSQ_ERR_SUCCESS;
error:
	mosquitto__FREE(chunk->clientid);
	return rc;
}

#endif
