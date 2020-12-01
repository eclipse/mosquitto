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
#include "persist.h"
#include "time_mosq.h"
#include "util_mosq.h"


int persist__chunk_header_read_v234(FILE *db_fptr, uint32_t *chunk, uint32_t *length)
{
	size_t rlen;
	uint16_t i16temp;
	uint32_t i32temp;

	rlen = fread(&i16temp, sizeof(uint16_t), 1, db_fptr);
	if(rlen != 1) return 1;
	
	rlen = fread(&i32temp, sizeof(uint32_t), 1, db_fptr);
	if(rlen != 1) return 1;
	
	*chunk = ntohs(i16temp);
	*length = ntohl(i32temp);

	return MOSQ_ERR_SUCCESS;
}


int persist__chunk_cfg_read_v234(FILE *db_fptr, struct PF_cfg *chunk)
{
	read_e(db_fptr, &chunk->shutdown, sizeof(uint8_t)); /* shutdown */
	read_e(db_fptr, &chunk->dbid_size, sizeof(uint8_t)); /* sizeof(dbid_t) */
	read_e(db_fptr, &chunk->last_db_id, sizeof(dbid_t));

	return MOSQ_ERR_SUCCESS;
error:
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
	return 1;
}


int persist__chunk_client_read_v234(FILE *db_fptr, struct P_client *chunk, uint32_t db_version)
{
	uint16_t i16temp;
	int rc;
	time_t temp;

	rc = persist__read_string(db_fptr, &chunk->client_id);
	if(rc){
		return rc;
	}

	read_e(db_fptr, &i16temp, sizeof(uint16_t));
	chunk->F.last_mid = ntohs(i16temp);
	if(db_version != 2){
		read_e(db_fptr, &temp, sizeof(time_t));
	}

	return MOSQ_ERR_SUCCESS;
error:
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", strerror(errno));
	mosquitto__free(chunk->client_id);
	return 1;
}


int persist__chunk_client_msg_read_v234(FILE *db_fptr, struct P_client_msg *chunk)
{
	uint16_t i16temp;
	int rc;
	char *err;
	uint8_t retain, dup;

	rc = persist__read_string(db_fptr, &chunk->client_id);
	if(rc){
		return rc;
	}

	read_e(db_fptr, &chunk->F.store_id, sizeof(dbid_t));

	read_e(db_fptr, &i16temp, sizeof(uint16_t));
	chunk->F.mid = ntohs(i16temp);

	read_e(db_fptr, &chunk->F.qos, sizeof(uint8_t));
	read_e(db_fptr, &retain, sizeof(uint8_t));
	read_e(db_fptr, &chunk->F.direction, sizeof(uint8_t));
	read_e(db_fptr, &chunk->F.state, sizeof(uint8_t));
	read_e(db_fptr, &dup, sizeof(uint8_t));

	chunk->F.retain_dup = (uint8_t)((retain&0x0F)<<4 | (dup&0x0F));

	return MOSQ_ERR_SUCCESS;
error:
	err = strerror(errno);
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", err);
	mosquitto__free(chunk->client_id);
	return 1;
}


int persist__chunk_msg_store_read_v234(FILE *db_fptr, struct P_msg_store *chunk, uint32_t db_version)
{
	uint32_t i32temp;
	uint16_t i16temp;
	int rc = 0;
	char *err;

	read_e(db_fptr, &chunk->F.store_id, sizeof(dbid_t));

	rc = persist__read_string(db_fptr, &chunk->source.id);
	if(rc){
		return rc;
	}
	if(db_version == 4){
		rc = persist__read_string(db_fptr, &chunk->source.username);
		if(rc){
			mosquitto__free(chunk->source.id);
			return rc;
		}
		read_e(db_fptr, &i16temp, sizeof(uint16_t));
		chunk->F.source_port = ntohs(i16temp);
	}

	read_e(db_fptr, &i16temp, sizeof(uint16_t));
	chunk->F.source_mid = ntohs(i16temp);

	/* This is the mid - don't need it */
	read_e(db_fptr, &i16temp, sizeof(uint16_t));

	rc = persist__read_string(db_fptr, &chunk->topic);
	if(rc){
		mosquitto__free(chunk->source.id);
		mosquitto__free(chunk->source.username);
		return rc;
	}

	read_e(db_fptr, &chunk->F.qos, sizeof(uint8_t));
	read_e(db_fptr, &chunk->F.retain, sizeof(uint8_t));
	
	read_e(db_fptr, &i32temp, sizeof(uint32_t));
	chunk->F.payloadlen = ntohl(i32temp);

	if(chunk->F.payloadlen){
		chunk->payload = mosquitto_malloc(chunk->F.payloadlen+1);
		if(chunk->payload == NULL){
			mosquitto__free(chunk->source.id);
			mosquitto__free(chunk->source.username);
			mosquitto__free(chunk->topic);
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
		/* Ensure zero terminated regardless of contents */
		((uint8_t *)chunk->payload)[chunk->F.payloadlen] = 0;
		read_e(db_fptr, chunk->payload, chunk->F.payloadlen);
	}

	return MOSQ_ERR_SUCCESS;
error:
	err = strerror(errno);
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", err);
	mosquitto__free(chunk->source.id);
	mosquitto__free(chunk->source.username);
	return 1;
}


int persist__chunk_retain_read_v234(FILE *db_fptr, struct P_retain *chunk)
{
	dbid_t i64temp;
	char *err;

	if(fread(&i64temp, sizeof(dbid_t), 1, db_fptr) != 1){
		err = strerror(errno);
		log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", err);
		return 1;
	}
	chunk->F.store_id = i64temp;

	return MOSQ_ERR_SUCCESS;
}


int persist__chunk_sub_read_v234(FILE *db_fptr, struct P_sub *chunk)
{
	int rc;
	char *err;

	rc = persist__read_string(db_fptr, &chunk->client_id);
	if(rc){
		return rc;
	}

	rc = persist__read_string(db_fptr, &chunk->topic);
	if(rc){
		mosquitto__free(chunk->client_id);
		return rc;
	}

	read_e(db_fptr, &chunk->F.qos, sizeof(uint8_t));

	return MOSQ_ERR_SUCCESS;
error:
	err = strerror(errno);
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", err);
	mosquitto__free(chunk->client_id);
	mosquitto__free(chunk->topic);
	return 1;
}

#endif
