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

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <mosquitto_broker_internal.h>
#include <memory_mosq.h>
#include <persist.h>

#define mosquitto__malloc(A) malloc((A))
#define mosquitto__free(A) free((A))
#define _mosquitto_malloc(A) malloc((A))
#define _mosquitto_free(A) free((A))
#include <uthash.h>

#include "db_dump.h"

struct client_data
{
	UT_hash_handle hh_id;
	char *id;
	uint32_t subscriptions;
	uint32_t subscription_size;
	int messages;
	long message_size;
};

struct msg_store_chunk
{
	UT_hash_handle hh;
	dbid_t store_id;
	uint32_t length;
};

struct mosquitto_db db;

extern uint32_t db_version;
static int stats = 0;
static int client_stats = 0;
static int do_print = 1;

/* Counts */
static long cfg_count = 0;
static long client_count = 0;
static long client_msg_count = 0;
static long msg_store_count = 0;
static long retain_count = 0;
static long sub_count = 0;
/* ====== */


struct client_data *clients_by_id = NULL;
struct msg_store_chunk *msgs_by_id = NULL;


static void free__sub(struct P_sub *chunk)
{
	free(chunk->client_id);
	free(chunk->topic);
}

static void free__client(struct P_client *chunk)
{
	free(chunk->client_id);
}


static void free__client_msg(struct P_client_msg *chunk)
{
	free(chunk->client_id);
	mosquitto_property_free_all(&chunk->properties);
}


static void free__msg_store(struct P_msg_store *chunk)
{
	//free(chunk->source_id);
	free(chunk->topic);
	free(chunk->payload);
	mosquitto_property_free_all(&chunk->properties);
}


static int dump__cfg_chunk_process(FILE *db_fd, uint32_t length)
{
	struct PF_cfg chunk;
	int rc;

	cfg_count++;

	memset(&chunk, 0, sizeof(struct PF_cfg));

	if(db_version == 6 || db_version == 5){
		rc = persist__chunk_cfg_read_v56(db_fd, &chunk);
	}else{
		rc = persist__chunk_cfg_read_v234(db_fd, &chunk);
	}
	if(rc){
		fprintf(stderr, "Error: Corrupt persistent database.");
		fclose(db_fd);
		return rc;
	}
	
	if(do_print) printf("DB_CHUNK_CFG:\n");
	if(do_print) printf("\tLength: %d\n", length);
	if(do_print) printf("\tShutdown: %d\n", chunk.shutdown);
	if(do_print) printf("\tDB ID size: %d\n", chunk.dbid_size);
	if(chunk.dbid_size != sizeof(dbid_t)){
		fprintf(stderr, "Error: Incompatible database configuration (dbid size is %d bytes, expected %ld)",
				chunk.dbid_size, sizeof(dbid_t));
		fclose(db_fd);
		return 1;
	}
	if(do_print) printf("\tLast DB ID: %" PRIu64 "\n", chunk.last_db_id);

	return 0;
}


static int dump__client_chunk_process(FILE *db_fd, uint32_t length)
{
	struct P_client chunk;
	int rc = 0;
	struct client_data *cc;

	client_count++;

	memset(&chunk, 0, sizeof(struct P_client));

	if(db_version == 6 || db_version == 5){
		rc = persist__chunk_client_read_v56(db_fd, &chunk, db_version);
	}else{
		rc = persist__chunk_client_read_v234(db_fd, &chunk, db_version);
	}
	if(rc){
		fprintf(stderr, "Error: Corrupt persistent database.");
		return rc;
	}

	if(client_stats){
		cc = calloc(1, sizeof(struct client_data));
		if(!cc){
			fprintf(stderr, "Error: Out of memory.\n");
			fclose(db_fd);
			free(chunk.client_id);
			return 1;
		}
		cc->id = strdup(chunk.client_id);
		HASH_ADD_KEYPTR(hh_id, clients_by_id, cc->id, strlen(cc->id), cc);
	}

	if(do_print) {
		print__client(&chunk, length);
	}
	free__client(&chunk);

	return 0;
}


static int dump__client_msg_chunk_process(FILE *db_fd, uint32_t length)
{
	struct P_client_msg chunk;
	struct client_data *cc;
	struct msg_store_chunk *msc;
	int rc;

	client_msg_count++;

	memset(&chunk, 0, sizeof(struct P_client_msg));
	if(db_version == 6 || db_version == 5){
		rc = persist__chunk_client_msg_read_v56(db_fd, &chunk, length);
	}else{
		rc = persist__chunk_client_msg_read_v234(db_fd, &chunk);
	}
	if(rc){
		fprintf(stderr, "Error: Corrupt persistent database.");
		fclose(db_fd);
		return rc;
	}

	if(client_stats){
		HASH_FIND(hh_id, clients_by_id, chunk.client_id, strlen(chunk.client_id), cc);
		if(cc){
			cc->messages++;
			cc->message_size += length;

			HASH_FIND(hh, msgs_by_id, &chunk.F.store_id, sizeof(dbid_t), msc);
			if(msc){
				cc->message_size += msc->length;
			}
		}
	}

	if(do_print) {
		print__client_msg(&chunk, length);
	}
	free__client_msg(&chunk);
	return 0;
}


static int dump__msg_store_chunk_process(FILE *db_fptr, uint32_t length)
{
	struct P_msg_store chunk;
	struct mosquitto_msg_store *stored = NULL;
	struct mosquitto_msg_store_load *load;
	int64_t message_expiry_interval64;
	uint32_t message_expiry_interval;
	int rc = 0;
	struct msg_store_chunk *mcs;

	msg_store_count++;

	memset(&chunk, 0, sizeof(struct P_msg_store));
	if(db_version == 6 || db_version == 5){
		rc = persist__chunk_msg_store_read_v56(db_fptr, &chunk, length);
	}else{
		rc = persist__chunk_msg_store_read_v234(db_fptr, &chunk, db_version);
	}
	if(rc){
		fprintf(stderr, "Error: Corrupt persistent database.");
		fclose(db_fptr);
		return rc;
	}

	load = mosquitto__calloc(1, sizeof(struct mosquitto_msg_store_load));
	if(!load){
		fclose(db_fptr);
		mosquitto__free(chunk.source.id);
		mosquitto__free(chunk.source.username);
		mosquitto__free(chunk.topic);
		mosquitto__free(chunk.payload);
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}

	if(chunk.F.expiry_time > 0){
		message_expiry_interval64 = chunk.F.expiry_time - time(NULL);
		if(message_expiry_interval64 < 0 || message_expiry_interval64 > UINT32_MAX){
			message_expiry_interval = 0;
		}else{
			message_expiry_interval = (uint32_t)message_expiry_interval64;
		}
	}else{
		message_expiry_interval = 0;
	}

	stored = mosquitto__calloc(1, sizeof(struct mosquitto_msg_store));
	if(stored == NULL){
		mosquitto__free(load);
		fclose(db_fptr);
		mosquitto__free(chunk.source.id);
		mosquitto__free(chunk.source.username);
		mosquitto__free(chunk.topic);
		mosquitto__free(chunk.payload);
		return MOSQ_ERR_NOMEM;
	}
	stored->source_mid = chunk.F.source_mid;
	stored->topic = chunk.topic;
	stored->qos = chunk.F.qos;
	stored->retain = chunk.F.retain;
	stored->payloadlen = chunk.F.payloadlen;
	stored->payload =  chunk.payload;
	stored->properties = chunk.properties;

	rc = db__message_store(&chunk.source, stored, message_expiry_interval,
			chunk.F.store_id, mosq_mo_client);

	mosquitto__free(chunk.source.id);
	mosquitto__free(chunk.source.username);
	chunk.source.id = NULL;
	chunk.source.username = NULL;

	if(rc == MOSQ_ERR_SUCCESS){
		stored->source_listener = chunk.source.listener;
		load->db_id = stored->db_id;
		load->store = stored;

		HASH_ADD(hh, db.msg_store_load, db_id, sizeof(dbid_t), load);
	}else{
		mosquitto__free(load);
		fclose(db_fptr);
		return rc;
	}

	if(client_stats){
		mcs = calloc(1, sizeof(struct msg_store_chunk));
		if(!mcs){
			errno = ENOMEM;
			return 1;
		}
		mcs->store_id = chunk.F.store_id;
		mcs->length = length;
		HASH_ADD(hh, msgs_by_id, store_id, sizeof(dbid_t), mcs);
	}

	if(do_print){
		print__msg_store(&chunk, length);
	}
	free__msg_store(&chunk);

	return 0;
}


static int dump__retain_chunk_process(FILE *db_fd, uint32_t length)
{
	struct P_retain chunk;
	int rc;

	retain_count++;
	if(do_print) printf("DB_CHUNK_RETAIN:\n");
	if(do_print) printf("\tLength: %d\n", length);

	if(db_version == 6 || db_version == 5){
		rc = persist__chunk_retain_read_v56(db_fd, &chunk);
	}else{
		rc = persist__chunk_retain_read_v234(db_fd, &chunk);
	}
	if(rc){
		fclose(db_fd);
		return rc;
	}

	if(do_print) printf("\tStore ID: %" PRIu64 "\n", chunk.F.store_id);
	return 0;
}


static int dump__sub_chunk_process(FILE *db_fd, uint32_t length)
{
	int rc = 0;
	struct P_sub chunk;
	struct client_data *cc;

	sub_count++;

	memset(&chunk, 0, sizeof(struct P_sub));
	if(db_version == 6 || db_version == 5){
		rc = persist__chunk_sub_read_v56(db_fd, &chunk);
	}else{
		rc = persist__chunk_sub_read_v234(db_fd, &chunk);
	}
	if(rc){
		fprintf(stderr, "Error: Corrupt persistent database.");
		fclose(db_fd);
		return rc;
	}

	if(client_stats){
		HASH_FIND(hh_id, clients_by_id, chunk.client_id, strlen(chunk.client_id), cc);
		if(cc){
			cc->subscriptions++;
			cc->subscription_size += length;
		}
	}

	if(do_print) {
		print__sub(&chunk, length);
	}
	free__sub(&chunk);

	return 0;
}


int main(int argc, char *argv[])
{
	FILE *fd;
	char header[15];
	int rc = 0;
	uint32_t crc;
	uint32_t i32temp;
	uint32_t length;
	uint32_t chunk;
	char *filename;
	struct client_data *cc, *cc_tmp;

	if(argc == 2){
		filename = argv[1];
	}else if(argc == 3 && !strcmp(argv[1], "--stats")){
		stats = 1;
		do_print = 0;
		filename = argv[2];
	}else if(argc == 3 && !strcmp(argv[1], "--client-stats")){
		client_stats = 1;
		do_print = 0;
		filename = argv[2];
	}else{
		fprintf(stderr, "Usage: db_dump [--stats | --client-stats] <mosquitto db filename>\n");
		return 1;
	}
	memset(&db, 0, sizeof(struct mosquitto_db));
	fd = fopen(filename, "rb");
	if(!fd){
		fprintf(stderr, "Error: Unable to open %s\n", filename);
		return 0;
	}
	read_e(fd, &header, 15);
	if(!memcmp(header, magic, 15)){
		if(do_print) printf("Mosquitto DB dump\n");
		// Restore DB as normal
		read_e(fd, &crc, sizeof(uint32_t));
		if(do_print) printf("CRC: %d\n", crc);
		read_e(fd, &i32temp, sizeof(uint32_t));
		db_version = ntohl(i32temp);
		if(do_print) printf("DB version: %d\n", db_version);

		if(db_version > MOSQ_DB_VERSION){
			if(do_print) printf("Warning: mosquitto_db_dump does not support this DB version, continuing but expecting errors.\n");
		}

		while(persist__chunk_header_read(fd, &chunk, &length) == MOSQ_ERR_SUCCESS){
			switch(chunk){
				case DB_CHUNK_CFG:
					if(dump__cfg_chunk_process(fd, length)) return 1;
					break;

				case DB_CHUNK_MSG_STORE:
					if(dump__msg_store_chunk_process(fd, length)) return 1;
					break;

				case DB_CHUNK_CLIENT_MSG:
					if(dump__client_msg_chunk_process(fd, length)) return 1;
					break;

				case DB_CHUNK_RETAIN:
					if(dump__retain_chunk_process(fd, length)) return 1;
					break;

				case DB_CHUNK_SUB:
					if(dump__sub_chunk_process(fd, length)) return 1;
					break;

				case DB_CHUNK_CLIENT:
					if(dump__client_chunk_process(fd, length)) return 1;
					break;

				default:
					fprintf(stderr, "Warning: Unsupported chunk \"%d\" in persistent database file. Ignoring.\n", chunk);
					if(fseek(fd, length, SEEK_CUR) < 0){
						fprintf(stderr, "Error seeking in file.\n");
						return 1;
					}
					break;
			}
		}
	}else{
		fprintf(stderr, "Error: Unrecognised file format.");
		rc = 1;
	}

	fclose(fd);

	if(stats){
		printf("DB_CHUNK_CFG:        %ld\n", cfg_count);
		printf("DB_CHUNK_MSG_STORE:  %ld\n", msg_store_count);
		printf("DB_CHUNK_CLIENT_MSG: %ld\n", client_msg_count);
		printf("DB_CHUNK_RETAIN:     %ld\n", retain_count);
		printf("DB_CHUNK_SUB:        %ld\n", sub_count);
		printf("DB_CHUNK_CLIENT:     %ld\n", client_count);
	}

	if(client_stats){
		HASH_ITER(hh_id, clients_by_id, cc, cc_tmp){
			printf("SC: %d SS: %d MC: %d MS: %ld   ", cc->subscriptions, cc->subscription_size, cc->messages, cc->message_size);
			printf("%s\n", cc->id);
			free(cc->id);
		}
	}

	return rc;
error:
	fprintf(stderr, "Error: %s.", strerror(errno));
	if(fd) fclose(fd);
	return 1;
}

