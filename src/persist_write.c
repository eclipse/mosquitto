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
#include "misc_mosq.h"
#include "util_mosq.h"

static int persist__client_messages_save(FILE *db_fptr, struct mosquitto *context, struct mosquitto_client_msg *queue)
{
	struct P_client_msg chunk;
	struct mosquitto_client_msg *cmsg;
	int rc;

	assert(db_fptr);
	assert(context);

	memset(&chunk, 0, sizeof(struct P_client_msg));

	cmsg = queue;
	while(cmsg){
		if(!strncmp(cmsg->store->topic, "$SYS", 4)
				&& cmsg->store->ref_count <= 1
				&& cmsg->store->dest_id_count == 0){

			/* This $SYS message won't have been persisted, so we can't persist
			 * this client message. */
			cmsg = cmsg->next;
			continue;
		}

		chunk.F.store_id = cmsg->store->db_id;
		chunk.F.mid = cmsg->mid;
		chunk.F.id_len = (uint16_t)strlen(context->id);
		chunk.F.qos = cmsg->qos;
		chunk.F.retain_dup = (uint8_t)((cmsg->retain&0x0F)<<4 | (cmsg->dup&0x0F));
		chunk.F.direction = (uint8_t)cmsg->direction;
		chunk.F.state = (uint8_t)cmsg->state;
		chunk.client_id = context->id;
		chunk.properties = cmsg->properties;

		rc = persist__chunk_client_msg_write_v6(db_fptr, &chunk);
		if(rc){
			return rc;
		}

		cmsg = cmsg->next;
	}

	return MOSQ_ERR_SUCCESS;
}


static int persist__message_store_save(FILE *db_fptr)
{
	struct P_msg_store chunk;
	struct mosquitto_msg_store *stored;
	int rc;

	assert(db_fptr);

	memset(&chunk, 0, sizeof(struct P_msg_store));

	stored = db.msg_store;
	while(stored){
		if(stored->ref_count < 1 || stored->topic == NULL){
			stored = stored->next;
			continue;
		}

		if(!strncmp(stored->topic, "$SYS", 4)){
			if(stored->ref_count <= 1 && stored->dest_id_count == 0){
				/* $SYS messages that are only retained shouldn't be persisted. */
				stored = stored->next;
				continue;
			}
			/* Don't save $SYS messages as retained otherwise they can give
			 * misleading information when reloaded. They should still be saved
			 * because a disconnected durable client may have them in their
			 * queue. */
			chunk.F.retain = 0;
		}else{
			chunk.F.retain = (uint8_t)stored->retain;
		}

		chunk.F.store_id = stored->db_id;
		chunk.F.expiry_time = stored->message_expiry_time;
		chunk.F.payloadlen = stored->payloadlen;
		chunk.F.source_mid = stored->source_mid;
		if(stored->source_id){
			chunk.F.source_id_len = (uint16_t)strlen(stored->source_id);
			chunk.source.id = stored->source_id;
		}else{
			chunk.F.source_id_len = 0;
			chunk.source.id = NULL;
		}
		if(stored->source_username){
			chunk.F.source_username_len = (uint16_t)strlen(stored->source_username);
			chunk.source.username = stored->source_username;
		}else{
			chunk.F.source_username_len = 0;
			chunk.source.username = NULL;
		}

		chunk.F.topic_len = (uint16_t)strlen(stored->topic);
		chunk.topic = stored->topic;

		if(stored->source_listener){
			chunk.F.source_port = stored->source_listener->port;
		}else{
			chunk.F.source_port = 0;
		}
		chunk.F.qos = stored->qos;
		chunk.payload = stored->payload;
		chunk.properties = stored->properties;

		rc = persist__chunk_message_store_write_v6(db_fptr, &chunk);
		if(rc){
			return rc;
		}
		stored = stored->next;
	}

	return MOSQ_ERR_SUCCESS;
}

static int persist__client_save(FILE *db_fptr)
{
	struct mosquitto *context, *ctxt_tmp;
	struct P_client chunk;
	int rc;

	assert(db_fptr);

	memset(&chunk, 0, sizeof(struct P_client));

	HASH_ITER(hh_id, db.contexts_by_id, context, ctxt_tmp){
		if(context && context->clean_start == false){
			chunk.F.session_expiry_time = context->session_expiry_time;
			chunk.F.session_expiry_interval = context->session_expiry_interval;
			chunk.F.last_mid = context->last_mid;
			chunk.F.id_len = (uint16_t)strlen(context->id);
			chunk.client_id = context->id;
			if(context->username){
				chunk.F.username_len = (uint16_t)strlen(context->username);
				chunk.username = context->username;
			}
			if(context->listener){
				chunk.F.listener_port = context->listener->port;
			}

			if(chunk.F.id_len == 0){
				/* This should never happen, but in case we have a client with
				 * zero length ID, don't persist them. */
				continue;
			}

			rc = persist__chunk_client_write_v6(db_fptr, &chunk);
			if(rc){
				return rc;
			}

			if(persist__client_messages_save(db_fptr, context, context->msgs_in.inflight)) return 1;
			if(persist__client_messages_save(db_fptr, context, context->msgs_in.queued)) return 1;
			if(persist__client_messages_save(db_fptr, context, context->msgs_out.inflight)) return 1;
			if(persist__client_messages_save(db_fptr, context, context->msgs_out.queued)) return 1;
		}
	}

	return MOSQ_ERR_SUCCESS;
}


static int persist__subs_save(FILE *db_fptr, struct mosquitto__subhier *node, const char *topic, int level)
{
	struct mosquitto__subhier *subhier, *subhier_tmp;
	struct mosquitto__subleaf *sub;
	struct P_sub sub_chunk;
	char *thistopic;
	size_t slen;
	int rc;

	memset(&sub_chunk, 0, sizeof(struct P_sub));

	slen = strlen(topic) + node->topic_len + 2;
	thistopic = mosquitto__malloc(sizeof(char)*slen);
	if(!thistopic) return MOSQ_ERR_NOMEM;
	if(level > 1 || strlen(topic)){
		snprintf(thistopic, slen, "%s/%s", topic, node->topic);
	}else{
		snprintf(thistopic, slen, "%s", node->topic);
	}

	sub = node->subs;
	while(sub){
		if(sub->context->clean_start == false && sub->context->id){
			sub_chunk.F.identifier = sub->identifier;
			sub_chunk.F.id_len = (uint16_t)strlen(sub->context->id);
			sub_chunk.F.topic_len = (uint16_t)strlen(thistopic);
			sub_chunk.F.qos = (uint8_t)sub->qos;
			sub_chunk.F.options = (uint8_t)(sub->no_local<<2 | sub->retain_as_published<<3);
			sub_chunk.client_id = sub->context->id;
			sub_chunk.topic = thistopic;

			rc = persist__chunk_sub_write_v6(db_fptr, &sub_chunk);
			if(rc){
				mosquitto__free(thistopic);
				return rc;
			}
		}
		sub = sub->next;
	}

	HASH_ITER(hh, node->children, subhier, subhier_tmp){
		persist__subs_save(db_fptr, subhier, thistopic, level+1);
	}
	mosquitto__free(thistopic);
	return MOSQ_ERR_SUCCESS;
}

static int persist__subs_save_all(FILE *db_fptr)
{
	struct mosquitto__subhier *subhier, *subhier_tmp;

	HASH_ITER(hh, db.subs, subhier, subhier_tmp){
		if(subhier->children){
			persist__subs_save(db_fptr, subhier->children, "", 0);
		}
	}

	return MOSQ_ERR_SUCCESS;
}

static int persist__retain_save(FILE *db_fptr, struct mosquitto__retainhier *node, int level)
{
	struct mosquitto__retainhier *retainhier, *retainhier_tmp;
	struct P_retain retain_chunk;
	int rc;

	memset(&retain_chunk, 0, sizeof(struct P_retain));

	if(node->retained && strncmp(node->retained->topic, "$SYS", 4)){
		/* Don't save $SYS messages. */
		retain_chunk.F.store_id = node->retained->db_id;
		rc = persist__chunk_retain_write_v6(db_fptr, &retain_chunk);
		if(rc){
			return rc;
		}
	}

	HASH_ITER(hh, node->children, retainhier, retainhier_tmp){
		persist__retain_save(db_fptr, retainhier, level+1);
	}
	return MOSQ_ERR_SUCCESS;
}

static int persist__retain_save_all(FILE *db_fptr)
{
	struct mosquitto__retainhier *retainhier, *retainhier_tmp;

	HASH_ITER(hh, db.retains, retainhier, retainhier_tmp){
		if(retainhier->children){
			persist__retain_save(db_fptr, retainhier->children, 0);
		}
	}
	
	return MOSQ_ERR_SUCCESS;
}

int persist__backup(bool shutdown)
{
	int rc = 0;
	FILE *db_fptr = NULL;
	uint32_t db_version_w = htonl(MOSQ_DB_VERSION);
	uint32_t crc = 0;
	char *err;
	char *outfile = NULL;
	size_t len;
	struct PF_cfg cfg_chunk;

	if(db.config == NULL) return MOSQ_ERR_INVAL;
	if(db.config->persistence == false) return MOSQ_ERR_SUCCESS;
	if(db.config->persistence_filepath == NULL) return MOSQ_ERR_INVAL;

	log__printf(NULL, MOSQ_LOG_INFO, "Saving in-memory database to %s.", db.config->persistence_filepath);

	len = strlen(db.config->persistence_filepath)+5;
	outfile = mosquitto__malloc(len+1);
	if(!outfile){
		log__printf(NULL, MOSQ_LOG_INFO, "Error saving in-memory database, out of memory.");
		return MOSQ_ERR_NOMEM;
	}
	snprintf(outfile, len, "%s.new", db.config->persistence_filepath);
	outfile[len] = '\0';

#ifndef WIN32
	/**
 	*
	* If a system lost power during the rename operation at the
	* end of this file the filesystem could potentially be left
	* with a directory that looks like this after powerup:
	*
	* 24094 -rw-r--r--    2 root     root          4099 May 30 16:27 mosquitto.db
	* 24094 -rw-r--r--    2 root     root          4099 May 30 16:27 mosquitto.db.new
	*
	* The 24094 shows that mosquitto.db.new is hard-linked to the
	* same file as mosquitto.db.  If fopen(outfile, "wb") is naively
	* called then mosquitto.db will be truncated and the database
	* potentially corrupted.
	*
	* Any existing mosquitto.db.new file must be removed prior to
	* opening to guarantee that it is not hard-linked to
	* mosquitto.db.
	*
	*/
	rc = unlink(outfile);
	if (rc != 0) {
		rc = 0;
		if (errno != ENOENT) {
			log__printf(NULL, MOSQ_LOG_INFO, "Error saving in-memory database, unable to remove %s.", outfile);
			goto error;
		}
	}
#endif

	db_fptr = mosquitto__fopen(outfile, "wb", true);
	if(db_fptr == NULL){
		log__printf(NULL, MOSQ_LOG_INFO, "Error saving in-memory database, unable to open %s for writing.", outfile);
		goto error;
	}

	/* Header */
	write_e(db_fptr, magic, 15);
	write_e(db_fptr, &crc, sizeof(uint32_t));
	write_e(db_fptr, &db_version_w, sizeof(uint32_t));

	memset(&cfg_chunk, 0, sizeof(struct PF_cfg));
	cfg_chunk.last_db_id = db.last_db_id;
	cfg_chunk.shutdown = shutdown;
	cfg_chunk.dbid_size = sizeof(dbid_t);
	if(persist__chunk_cfg_write_v6(db_fptr, &cfg_chunk)){
		goto error;
	}

	if(persist__message_store_save(db_fptr)){
		goto error;
	}

	persist__client_save(db_fptr);
	persist__subs_save_all(db_fptr);
	persist__retain_save_all(db_fptr);

#ifndef WIN32
	/**
	*
	* Closing a file does not guarantee that the contents are
	* written to disk.  Need to flush to send data from app to OS
	* buffers, then fsync to deliver data from OS buffers to disk
	* (as well as disk hardware permits).
	* 
	* man close (http://linux.die.net/man/2/close, 2016-06-20):
	* 
	*   "successful close does not guarantee that the data has
	*   been successfully saved to disk, as the kernel defers
	*   writes.  It is not common for a filesystem to flush
	*   the  buffers  when  the stream is closed.  If you need
	*   to be sure that the data is physically stored, use
	*   fsync(2).  (It will depend on the disk hardware at this
	*   point."
	*
	* This guarantees that the new state file will not overwrite
	* the old state file before its contents are valid.
	*
	*/

	fflush(db_fptr);
	fsync(fileno(db_fptr));
#endif
	fclose(db_fptr);

#ifdef WIN32
	if(remove(db.config->persistence_filepath) != 0){
		if(errno != ENOENT){
			goto error;
		}
	}
#endif
	if(rename(outfile, db.config->persistence_filepath) != 0){
		goto error;
	}
	mosquitto__free(outfile);
	outfile = NULL;
	return rc;
error:
	mosquitto__free(outfile);
	err = strerror(errno);
	log__printf(NULL, MOSQ_LOG_ERR, "Error: %s.", err);
	if(db_fptr) fclose(db_fptr);
	return 1;
}


#endif
