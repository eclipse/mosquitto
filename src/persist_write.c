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
		if(!strncmp(cmsg->base_msg->topic, "$SYS", 4)
				&& cmsg->base_msg->ref_count <= 1
				&& cmsg->base_msg->dest_id_count == 0){

			/* This $SYS message won't have been persisted, so we can't persist
			 * this client message. */
			cmsg = cmsg->next;
			continue;
		}

		chunk.F.store_id = cmsg->base_msg->db_id;
		chunk.F.mid = cmsg->mid;
		chunk.F.id_len = (uint16_t)strlen(context->id);
		chunk.F.qos = cmsg->qos;
		chunk.F.retain_dup = (uint8_t)((cmsg->retain&0x0F)<<4 | (cmsg->dup&0x0F));
		chunk.F.direction = (uint8_t)cmsg->direction;
		chunk.F.state = (uint8_t)cmsg->state;
		chunk.client_id = context->id;
		chunk.subscription_identifier = cmsg->subscription_identifier;

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
	struct P_base_msg chunk;
	struct mosquitto_base_msg *base_msg, *base_msg_tmp;
	int rc;

	assert(db_fptr);

	memset(&chunk, 0, sizeof(struct P_base_msg));

	base_msg = db.msg_store;
	HASH_ITER(hh, db.msg_store, base_msg, base_msg_tmp){
		if(base_msg->ref_count < 1 || base_msg->topic == NULL){
			continue;
		}

		if(!strncmp(base_msg->topic, "$SYS", 4)){
			if(base_msg->ref_count <= 1 && base_msg->dest_id_count == 0){
				/* $SYS messages that are only retained shouldn't be persisted. */
				continue;
			}
			/* Don't save $SYS messages as retained otherwise they can give
			 * misleading information when reloaded. They should still be saved
			 * because a disconnected durable client may have them in their
			 * queue. */
			chunk.F.retain = 0;
		}else{
			chunk.F.retain = (uint8_t)base_msg->retain;
		}

		chunk.F.store_id = base_msg->db_id;
		chunk.F.expiry_time = base_msg->message_expiry_time;
		chunk.F.payloadlen = base_msg->payloadlen;
		chunk.F.source_mid = base_msg->source_mid;
		if(base_msg->source_id){
			chunk.F.source_id_len = (uint16_t)strlen(base_msg->source_id);
			chunk.source.id = base_msg->source_id;
		}else{
			chunk.F.source_id_len = 0;
			chunk.source.id = NULL;
		}
		if(base_msg->source_username){
			chunk.F.source_username_len = (uint16_t)strlen(base_msg->source_username);
			chunk.source.username = base_msg->source_username;
		}else{
			chunk.F.source_username_len = 0;
			chunk.source.username = NULL;
		}

		chunk.F.topic_len = (uint16_t)strlen(base_msg->topic);
		chunk.topic = base_msg->topic;

		if(base_msg->source_listener){
			chunk.F.source_port = base_msg->source_listener->port;
		}else{
			chunk.F.source_port = 0;
		}
		chunk.F.qos = base_msg->qos;
		chunk.payload = base_msg->payload;
		chunk.properties = base_msg->properties;

		rc = persist__chunk_message_store_write_v6(db_fptr, &chunk);
		if(rc){
			return rc;
		}
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
		if(context && (context->clean_start == false
#ifdef WITH_BRIDGE
				|| (context->bridge && context->bridge->clean_start_local == false)
#endif
				)){
			chunk.F.session_expiry_time = context->session_expiry_time;
			if(context->session_expiry_interval != 0 && context->session_expiry_interval != UINT32_MAX && context->session_expiry_time == 0){
				chunk.F.session_expiry_time = context->session_expiry_interval + db.now_real_s;
			}else{
				chunk.F.session_expiry_time = context->session_expiry_time;
			}
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
				mosquitto__FREE(thistopic);
				return rc;
			}
		}
		sub = sub->next;
	}

	HASH_ITER(hh, node->children, subhier, subhier_tmp){
		persist__subs_save(db_fptr, subhier, thistopic, level+1);
	}
	mosquitto__FREE(thistopic);
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

static int persist__write_data(FILE* db_fptr, void* user_data);

static void persist__log_write_error(const char* msg)
{
	log__printf(NULL, MOSQ_LOG_ERR, "Error saving in-memory database, %s", msg);
}

int persist__backup(bool shutdown)
{
	if(db.config == NULL) return MOSQ_ERR_INVAL;
	if(db.config->persistence == false) return MOSQ_ERR_SUCCESS;
	if(db.config->persistence_filepath == NULL) return MOSQ_ERR_INVAL;

	log__printf(NULL, MOSQ_LOG_INFO, "Saving in-memory database to %s.", db.config->persistence_filepath);

	return mosquitto_write_file(db.config->persistence_filepath,true,&persist__write_data,&shutdown,&persist__log_write_error);
}

static int persist__write_data(FILE* db_fptr, void* user_data)
{
	bool shutdown = *(bool*)(user_data);
	uint32_t db_version_w = htonl(MOSQ_DB_VERSION);
	uint32_t crc = 0;
	const char* err;
	struct PF_cfg cfg_chunk;

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

	if (persist__client_save(db_fptr)
			|| persist__subs_save_all(db_fptr)
			|| persist__retain_save_all(db_fptr)){
		goto error;
	}
	return MOSQ_ERR_SUCCESS;

error:
	err = strerror(errno);
	log__printf(NULL, MOSQ_LOG_ERR, "Error during saving in-memory database %s: %s.", db.config->persistence_filepath, err);
	if(db_fptr) fclose(db_fptr);
	return 1;
}


#endif
