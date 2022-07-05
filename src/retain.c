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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "util_mosq.h"

#include "utlist.h"

static struct mosquitto__retainhier *retain__add_hier_entry(struct mosquitto__retainhier *parent, struct mosquitto__retainhier **sibling, const char *topic, uint16_t len)
{
	struct mosquitto__retainhier *child;

	assert(sibling);

	child = mosquitto__calloc(1, sizeof(struct mosquitto__retainhier));
	if(!child){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return NULL;
	}
	child->parent = parent;
	child->topic_len = len;
	child->topic = mosquitto__malloc((size_t)len+1);
	if(!child->topic){
		child->topic_len = 0;
		mosquitto__FREE(child);
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return NULL;
	}else{
		strncpy(child->topic, topic, (size_t)child->topic_len+1);
	}

	HASH_ADD_KEYPTR(hh, *sibling, child->topic, child->topic_len, child);

	return child;
}


int retain__init(void)
{
	struct mosquitto__retainhier *retainhier;

	retainhier = retain__add_hier_entry(NULL, &db.retains, "", 0);
	if(!retainhier) return MOSQ_ERR_NOMEM;

	retainhier = retain__add_hier_entry(NULL, &db.retains, "$SYS", (uint16_t)strlen("$SYS"));
	if(!retainhier) return MOSQ_ERR_NOMEM;

	return MOSQ_ERR_SUCCESS;
}

BROKER_EXPORT int mosquitto_persist_retain_msg_set(const char *topic, uint64_t base_msg_id)
{
	struct mosquitto_base_msg *base_msg;
	int rc = MOSQ_ERR_UNKNOWN;
	char **split_topics = NULL;
	char *local_topic = NULL;

	if(topic == NULL) return MOSQ_ERR_INVAL;

	HASH_FIND(hh, db.msg_store, &base_msg_id, sizeof(base_msg_id), base_msg);
	if(base_msg){
		if(sub__topic_tokenise(topic, &local_topic, &split_topics, NULL)) return MOSQ_ERR_NOMEM;

		rc = retain__store(topic, base_msg, split_topics, false);
		mosquitto__free(split_topics);
		mosquitto__free(local_topic);
	}

	return rc;
}



BROKER_EXPORT int mosquitto_persist_retain_msg_delete(const char *topic)
{
	struct mosquitto_base_msg base_msg;
	int rc = MOSQ_ERR_UNKNOWN;
	char **split_topics = NULL;
	char *local_topic = NULL;

	if(topic == NULL) return MOSQ_ERR_INVAL;

	memset(&base_msg, 0, sizeof(base_msg));
	base_msg.ref_count = 10; /* Ensure this isn't freed */

	if(sub__topic_tokenise(topic, &local_topic, &split_topics, NULL)) return MOSQ_ERR_NOMEM;

	/* With stored->payloadlen == 0, this means the message will be removed */
	rc = retain__store(topic, &base_msg, split_topics, false);
	mosquitto__FREE(split_topics);
	mosquitto__FREE(local_topic);

	return rc;
}



int retain__store(const char *topic, struct mosquitto_base_msg *base_msg, char **split_topics, bool persist)
{
	struct mosquitto__retainhier *retainhier;
	struct mosquitto__retainhier *branch;
	int i;
	size_t slen;

	assert(base_msg);
	assert(split_topics);

	HASH_FIND(hh, db.retains, split_topics[0], strlen(split_topics[0]), retainhier);
	if(retainhier == NULL){
		retainhier = retain__add_hier_entry(NULL, &db.retains, split_topics[0], (uint16_t)strlen(split_topics[0]));
		if(!retainhier) return MOSQ_ERR_NOMEM;
	}

	for(i=0; split_topics[i] != NULL; i++){
		slen = strlen(split_topics[i]);
		HASH_FIND(hh, retainhier->children, split_topics[i], slen, branch);
		if(branch == NULL){
			branch = retain__add_hier_entry(retainhier, &retainhier->children, split_topics[i], (uint16_t)slen);
			if(branch == NULL){
				return MOSQ_ERR_NOMEM;
			}
		}
		retainhier = branch;
	}

#ifdef WITH_PERSISTENCE
	if(strncmp(topic, "$SYS", 4)){
		/* Retained messages count as a persistence change, but only if
		 * they aren't for $SYS. */
		db.persistence_changes++;
	}
#else
	UNUSED(topic);
#endif

	if(retainhier->retained){
		if(persist && retainhier->retained->topic[0] != '$' && base_msg->payloadlen == 0){
			/* Only delete if another retained message isn't replacing this one */
			plugin_persist__queue_retain_event(retainhier->retained, MOSQ_EVT_PERSIST_RETAIN_MSG_DELETE);
		}
		db__msg_store_ref_dec(&retainhier->retained);
#ifdef WITH_SYS_TREE
		db.retained_count--;
#endif
		if(base_msg->payloadlen == 0){
			retainhier->retained = NULL;
		}
	}
	if(base_msg->payloadlen){
		retainhier->retained = base_msg;
		db__msg_store_ref_inc(retainhier->retained);
		if(persist && retainhier->retained->topic[0] != '$'){
			plugin_persist__queue_retain_event(retainhier->retained, MOSQ_EVT_PERSIST_RETAIN_MSG_SET);
		}
#ifdef WITH_SYS_TREE
		db.retained_count++;
#endif
	}

	return MOSQ_ERR_SUCCESS;
}


static int retain__process(struct mosquitto__retainhier *branch, struct mosquitto *context, uint8_t sub_qos, uint32_t subscription_identifier)
{
	int rc = 0;
	uint8_t qos;
	uint16_t mid;
	struct mosquitto_base_msg *retained;

	if(branch->retained->message_expiry_time > 0 && db.now_real_s >= branch->retained->message_expiry_time){
		plugin_persist__handle_retain_msg_delete(branch->retained);
		db__msg_store_ref_dec(&branch->retained);
		branch->retained = NULL;
#ifdef WITH_SYS_TREE
		db.retained_count--;
#endif
		return MOSQ_ERR_SUCCESS;
	}

	retained = branch->retained;

	rc = mosquitto_acl_check(context, retained->topic, retained->payloadlen, retained->payload,
			retained->qos, retained->retain, MOSQ_ACL_READ);
	if(rc == MOSQ_ERR_ACL_DENIED){
		return MOSQ_ERR_SUCCESS;
	}else if(rc != MOSQ_ERR_SUCCESS){
		return rc;
	}

	/* Check for original source access */
	if(db.config->check_retain_source && retained->origin != mosq_mo_broker && retained->source_id){
		struct mosquitto retain_ctxt;
		memset(&retain_ctxt, 0, sizeof(struct mosquitto));

		retain_ctxt.id = retained->source_id;
		retain_ctxt.username = retained->source_username;
		retain_ctxt.listener = retained->source_listener;

		rc = acl__find_acls(&retain_ctxt);
		if(rc) return rc;

		rc = mosquitto_acl_check(&retain_ctxt, retained->topic, retained->payloadlen, retained->payload,
				retained->qos, retained->retain, MOSQ_ACL_WRITE);
		if(rc == MOSQ_ERR_ACL_DENIED){
			return MOSQ_ERR_SUCCESS;
		}else if(rc != MOSQ_ERR_SUCCESS){
			return rc;
		}
	}

	if (db.config->upgrade_outgoing_qos){
		qos = sub_qos;
	} else {
		qos = retained->qos;
		if(qos > sub_qos) qos = sub_qos;
	}
	if(qos > 0){
		mid = mosquitto__mid_generate(context);
	}else{
		mid = 0;
	}
	return db__message_insert_outgoing(context, 0, mid, qos, true, retained, subscription_identifier, false, true);
}


static int retain__search(struct mosquitto__retainhier *retainhier, char **split_topics, struct mosquitto *context, const char *sub, uint8_t sub_qos, uint32_t subscription_identifier, int level)
{
	struct mosquitto__retainhier *branch, *branch_tmp;
	int flag = 0;

	if(!strcmp(split_topics[0], "#") && split_topics[1] == NULL){
		HASH_ITER(hh, retainhier->children, branch, branch_tmp){
			/* Set flag to indicate that we should check for retained messages
			 * on "foo" when we are subscribing to e.g. "foo/#" and then exit
			 * this function and return to an earlier retain__search().
			 */
			flag = -1;
			if(branch->retained){
				retain__process(branch, context, sub_qos, subscription_identifier);
			}
			if(branch->children){
				retain__search(branch, split_topics, context, sub, sub_qos, subscription_identifier, level+1);
			}
		}
	}else{
		if(!strcmp(split_topics[0], "+")){
			HASH_ITER(hh, retainhier->children, branch, branch_tmp){
				if(split_topics[1] != NULL){
					if(retain__search(branch, &(split_topics[1]), context, sub, sub_qos, subscription_identifier, level+1) == -1
							|| (split_topics[1] != NULL && !strcmp(split_topics[1], "#") && level>0)){

						if(branch->retained){
							retain__process(branch, context, sub_qos, subscription_identifier);
						}
					}
				}else{
					if(branch->retained){
						retain__process(branch, context, sub_qos, subscription_identifier);
					}
				}
			}
		}else{
			HASH_FIND(hh, retainhier->children, split_topics[0], strlen(split_topics[0]), branch);
			if(branch){
				if(split_topics[1] != NULL){
					if(retain__search(branch, &(split_topics[1]), context, sub, sub_qos, subscription_identifier, level+1) == -1
							|| (split_topics[1] != NULL && !strcmp(split_topics[1], "#") && level>0)){

						if(branch->retained){
							retain__process(branch, context, sub_qos, subscription_identifier);
						}
					}
				}else{
					if(branch->retained){
						retain__process(branch, context, sub_qos, subscription_identifier);
					}
				}
			}
		}
	}
	return flag;
}


int retain__queue(struct mosquitto *context, const char *sub, uint8_t sub_qos, uint32_t subscription_identifier)
{
	struct mosquitto__retainhier *retainhier;
	char *local_sub;
	char **split_topics;
	int rc;

	assert(context);
	assert(sub);

	if(!strncmp(sub, "$share/", strlen("$share/"))){
		return MOSQ_ERR_SUCCESS;
	}

	rc = sub__topic_tokenise(sub, &local_sub, &split_topics, NULL);
	if(rc) return rc;

	HASH_FIND(hh, db.retains, split_topics[0], strlen(split_topics[0]), retainhier);

	if(retainhier){
		retain__search(retainhier, split_topics, context, sub, sub_qos, subscription_identifier, 0);
	}
	mosquitto__FREE(local_sub);
	mosquitto__FREE(split_topics);

	return MOSQ_ERR_SUCCESS;
}


void retain__clean(struct mosquitto__retainhier **retainhier)
{
	struct mosquitto__retainhier *peer, *retainhier_tmp;

	HASH_ITER(hh, *retainhier, peer, retainhier_tmp){
		if(peer->retained){
			db__msg_store_ref_dec(&peer->retained);
		}
		retain__clean(&peer->children);
		mosquitto__FREE(peer->topic);

		HASH_DELETE(hh, *retainhier, peer);
		mosquitto__FREE(peer);
	}
}

static int buffer_add_msg(struct mosquitto_base_msg *retained, struct mosquitto_message **buffer, size_t buffer_size, int *index)
{

	if (*index >= buffer_size)
	{
		log__printf(NULL, MOSQ_LOG_ERR, "buffer_add_msg(): overflow index: %d, buffer_size: %d", *index, buffer_size);
		return -1;
	}

	if (buffer[*index] == NULL)
	{
		return MOSQ_ERR_NOMEM;
	}
	struct mosquitto_message *msg = buffer[*index];
	(*msg).mid = 0;
	(*msg).payload = retained->payload;			   // does this need to be copied?
	(*msg).payloadlen = (int)retained->payloadlen; // cast could be bad if payloadlen is big
	(*msg).qos = 0;
	(*msg).topic = retained->topic;
	(*msg).retain = true;

	struct mosquitto_message message = *buffer[*index];

	*index = *index + 1;
	return 0;
}

static int retain__search2(struct mosquitto__retainhier *retainhier, char **split_topics, const char *sub, struct mosquitto_message *const *buffer, size_t buffer_size, int level,
						   int *index)
{
	struct mosquitto__retainhier *branch, *branch_tmp;
	int flag = 0;

	if (!strcmp(split_topics[0], "#") && split_topics[1] == NULL)
	{
		HASH_ITER(hh, retainhier->children, branch, branch_tmp)
		{
			/* Set flag to indicate that we should check for retained messages
			 * on "foo" when we are subscribing to e.g. "foo/#" and then exit
			 * this function and return to an earlier retain__search().
			 */
			flag = -1;
			if (branch->retained)
			{
				int rc = buffer_add_msg(branch->retained, buffer, buffer_size, index);
				if (rc == MOSQ_ERR_BUFFER_FULL)
				{
					return rc;
				}
			}

			if (branch->children)
			{
				int rc = retain__search2(branch, split_topics, sub, buffer, buffer_size, level + 1, index);
				if (rc == MOSQ_ERR_BUFFER_FULL)
				{
					return rc;
				}
			}
		}
	}
	else
	{
		if (!strcmp(split_topics[0], "+"))
		{
			HASH_ITER(hh, retainhier->children, branch, branch_tmp)
			{
				if (split_topics[1] != NULL)
				{
					int rc = retain__search2(branch, &(split_topics[1]), sub, buffer, buffer_size, level + 1, index);
					if (rc == -1 || (split_topics[1] != NULL && !strcmp(split_topics[1], "#") && level > 0))
					{

						if (branch->retained)
						{

							int rc = buffer_add_msg(branch->retained, buffer, buffer_size, index);
							if (rc == MOSQ_ERR_BUFFER_FULL)
							{
								return rc;
							}
						}
					}
					else if (rc == MOSQ_ERR_BUFFER_FULL)
					{
						return rc;
					}
				}
				else
				{
					if (branch->retained)
					{

						int rc = buffer_add_msg(branch->retained, buffer, buffer_size, index);
						if (rc == MOSQ_ERR_BUFFER_FULL)
						{
							return rc;
						}
					}
				}
			}
		}
		else
		{
			HASH_FIND(hh, retainhier->children, split_topics[0], strlen(split_topics[0]), branch);
			if (branch)
			{
				if (split_topics[1] != NULL)
				{
					if (retain__search2(branch, &(split_topics[1]), sub, buffer, buffer_size, level + 1, index) == -1 || (split_topics[1] != NULL && !strcmp(split_topics[1], "#") && level > 0))
					{

						if (branch->retained)
						{
							int rc = buffer_add_msg(branch->retained, buffer, buffer_size, index);
							if (rc == MOSQ_ERR_BUFFER_FULL)
							{
								return rc;
							}
						}
					}
				}
				else
				{
					if (branch->retained)
					{
						int rc = buffer_add_msg(branch->retained, buffer, buffer_size, index);
						if (rc == MOSQ_ERR_BUFFER_FULL)
						{
							return rc;
						}
					}
				}
			}
		}
	}
	return flag;
}

libmosq_EXPORT int mosquitto_get_retained(const char *sub, struct mosquitto_message *const *buffer, size_t *buffer_size, size_t *messages_found)
{
	struct mosquitto__retainhier *retainhier = db.retains;
	char *local_sub;
	char **split_topics;
	int rc;

	assert(sub);
	rc = sub__topic_tokenise(sub, &local_sub, &split_topics, NULL);
	if (rc)
		return rc;

	HASH_FIND(hh, db.retains, split_topics[0], strlen(split_topics[0]), retainhier);
	int *index = mosquitto_malloc(sizeof(int));
	if(index == NULL){
		return MOSQ_ERR_NOMEM;
	}

	*index = 0;
	rc = MOSQ_ERR_SUCCESS;
	if (retainhier)
	{
		if (retain__search2(retainhier, split_topics, sub, buffer, *buffer_size, 0, index) == MOSQ_ERR_BUFFER_FULL) {
			rc = MOSQ_ERR_BUFFER_FULL;
		};
	}

	// set number of elements found for caller
	*messages_found = *index;

	mosquitto_free(index);
	return rc;
}
