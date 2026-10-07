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
#include "mosquitto/mqtt_protocol.h"
#include "util_mosq.h"

#include "utlist.h"

static time_t next_expire_check = 0;

static struct mosquitto__retainhier *retain__add_hier_entry(struct mosquitto__retainhier *parent, struct mosquitto__retainhier **sibling, const char *topic, uint16_t len)
{
	struct mosquitto__retainhier *child;

	assert(sibling);

	child = mosquitto_calloc(1, sizeof(struct mosquitto__retainhier) + len + 1);
	if(!child){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return NULL;
	}
	child->parent = parent;
	child->topic_len = len;
	if(len > 0){
		strncpy(child->topic, topic, (size_t)(len+1));
	}

	HASH_ADD(hh, *sibling, topic, child->topic_len, child);

	return child;
}


int retain__init(void)
{
	struct mosquitto__retainhier *retainhier;

	retainhier = retain__add_hier_entry(NULL, &db.retains, "", 0);
	if(!retainhier){
		return MOSQ_ERR_NOMEM;
	}

	retainhier = retain__add_hier_entry(NULL, &db.retains, "$SYS", (uint16_t)strlen("$SYS"));
	if(!retainhier){
		return MOSQ_ERR_NOMEM;
	}

	return MOSQ_ERR_SUCCESS;
}


BROKER_EXPORT int mosquitto_persist_retain_msg_set(const char *topic, uint64_t base_msg_id)
{
	struct mosquitto__base_msg *base_msg;
	int rc = MOSQ_ERR_UNKNOWN;
	char **split_topics = NULL;
	char *local_topic = NULL;

	if(topic == NULL){
		return MOSQ_ERR_INVAL;
	}

	HASH_FIND(hh, db.msg_store, &base_msg_id, sizeof(base_msg_id), base_msg);
	if(base_msg){
		if(sub__topic_tokenise(topic, &local_topic, &split_topics, NULL)){
			return MOSQ_ERR_NOMEM;
		}

		rc = retain__store(topic, base_msg, split_topics, false);
		mosquitto_free(split_topics);
		mosquitto_free(local_topic);
	}

	return rc;
}


BROKER_EXPORT int mosquitto_persist_retain_msg_delete(const char *topic)
{
	struct mosquitto__base_msg base_msg;
	int rc = MOSQ_ERR_UNKNOWN;
	char **split_topics = NULL;
	char *local_topic = NULL;

	if(topic == NULL){
		return MOSQ_ERR_INVAL;
	}

	memset(&base_msg, 0, sizeof(base_msg));
	base_msg.ref_count = 10; /* Ensure this isn't freed */

	if(sub__topic_tokenise(topic, &local_topic, &split_topics, NULL)){
		return MOSQ_ERR_NOMEM;
	}

	/* With stored->payloadlen == 0, this means the message will be removed */
	rc = retain__store(topic, &base_msg, split_topics, false);
	mosquitto_FREE(split_topics);
	mosquitto_FREE(local_topic);

	return rc;
}


void retain__clean_empty_hierarchy(struct mosquitto__retainhier *retainhier)
{
	while(retainhier){
		if(retainhier->children || retainhier->retained || retainhier->parent == NULL){
			/* Entry is being used */
			return;
		}else{
			HASH_DELETE(hh, retainhier->parent->children, retainhier);

			struct mosquitto__retainhier *parent = retainhier->parent;
			mosquitto_FREE(retainhier);
			retainhier = parent;
		}
	}
}


int retain__store(const char *topic, struct mosquitto__base_msg *base_msg, char **split_topics, bool persist)
{
	struct mosquitto__retainhier *retainhier;
	struct mosquitto__retainhier *branch;
	size_t slen;

	assert(base_msg);
	assert(split_topics);

	HASH_FIND(hh, db.retains, split_topics[0], strlen(split_topics[0]), retainhier);
	if(retainhier == NULL){
		retainhier = retain__add_hier_entry(NULL, &db.retains, split_topics[0], (uint16_t)strlen(split_topics[0]));
		if(!retainhier){
			return MOSQ_ERR_NOMEM;
		}
	}

	for(int i=0; split_topics[i] != NULL; i++){
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
		if(retainhier->retained == base_msg){
			/* This may occur if multiple persistence providers are used */
			return MOSQ_ERR_SUCCESS;
		}

		if(persist && retainhier->retained->data.topic[0] != '$' && base_msg->data.payloadlen == 0){
			/* Only delete if another retained message isn't replacing this one */
			plugin_persist__handle_retain_msg_delete(retainhier->retained);
		}
		db__msg_store_ref_dec(&retainhier->retained);
#ifdef WITH_SYS_TREE
		db.retained_count--;
#endif
		if(base_msg->data.payloadlen == 0){
			retainhier->retained = NULL;
			retain__clean_empty_hierarchy(retainhier);
		}
	}
	if(base_msg->data.payloadlen){
		retainhier->retained = base_msg;
		db__msg_store_ref_inc(retainhier->retained);
		if(persist && retainhier->retained->data.topic[0] != '$'){
			plugin_persist__handle_base_msg_add(retainhier->retained);
			plugin_persist__handle_retain_msg_set(retainhier->retained);
		}
#ifdef WITH_SYS_TREE
		db.retained_count++;
#endif
	}

	return MOSQ_ERR_SUCCESS;
}


static bool retain__delete_expired_msg(struct mosquitto__retainhier *branch)
{
	if(branch->retained && branch->retained->data.expiry_time > 0 && db.now_real_s >= branch->retained->data.expiry_time){
		plugin_persist__handle_retain_msg_delete(branch->retained);
		db__msg_store_ref_dec(&branch->retained);
		branch->retained = NULL;
#ifdef WITH_SYS_TREE
		db.retained_count--;
#endif
		return true;
	}
	return false;
}


static int retain__process(struct mosquitto__retainhier *branch, struct mosquitto *context, const struct mosquitto_subscription *sub)
{
	int rc = 0;
	uint8_t qos, sub_qos;
	uint16_t mid;
	struct mosquitto__base_msg *retained;

	if(retain__delete_expired_msg(branch)){
		return MOSQ_ERR_SUCCESS;
	}

	retained = branch->retained;

	rc = mosquitto_acl_check(context, retained->data.topic, retained->data.payloadlen, retained->data.payload,
			retained->data.qos, retained->data.retain, retained->data.properties, MOSQ_ACL_READ);
	if(rc == MOSQ_ERR_ACL_DENIED){
		return MOSQ_ERR_SUCCESS;
	}else if(rc != MOSQ_ERR_SUCCESS){
		return rc;
	}

	/* Check for original source access */
	if(db.config->check_retain_source && retained->origin != mosq_mo_broker && retained->data.source_id){
		struct mosquitto retain_ctxt;
		memset(&retain_ctxt, 0, sizeof(struct mosquitto));

		retain_ctxt.id = retained->data.source_id;
		retain_ctxt.username = retained->data.source_username;
		retain_ctxt.listener = retained->source_listener;

		rc = mosquitto_acl_check(&retain_ctxt, retained->data.topic, retained->data.payloadlen, retained->data.payload,
				retained->data.qos, retained->data.retain, retained->data.properties, MOSQ_ACL_WRITE);
		if(rc == MOSQ_ERR_ACL_DENIED){
			return MOSQ_ERR_SUCCESS;
		}else if(rc != MOSQ_ERR_SUCCESS){
			return rc;
		}
	}

	sub_qos = sub->options & 0x03;
	if(db.config->upgrade_outgoing_qos){
		qos = sub_qos;
	}else{
		qos = retained->data.qos;
		if(qos > sub_qos){
			qos = sub_qos;
		}
	}
	if(qos > 0){
		mid = mosquitto__mid_generate(context);
	}else{
		mid = 0;
	}
	return db__message_insert_outgoing(context, 0, mid, qos, true, retained, sub->identifier, false, true);
}


static int retain__search(struct mosquitto__retainhier *retainhier, char **split_topics, struct mosquitto *context, const struct mosquitto_subscription *sub, int level)
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
				retain__process(branch, context, sub);
			}
			if(branch->children){
				retain__search(branch, split_topics, context, sub, level+1);
			}
		}
	}else{
		if(!strcmp(split_topics[0], "+")){
			HASH_ITER(hh, retainhier->children, branch, branch_tmp){
				if(split_topics[1] != NULL){
					if(retain__search(branch, &(split_topics[1]), context, sub, level+1) == -1
							|| (split_topics[1] != NULL && !strcmp(split_topics[1], "#") && level>0)){

						if(branch->retained){
							retain__process(branch, context, sub);
						}
					}
				}else{
					if(branch->retained){
						retain__process(branch, context, sub);
					}
				}
			}
		}else{
			HASH_FIND(hh, retainhier->children, split_topics[0], strlen(split_topics[0]), branch);
			if(branch){
				if(split_topics[1] != NULL){
					if(retain__search(branch, &(split_topics[1]), context, sub, level+1) == -1
							|| (split_topics[1] != NULL && !strcmp(split_topics[1], "#") && level>0)){

						if(branch->retained){
							retain__process(branch, context, sub);
						}
					}
				}else{
					if(branch->retained){
						retain__process(branch, context, sub);
					}
				}
			}
		}
	}
	return flag;
}


int retain__queue(struct mosquitto *context, const struct mosquitto_subscription *sub)
{
	struct mosquitto__retainhier *retainhier;
	char *local_sub;
	char **split_topics;
	int rc;

	assert(context);
	assert(sub);

	if(!strncmp(sub->topic_filter, "$share/", strlen("$share/"))){
		return MOSQ_ERR_SUCCESS;
	}

	rc = sub__topic_tokenise(sub->topic_filter, &local_sub, &split_topics, NULL);
	if(rc){
		return rc;
	}

	HASH_FIND(hh, db.retains, split_topics[0], strlen(split_topics[0]), retainhier);

	if(retainhier){
		retain__search(retainhier, split_topics, context, sub, 0);
	}
	mosquitto_FREE(local_sub);
	mosquitto_FREE(split_topics);

	return MOSQ_ERR_SUCCESS;
}


void retain__expire(struct mosquitto__retainhier **retainhier)
{
	struct mosquitto__retainhier *peer, *retainhier_tmp;

	HASH_ITER(hh, *retainhier, peer, retainhier_tmp){
		retain__expire(&peer->children);

		struct mosquitto__retainhier *parent = peer->parent;
		if(retain__delete_expired_msg(peer)){
			retain__clean_empty_hierarchy(parent);
		}
	}
}


void retain__clean(struct mosquitto__retainhier **retainhier)
{
	struct mosquitto__retainhier *peer, *retainhier_tmp;

	HASH_ITER(hh, *retainhier, peer, retainhier_tmp){
		if(peer->retained){
			db__msg_store_ref_dec(&peer->retained);
		}
		retain__clean(&peer->children);

		HASH_DELETE(hh, *retainhier, peer);
		mosquitto_FREE(peer);
	}
}


void retain__expiry_check(void)
{
	if(db.config->retain_expiry_interval > 0 && db.now_s > next_expire_check){
		retain__expire(&db.retains);
		next_expire_check = db.now_s + db.config->retain_expiry_interval;
	}
}
