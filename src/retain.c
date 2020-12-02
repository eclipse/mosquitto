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
		mosquitto__free(child);
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

	retainhier = retain__add_hier_entry(NULL, &db.retains, "", (int)strlen(""));
	if(!retainhier) return MOSQ_ERR_NOMEM;

	retainhier = retain__add_hier_entry(NULL, &db.retains, "$SYS", (int)strlen("$SYS"));
	if(!retainhier) return MOSQ_ERR_NOMEM;

	return MOSQ_ERR_SUCCESS;
}


int retain__store(const char *topic, struct mosquitto_msg_store *stored, char **split_topics)
{
	struct mosquitto__retainhier *retainhier;
	struct mosquitto__retainhier *branch;
	int i;
	size_t slen;

	assert(stored);
	assert(split_topics);

	HASH_FIND(hh, db.retains, split_topics[0], strlen(split_topics[0]), retainhier);
	if(retainhier == NULL) return MOSQ_ERR_NOT_FOUND;

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
#endif
	if(retainhier->retained){
		db__msg_store_ref_dec(&retainhier->retained);
#ifdef WITH_SYS_TREE
		db.retained_count--;
#endif
	}
	if(stored->payloadlen){
		retainhier->retained = stored;
		db__msg_store_ref_inc(retainhier->retained);
#ifdef WITH_SYS_TREE
		db.retained_count++;
#endif
	}else{
		retainhier->retained = NULL;
	}

	return MOSQ_ERR_SUCCESS;
}


static int retain__process(struct mosquitto__retainhier *branch, struct mosquitto *context, uint8_t sub_qos, uint32_t subscription_identifier)
{
	int rc = 0;
	uint8_t qos;
	uint16_t mid;
	mosquitto_property *properties = NULL;
	struct mosquitto_msg_store *retained;

	if(branch->retained->message_expiry_time > 0 && db.now_real_s >= branch->retained->message_expiry_time){
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
	if(subscription_identifier > 0){
		mosquitto_property_add_varint(&properties, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, subscription_identifier);
	}
	return db__message_insert(context, mid, mosq_md_out, qos, true, retained, properties, false);
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

	rc = sub__topic_tokenise(sub, &local_sub, &split_topics, NULL);
	if(rc) return rc;

	HASH_FIND(hh, db.retains, split_topics[0], strlen(split_topics[0]), retainhier);

	if(retainhier){
		retain__search(retainhier, split_topics, context, sub, sub_qos, subscription_identifier, 0);
	}
	mosquitto__free(local_sub);
	mosquitto__free(split_topics);

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
		mosquitto__free(peer->topic);

		HASH_DELETE(hh, *retainhier, peer);
		mosquitto__free(peer);
	}
}

