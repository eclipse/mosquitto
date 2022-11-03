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

/* A note on matching topic subscriptions.
 *
 * Topics can be up to 32767 characters in length. The / character is used as a
 * hierarchy delimiter. Messages are published to a particular topic.
 * Clients may subscribe to particular topics directly, but may also use
 * wildcards in subscriptions.  The + and # characters are used as wildcards.
 * The # wildcard can be used at the end of a subscription only, and is a
 * wildcard for the level of hierarchy at which it is placed and all subsequent
 * levels.
 * The + wildcard may be used at any point within the subscription and is a
 * wildcard for only the level of hierarchy at which it is placed.
 * Neither wildcard may be used as part of a substring.
 * Valid:
 * 	a/b/+
 * 	a/+/c
 * 	a/#
 * 	a/b/#
 * 	#
 * 	+/b/c
 * 	+/+/+
 * Invalid:
 *	a/#/c
 *	a+/b/c
 * Valid but non-matching:
 *	a/b
 *	a/+
 *	+/b
 *	b/c/a
 *	a/b/d
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

static int subs__send(struct mosquitto__subleaf *leaf, const char *topic, uint8_t qos, int retain, struct mosquitto_base_msg *stored)
{
	bool client_retain;
	uint16_t mid;
	uint8_t client_qos, msg_qos;
	int rc2;

	/* Check for ACL topic access. */
	rc2 = mosquitto_acl_check(leaf->context, topic, stored->payloadlen, stored->payload, stored->qos, stored->retain, MOSQ_ACL_READ);
	if(rc2 == MOSQ_ERR_ACL_DENIED){
		return MOSQ_ERR_SUCCESS;
	}else if(rc2 == MOSQ_ERR_SUCCESS){
		client_qos = leaf->qos;

		if(db.config->upgrade_outgoing_qos){
			msg_qos = client_qos;
		}else{
			if(qos > client_qos){
				msg_qos = client_qos;
			}else{
				msg_qos = qos;
			}
		}
		if(msg_qos){
			mid = mosquitto__mid_generate(leaf->context);
		}else{
			mid = 0;
		}
		if(leaf->retain_as_published){
			client_retain = retain;
		}else{
			client_retain = false;
		}
		if(db__message_insert_outgoing(leaf->context, 0, mid, msg_qos, client_retain, stored, leaf->identifier, true, true) == 1){
			return 1;
		}
	}else{
		return 1; /* Application error */
	}
	return 0;
}


static int subs__shared_process(struct mosquitto__subhier *hier, const char *topic, uint8_t qos, int retain, struct mosquitto_base_msg *stored)
{
	int rc = 0, rc2;
	struct mosquitto__subshared *shared, *shared_tmp;
	struct mosquitto__subleaf *leaf;

	HASH_ITER(hh, hier->shared, shared, shared_tmp){
		leaf = shared->subs;
		rc2 = subs__send(leaf, topic, qos, retain, stored);
		/* Remove current from the top, add back to the bottom */
		DL_DELETE(shared->subs, leaf);
		DL_APPEND(shared->subs, leaf);

		if(rc2) rc = 1;
	}

	return rc;
}

static int subs__process(struct mosquitto__subhier *hier, const char *source_id, const char *topic, uint8_t qos, int retain, struct mosquitto_base_msg *stored)
{
	int rc = 0;
	int rc2;
	struct mosquitto__subleaf *leaf;

	rc = subs__shared_process(hier, topic, qos, retain, stored);

	leaf = hier->subs;
	while(source_id && leaf){
		if(!leaf->context->id || (leaf->no_local && !strcmp(leaf->context->id, source_id))){
			leaf = leaf->next;
			continue;
		}
		rc2 = subs__send(leaf, topic, qos, retain, stored);
		if(rc2){
			rc = 1;
		}
		leaf = leaf->next;
	}
	if(hier->subs || hier->shared){
		return rc;
	}else{
		return MOSQ_ERR_NO_SUBSCRIBERS;
	}
}


static int sub__add_leaf(struct mosquitto *context, const char *topic_filter, uint8_t qos, uint32_t identifier, int options, struct mosquitto__subleaf **head, struct mosquitto__subleaf **newleaf)
{
	struct mosquitto__subleaf *leaf;

	*newleaf = NULL;
	leaf = *head;

	while(leaf){
		if(leaf->context && leaf->context->id && !strcmp(leaf->context->id, context->id)){
			/* Client making a second subscription to same topic. Only
			 * need to update QoS. Return MOSQ_ERR_SUB_EXISTS to
			 * indicate this to the calling function. */
			leaf->qos = qos;
			leaf->identifier = identifier;
			leaf->no_local = ((options & MQTT_SUB_OPT_NO_LOCAL) != 0);
			leaf->retain_as_published = ((options & MQTT_SUB_OPT_RETAIN_AS_PUBLISHED) != 0);
			return MOSQ_ERR_SUB_EXISTS;
		}
		leaf = leaf->next;
	}
	leaf = mosquitto__calloc(1, sizeof(struct mosquitto__subleaf) + strlen(topic_filter) + 1);
	if(!leaf) return MOSQ_ERR_NOMEM;
	leaf->context = context;
	leaf->qos = qos;
	leaf->identifier = identifier;
	leaf->no_local = ((options & MQTT_SUB_OPT_NO_LOCAL) != 0);
	leaf->retain_as_published = ((options & MQTT_SUB_OPT_RETAIN_AS_PUBLISHED) != 0);
	strcpy(leaf->topic_filter, topic_filter);

	DL_APPEND(*head, leaf);
	*newleaf = leaf;

	return MOSQ_ERR_SUCCESS;
}


static void sub__remove_shared_leaf(struct mosquitto__subhier *subhier, struct mosquitto__subshared *shared, struct mosquitto__subleaf *leaf)
{
	DL_DELETE(shared->subs, leaf);
	if(shared->subs == NULL){
		HASH_DELETE(hh, subhier->shared, shared);
		mosquitto__FREE(shared);
	}
}


static int sub__add_shared(struct mosquitto *context, const char *sub, uint8_t qos, uint32_t identifier, int options, struct mosquitto__subhier *subhier, const char *sharename)
{
	struct mosquitto__subleaf *newleaf;
	struct mosquitto__subshared *shared = NULL;
	struct mosquitto__subleaf **subs;
	int i;
	size_t slen;
	int rc;

	slen = strlen(sharename);

	HASH_FIND(hh, subhier->shared, sharename, slen, shared);
	if(shared == NULL){
		shared = mosquitto__calloc(1, sizeof(struct mosquitto__subshared) + slen + 1);
		if(!shared){
			return MOSQ_ERR_NOMEM;
		}
		strncpy(shared->name, sharename, slen+1);

		HASH_ADD(hh, subhier->shared, name, slen, shared);
	}

	rc = sub__add_leaf(context, sub, qos, identifier, options, &shared->subs, &newleaf);
	if(rc > 0){
		if(shared->subs == NULL){
			HASH_DELETE(hh, subhier->shared, shared);
			mosquitto__FREE(shared);
		}
		return rc;
	}

	if(rc != MOSQ_ERR_SUB_EXISTS){
		newleaf->hier = subhier;
		newleaf->shared = shared;

		bool assigned = false;
		for(i=0; i<context->sub_count; i++){
			if(!context->subs[i]){
				context->subs[i] = newleaf;
				assigned = true;
				break;
			}
		}
		if(assigned == false){
			subs = mosquitto__realloc(context->subs, sizeof(struct mosquitto__subleaf *)*(size_t)(context->sub_count + 1));
			if(!subs){
				sub__remove_shared_leaf(subhier, shared, newleaf);
				mosquitto__FREE(newleaf);
				return MOSQ_ERR_NOMEM;
			}
			context->subs = subs;
			context->sub_count++;
			context->subs[context->sub_count-1] = newleaf;
		}
#ifdef WITH_SYS_TREE
		db.shared_subscription_count++;
#endif
	}

	if(context->protocol == mosq_p_mqtt31 || context->protocol == mosq_p_mqtt5){
		return rc;
	}else{
		/* mqttv311/mqttv5 requires retained messages are resent on
		 * resubscribe. */
		return MOSQ_ERR_SUCCESS;
	}
}


static int sub__add_normal(struct mosquitto *context, const char *sub, uint8_t qos, uint32_t identifier, int options, struct mosquitto__subhier *subhier)
{
	struct mosquitto__subleaf *newleaf = NULL;
	struct mosquitto__subleaf **subs;
	int i;
	int rc;

	rc = sub__add_leaf(context, sub, qos, identifier, options, &subhier->subs, &newleaf);
	if(rc > 0){
		return rc;
	}

	if(rc != MOSQ_ERR_SUB_EXISTS){
		newleaf->hier = subhier;
		newleaf->shared = NULL;

		bool assigned = false;
		for(i=0; i<context->sub_count; i++){
			if(!context->subs[i]){
				context->subs[i] = newleaf;
				assigned = true;
				break;
			}
		}
		if(assigned == false){
			subs = mosquitto__realloc(context->subs, sizeof(struct mosquitto__subleaf *)*(size_t)(context->sub_count + 1));
			if(!subs){
				DL_DELETE(subhier->subs, newleaf);
				mosquitto__FREE(newleaf);
				return MOSQ_ERR_NOMEM;
			}
			context->subs = subs;
			context->sub_count++;
			context->subs[context->sub_count-1] = newleaf;
		}
#ifdef WITH_SYS_TREE
		db.subscription_count++;
#endif
	}

	if(context->protocol == mosq_p_mqtt31 || context->protocol == mosq_p_mqtt5){
		return rc;
	}else{
		/* mqttv311/mqttv5 requires retained messages are resent on
		 * resubscribe. */
		return MOSQ_ERR_SUCCESS;
	}
}


static int sub__add_context(struct mosquitto *context, const char *topic_filter, uint8_t qos, uint32_t identifier, int options, struct mosquitto__subhier *subhier, char *const *const topics, const char *sharename)
{
	struct mosquitto__subhier *branch;
	int topic_index = 0;
	size_t topiclen;

	/* Find leaf node */
	while(topics && topics[topic_index] != NULL){
		topiclen = strlen(topics[topic_index]);
		if(topiclen > UINT16_MAX){
			return MOSQ_ERR_INVAL;
		}
		HASH_FIND(hh, subhier->children, topics[topic_index], topiclen, branch);
		if(!branch){
			/* Not found */
			branch = sub__add_hier_entry(subhier, &subhier->children, topics[topic_index], (uint16_t)topiclen);
			if(!branch) return MOSQ_ERR_NOMEM;
		}
		subhier = branch;
		topic_index++;
	}

	/* Add add our context */
	if(context && context->id){
		if(sharename){
			return sub__add_shared(context, topic_filter, qos, identifier, options, subhier, sharename);
		}else{
			return sub__add_normal(context, topic_filter, qos, identifier, options, subhier);
		}
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}


static int sub__remove_normal(struct mosquitto *context, struct mosquitto__subhier *subhier, uint8_t *reason)
{
	struct mosquitto__subleaf *leaf;
	int i;

	leaf = subhier->subs;
	while(leaf){
		if(leaf->context==context){
#ifdef WITH_SYS_TREE
			db.subscription_count--;
#endif
			DL_DELETE(subhier->subs, leaf);

			/* Remove the reference to the sub that the client is keeping.
			 * It would be nice to be able to use the reference directly,
			 * but that would involve keeping a copy of the topic string in
			 * each subleaf. Might be worth considering though. */
			for(i=0; i<context->sub_count; i++){
				if(context->subs[i] == leaf){
					mosquitto__FREE(context->subs[i]);
					break;
				}
			}
			*reason = 0;
			return MOSQ_ERR_SUCCESS;
		}
		leaf = leaf->next;
	}
	return MOSQ_ERR_NO_SUBSCRIBERS;
}


static int sub__remove_shared(struct mosquitto *context, struct mosquitto__subhier *subhier, uint8_t *reason, const char *sharename)
{
	struct mosquitto__subshared *shared;
	struct mosquitto__subleaf *leaf;
	int i;

	HASH_FIND(hh, subhier->shared, sharename, strlen(sharename), shared);
	if(shared){
		leaf = shared->subs;
		while(leaf){
			if(leaf->context==context){
#ifdef WITH_SYS_TREE
				db.shared_subscription_count--;
#endif
				DL_DELETE(shared->subs, leaf);

				/* Remove the reference to the sub that the client is keeping.
				* It would be nice to be able to use the reference directly,
				* but that would involve keeping a copy of the topic string in
				* each subleaf. Might be worth considering though. */
				for(i=0; i<context->sub_count; i++){
					if(context->subs[i] == leaf){
						mosquitto__FREE(context->subs[i]);
						break;
					}
				}

				if(shared->subs == NULL){
					HASH_DELETE(hh, subhier->shared, shared);
					mosquitto__FREE(shared);
				}

				*reason = 0;
				return MOSQ_ERR_SUCCESS;
			}
			leaf = leaf->next;
		}
		return MOSQ_ERR_NO_SUBSCRIBERS;
	}else{
		return MOSQ_ERR_NO_SUBSCRIBERS;
	}
}


static int sub__remove_recurse(struct mosquitto *context, struct mosquitto__subhier *subhier, char **topics, uint8_t *reason, const char *sharename)
{
	struct mosquitto__subhier *branch;

	if(topics == NULL || topics[0] == NULL){
		if(sharename){
			return sub__remove_shared(context, subhier, reason, sharename);
		}else{
			return sub__remove_normal(context, subhier, reason);
		}
	}

	HASH_FIND(hh, subhier->children, topics[0], strlen(topics[0]), branch);
	if(branch){
		sub__remove_recurse(context, branch, &(topics[1]), reason, sharename);
		if(!branch->children && !branch->subs && !branch->shared){
			HASH_DELETE(hh, subhier->children, branch);
			mosquitto__FREE(branch);
		}
	}
	return MOSQ_ERR_SUCCESS;
}


static int sub__search(struct mosquitto__subhier *subhier, char **split_topics, const char *source_id, const char *topic, uint8_t qos, int retain, struct mosquitto_base_msg *stored)
{
	/* FIXME - need to take into account source_id if the client is a bridge */
	struct mosquitto__subhier *branch;
	int rc;
	bool have_subscribers = false;

	if(split_topics && split_topics[0]){
		/* Check for literal match */
		HASH_FIND(hh, subhier->children, split_topics[0], strlen(split_topics[0]), branch);

		if(branch){
			rc = sub__search(branch, &(split_topics[1]), source_id, topic, qos, retain, stored);
			if(rc == MOSQ_ERR_SUCCESS){
				have_subscribers = true;
			}else if(rc != MOSQ_ERR_NO_SUBSCRIBERS){
				return rc;
			}
			if(split_topics[1] == NULL){ /* End of list */
				rc = subs__process(branch, source_id, topic, qos, retain, stored);
				if(rc == MOSQ_ERR_SUCCESS){
					have_subscribers = true;
				}else if(rc != MOSQ_ERR_NO_SUBSCRIBERS){
					return rc;
				}
			}
		}

		/* Check for + match */
		HASH_FIND(hh, subhier->children, "+", 1, branch);

		if(branch){
			rc = sub__search(branch, &(split_topics[1]), source_id, topic, qos, retain, stored);
			if(rc == MOSQ_ERR_SUCCESS){
				have_subscribers = true;
			}else if(rc != MOSQ_ERR_NO_SUBSCRIBERS){
				return rc;
			}
			if(split_topics[1] == NULL){ /* End of list */
				rc = subs__process(branch, source_id, topic, qos, retain, stored);
				if(rc == MOSQ_ERR_SUCCESS){
					have_subscribers = true;
				}else if(rc != MOSQ_ERR_NO_SUBSCRIBERS){
					return rc;
				}
			}
		}
	}

	/* Check for # match */
	HASH_FIND(hh, subhier->children, "#", 1, branch);
	if(branch && !branch->children){
		/* The topic matches due to a # wildcard - process the
		 * subscriptions but *don't* return. Although this branch has ended
		 * there may still be other subscriptions to deal with.
		 */
		rc = subs__process(branch, source_id, topic, qos, retain, stored);
		if(rc == MOSQ_ERR_SUCCESS){
			have_subscribers = true;
		}else if(rc != MOSQ_ERR_NO_SUBSCRIBERS){
			return rc;
		}
	}

	if(have_subscribers){
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_NO_SUBSCRIBERS;
	}
}


struct mosquitto__subhier *sub__add_hier_entry(struct mosquitto__subhier *parent, struct mosquitto__subhier **sibling, const char *topic, uint16_t len)
{
	struct mosquitto__subhier *child;

	assert(sibling);

	child = mosquitto__calloc(1, sizeof(struct mosquitto__subhier) + len + 1);
	if(!child){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return NULL;
	}
	child->parent = parent;
	child->topic_len = len;
	strncpy(child->topic, topic, len);

	HASH_ADD(hh, *sibling, topic, child->topic_len, child);

	return child;
}


int sub__add(struct mosquitto *context, const char *sub, uint8_t qos, uint32_t identifier, int options)
{
	int rc = 0;
	struct mosquitto__subhier *subhier;
	const char *sharename = NULL;
	char *local_sub;
	char **topics;
	size_t topiclen;

	assert(sub);

	rc = sub__topic_tokenise(sub, &local_sub, &topics, &sharename);
	if(rc) return rc;

	topiclen = strlen(topics[0]);
	if(topiclen > UINT16_MAX){
		mosquitto__FREE(local_sub);
		mosquitto__FREE(topics);
		return MOSQ_ERR_INVAL;
	}
	HASH_FIND(hh, db.subs, topics[0], topiclen, subhier);
	if(!subhier){
		subhier = sub__add_hier_entry(NULL, &db.subs, topics[0], (uint16_t)topiclen);
		if(!subhier){
			mosquitto__FREE(local_sub);
			mosquitto__FREE(topics);
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}

	}
	rc = sub__add_context(context, sub, qos, identifier, options, subhier, topics, sharename);

	mosquitto__FREE(local_sub);
	mosquitto__FREE(topics);

	return rc;
}

int sub__remove(struct mosquitto *context, const char *sub, uint8_t *reason)
{
	int rc = 0;
	struct mosquitto__subhier *subhier;
	const char *sharename = NULL;
	char *local_sub = NULL;
	char **topics = NULL;

	assert(sub);

	rc = sub__topic_tokenise(sub, &local_sub, &topics, &sharename);
	if(rc) return rc;

	HASH_FIND(hh, db.subs, topics[0], strlen(topics[0]), subhier);
	if(subhier){
		*reason = MQTT_RC_NO_SUBSCRIPTION_EXISTED;
		rc = sub__remove_recurse(context, subhier, topics, reason, sharename);
	}

	mosquitto__FREE(local_sub);
	mosquitto__FREE(topics);

	return rc;
}

int sub__messages_queue(const char *source_id, const char *topic, uint8_t qos, int retain, struct mosquitto_base_msg **stored)
{
	int rc = MOSQ_ERR_SUCCESS, rc2;
	struct mosquitto__subhier *subhier;
	char **split_topics = NULL;
	char *local_topic = NULL;

	assert(topic);

	if(sub__topic_tokenise(topic, &local_topic, &split_topics, NULL)) return 1;

	/* Protect this message until we have sent it to all
	clients - this is required because websockets client calls
	db__message_write(), which could remove the message if ref_count==0.
	*/
	db__msg_store_ref_inc(*stored);

	HASH_FIND(hh, db.subs, split_topics[0], strlen(split_topics[0]), subhier);
	if(subhier){
		rc = sub__search(subhier, split_topics, source_id, topic, qos, retain, *stored);
	}

	if(retain){
		rc2 = retain__store(topic, *stored, split_topics, true);
		if(rc2) rc = rc2;
	}

	mosquitto__FREE(split_topics);
	mosquitto__FREE(local_topic);
	/* Remove our reference and free if needed. */
	db__msg_store_ref_dec(stored);

	return rc;
}


/* Remove a subhier element, and return its parent if that needs freeing as well. */
static struct mosquitto__subhier *tmp_remove_subs(struct mosquitto__subhier *sub)
{
	struct mosquitto__subhier *parent;

	if(!sub || !sub->parent){
		return NULL;
	}

	if(sub->children || sub->subs){
		return NULL;
	}

	parent = sub->parent;
	HASH_DELETE(hh, parent->children, sub);
	mosquitto__FREE(sub);

	if(parent->subs == NULL
			&& parent->children == NULL
			&& parent->shared == NULL
			&& parent->parent){

		return parent;
	}else{
		return NULL;
	}
}


/* Remove all subscriptions for a client.
 */
int sub__clean_session(struct mosquitto *context)
{
	int i;
	struct mosquitto__subleaf *leaf;
	struct mosquitto__subhier *hier;

	for(i=0; i<context->sub_count; i++){
		if(context->subs[i] == NULL || context->subs[i]->hier == NULL){
			continue;
		}

		hier = context->subs[i]->hier;

		plugin_persist__handle_subscription_delete(context, context->subs[i]->topic_filter);
		if(context->subs[i]->shared){
			leaf = context->subs[i]->shared->subs;
			while(leaf){
				if(leaf->context==context){
#ifdef WITH_SYS_TREE
					db.shared_subscription_count--;
#endif
					sub__remove_shared_leaf(context->subs[i]->hier, context->subs[i]->shared, leaf);
					break;
				}
				leaf = leaf->next;
			}
		}else{
			leaf = hier->subs;
			while(leaf){
				if(leaf->context==context){
#ifdef WITH_SYS_TREE
					db.subscription_count--;
#endif
					DL_DELETE(hier->subs, leaf);
					break;
				}
				leaf = leaf->next;
			}
		}
		mosquitto__FREE(context->subs[i]);

		if(hier->subs == NULL
				&& hier->children == NULL
				&& hier->shared == NULL
				&& hier->parent){

			do{
				hier = tmp_remove_subs(hier);
			}while(hier);
		}
	}
	mosquitto__FREE(context->subs);
	context->sub_count = 0;

	return MOSQ_ERR_SUCCESS;
}

void sub__tree_print(struct mosquitto__subhier *root, int level)
{
	int i;
	struct mosquitto__subhier *branch, *branch_tmp;
	struct mosquitto__subleaf *leaf;

	HASH_ITER(hh, root, branch, branch_tmp){
	if(level > -1){
		for(i=0; i<(level+2)*2; i++){
			printf(" ");
		}
		printf("%s", branch->topic);
		leaf = branch->subs;
		while(leaf){
			if(leaf->context){
				printf(" (%s, %d)", leaf->context->id, leaf->qos);
			}else{
				printf(" (%s, %d)", "", leaf->qos);
			}
			leaf = leaf->next;
		}
		printf("\n");
	}

		sub__tree_print(branch->children, level+1);
	}
}
