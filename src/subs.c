/*
Copyright (c) 2010-2018 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
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
#include "util_mosq.h"

struct sub__token {
	struct sub__token *next;
	mosquitto__topic_element_uhpa topic;
	uint16_t topic_len;
};

static int subs__process(struct mosquitto_db *db, struct mosquitto__subhier *hier, const char *source_id, const char *topic, int qos, int retain, struct mosquitto_msg_store *stored, bool set_retain)
{
	int rc = 0;
	int rc2;
	int client_qos, msg_qos;
	uint16_t mid;
	struct mosquitto__subleaf *leaf;
	bool client_retain;

	leaf = hier->subs;

	if(retain && set_retain){
#ifdef WITH_PERSISTENCE
		if(strncmp(topic, "$SYS", 4)){
			/* Retained messages count as a persistence change, but only if
			 * they aren't for $SYS. */
			db->persistence_changes++;
		}
#endif
		if(hier->retained){
			db__msg_store_deref(db, &hier->retained);
#ifdef WITH_SYS_TREE
			db->retained_count--;
#endif
		}
		if(stored->payloadlen){
			hier->retained = stored;
			hier->retained->ref_count++;
#ifdef WITH_SYS_TREE
			db->retained_count++;
#endif
		}else{
			hier->retained = NULL;
		}
	}
	while(source_id && leaf){
		if(!leaf->context->id || (leaf->context->is_bridge && !strcmp(leaf->context->id, source_id))){
			leaf = leaf->next;
			continue;
		}
		/* Check for ACL topic access. */
		rc2 = mosquitto_acl_check(db, leaf->context, topic, stored->payloadlen, UHPA_ACCESS(stored->payload, stored->payloadlen), stored->qos, stored->retain, MOSQ_ACL_READ);
		if(rc2 == MOSQ_ERR_ACL_DENIED){
			leaf = leaf->next;
			continue;
		}else if(rc2 == MOSQ_ERR_SUCCESS){
			client_qos = leaf->qos;

			if(db->config->upgrade_outgoing_qos){
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
			if(leaf->context->is_bridge){
				/* If we know the client is a bridge then we should set retain
				 * even if the message is fresh. If we don't do this, retained
				 * messages won't be propagated. */
				client_retain = retain;
			}else{
				/* Client is not a bridge and this isn't a stale message so
				 * retain should be false. */
				client_retain = false;
			}
			if(db__message_insert(db, leaf->context, mid, mosq_md_out, msg_qos, client_retain, stored) == 1) rc = 1;
		}else{
			return 1; /* Application error */
		}
		leaf = leaf->next;
	}
	return rc;
}

static struct sub__token *sub__topic_append(struct sub__token **tail, struct sub__token **topics, char *topic)
{
	struct sub__token *new_topic;

	if(!topic){
		return NULL;
	}
	new_topic = mosquitto__malloc(sizeof(struct sub__token));
	if(!new_topic){
		return NULL;
	}
	new_topic->next = NULL;
	new_topic->topic_len = strlen(topic);
	if(UHPA_ALLOC_TOPIC(new_topic) == 0){
		mosquitto__free(new_topic);
		return NULL;
	}
	strncpy(UHPA_ACCESS_TOPIC(new_topic), topic, new_topic->topic_len+1);

	if(*tail){
		(*tail)->next = new_topic;
		*tail = (*tail)->next;
	}else{
		*topics = new_topic;
		*tail = new_topic;
	}
	return new_topic;
}

static int sub__topic_tokenise(const char *subtopic, struct sub__token **topics)
{
	struct sub__token *new_topic, *tail = NULL;
	int len;
	int start, stop, tlen;
	int i;
	mosquitto__topic_element_uhpa topic;

	assert(subtopic);
	assert(topics);

	if(subtopic[0] != '$'){
		new_topic = sub__topic_append(&tail, topics, "");
		if(!new_topic) goto cleanup;
	}

	len = strlen(subtopic);

	if(subtopic[0] == '/'){
		new_topic = sub__topic_append(&tail, topics, "");
		if(!new_topic) goto cleanup;

		start = 1;
	}else{
		start = 0;
	}

	stop = 0;
	for(i=start; i<len+1; i++){
		if(subtopic[i] == '/' || subtopic[i] == '\0'){
			stop = i;

			if(start != stop){
				tlen = stop-start;

				if(UHPA_ALLOC(topic, tlen+1) == 0) goto cleanup;
				memcpy(UHPA_ACCESS(topic, tlen+1), &subtopic[start], tlen);
				UHPA_ACCESS(topic, tlen+1)[tlen] = '\0';
				new_topic = sub__topic_append(&tail, topics, UHPA_ACCESS(topic, tlen+1));
				UHPA_FREE(topic, tlen+1);
			}else{
				new_topic = sub__topic_append(&tail, topics, "");
			}
			if(!new_topic) goto cleanup;
			start = i+1;
		}
	}

	return MOSQ_ERR_SUCCESS;

cleanup:
	tail = *topics;
	*topics = NULL;
	while(tail){
		UHPA_FREE_TOPIC(tail);
		new_topic = tail->next;
		mosquitto__free(tail);
		tail = new_topic;
	}
	return 1;
}

static void sub__topic_tokens_free(struct sub__token *tokens)
{
	struct sub__token *tail;

	while(tokens){
		tail = tokens->next;
		UHPA_FREE_TOPIC(tokens);
		mosquitto__free(tokens);
		tokens = tail;
	}
}

static int sub__add_recurse(struct mosquitto_db *db, struct mosquitto *context, int qos, struct mosquitto__subhier *subhier, struct sub__token *tokens)
	/* FIXME - this function has the potential to leak subhier, audit calling functions. */
{
	struct mosquitto__subhier *branch;
	struct mosquitto__subleaf *leaf, *last_leaf;
	struct mosquitto__subhier **subs;
	int i;

	if(!tokens){
		if(context && context->id){
			leaf = subhier->subs;
			last_leaf = NULL;
			while(leaf){
				if(leaf->context && leaf->context->id && !strcmp(leaf->context->id, context->id)){
					/* Client making a second subscription to same topic. Only
					 * need to update QoS. Return -1 to indicate this to the
					 * calling function. */
					leaf->qos = qos;
					if(context->protocol == mosq_p_mqtt31){
						return -1;
					}else{
						/* mqttv311 requires retained messages are resent on
						 * resubscribe. */
						return 0;
					}
				}
				last_leaf = leaf;
				leaf = leaf->next;
			}
			leaf = mosquitto__malloc(sizeof(struct mosquitto__subleaf));
			if(!leaf) return MOSQ_ERR_NOMEM;
			leaf->next = NULL;
			leaf->context = context;
			leaf->qos = qos;
			for(i=0; i<context->sub_count; i++){
				if(!context->subs[i]){
					context->subs[i] = subhier;
					break;
				}
			}
			if(i == context->sub_count){
				subs = mosquitto__realloc(context->subs, sizeof(struct mosquitto__subhier *)*(context->sub_count + 1));
				if(!subs){
					mosquitto__free(leaf);
					return MOSQ_ERR_NOMEM;
				}
				context->subs = subs;
				context->sub_count++;
				context->subs[context->sub_count-1] = subhier;
			}
			if(last_leaf){
				last_leaf->next = leaf;
				leaf->prev = last_leaf;
			}else{
				subhier->subs = leaf;
				leaf->prev = NULL;
			}
#ifdef WITH_SYS_TREE
			db->subscription_count++;
#endif
		}
		return MOSQ_ERR_SUCCESS;
	}

	HASH_FIND(hh, subhier->children, UHPA_ACCESS_TOPIC(tokens), tokens->topic_len, branch);
	if(branch){
		return sub__add_recurse(db, context, qos, branch, tokens->next);
	}else{
		/* Not found */
		branch = sub__add_hier_entry(subhier, &subhier->children, UHPA_ACCESS_TOPIC(tokens), tokens->topic_len+1);
		if(!branch) return MOSQ_ERR_NOMEM;

		return sub__add_recurse(db, context, qos, branch, tokens->next);
	}
}

static int sub__remove_recurse(struct mosquitto_db *db, struct mosquitto *context, struct mosquitto__subhier *subhier, struct sub__token *tokens)
{
	struct mosquitto__subhier *branch;
	struct mosquitto__subleaf *leaf;
	int i;

	if(!tokens){
		leaf = subhier->subs;
		while(leaf){
			if(leaf->context==context){
#ifdef WITH_SYS_TREE
				db->subscription_count--;
#endif
				if(leaf->prev){
					leaf->prev->next = leaf->next;
				}else{
					subhier->subs = leaf->next;
				}
				if(leaf->next){
					leaf->next->prev = leaf->prev;
				}
				mosquitto__free(leaf);

				/* Remove the reference to the sub that the client is keeping.
				 * It would be nice to be able to use the reference directly,
				 * but that would involve keeping a copy of the topic string in
				 * each subleaf. Might be worth considering though. */
				for(i=0; i<context->sub_count; i++){
					if(context->subs[i] == subhier){
						context->subs[i] = NULL;
						break;
					}
				}
				return MOSQ_ERR_SUCCESS;
			}
			leaf = leaf->next;
		}
		return MOSQ_ERR_SUCCESS;
	}

	HASH_FIND(hh, subhier->children, UHPA_ACCESS_TOPIC(tokens), tokens->topic_len, branch);
	if(branch){
		sub__remove_recurse(db, context, branch, tokens->next);
		if(!branch->children && !branch->subs && !branch->retained){
			HASH_DELETE(hh, subhier->children, branch);
			UHPA_FREE_TOPIC(branch);
			mosquitto__free(branch);
		}
	}
	return MOSQ_ERR_SUCCESS;
}

static void sub__search(struct mosquitto_db *db, struct mosquitto__subhier *subhier, struct sub__token *tokens, const char *source_id, const char *topic, int qos, int retain, struct mosquitto_msg_store *stored, bool set_retain)
{
	/* FIXME - need to take into account source_id if the client is a bridge */
	struct mosquitto__subhier *branch, *branch_tmp;
	bool sr;

	HASH_ITER(hh, subhier->children, branch, branch_tmp){
		sr = set_retain;

		if(tokens && UHPA_ACCESS_TOPIC(tokens)
					&& (!strcmp(UHPA_ACCESS_TOPIC(branch), UHPA_ACCESS_TOPIC(tokens))
					|| !strcmp(UHPA_ACCESS_TOPIC(branch), "+"))){
			/* The topic matches this subscription.
			 * Doesn't include # wildcards */
			if(!strcmp(UHPA_ACCESS_TOPIC(branch), "+")){
				/* Don't set a retained message where + is in the hierarchy. */
				sr = false;
			}
			sub__search(db, branch, tokens->next, source_id, topic, qos, retain, stored, sr);
			if(!tokens->next){
				subs__process(db, branch, source_id, topic, qos, retain, stored, sr);
			}
		}else if(!strcmp(UHPA_ACCESS_TOPIC(branch), "#") && !branch->children){
			/* The topic matches due to a # wildcard - process the
			 * subscriptions but *don't* return. Although this branch has ended
			 * there may still be other subscriptions to deal with.
			 */
			subs__process(db, branch, source_id, topic, qos, retain, stored, false);
		}
	}
}


struct mosquitto__subhier *sub__add_hier_entry(struct mosquitto__subhier *parent, struct mosquitto__subhier **sibling, const char *topic, size_t len)
{
	struct mosquitto__subhier *child;

	assert(sibling);

	child = mosquitto__malloc(sizeof(struct mosquitto__subhier));
	if(!child){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return NULL;
	}
	child->parent = parent;
	child->topic_len = strlen(topic);
	if(UHPA_ALLOC_TOPIC(child) == 0){
		child->topic_len = 0;
		mosquitto__free(child);
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return NULL;
	}else{
		strncpy(UHPA_ACCESS_TOPIC(child), topic, child->topic_len+1);
	}
	child->subs = NULL;
	child->children = NULL;
	child->retained = NULL;

	if(child->topic_len+1 > sizeof(child->topic.array)){
		if(child->topic.ptr){
			HASH_ADD_KEYPTR(hh, *sibling, child->topic.ptr, child->topic_len, child);
		}else{
			mosquitto__free(child);
			return NULL;
		}
	}else{
		HASH_ADD(hh, *sibling, topic.array, child->topic_len, child);
	}

	return child;
}


int sub__add(struct mosquitto_db *db, struct mosquitto *context, const char *sub, int qos, struct mosquitto__subhier **root)
{
	int rc = 0;
	struct mosquitto__subhier *subhier;
	struct sub__token *tokens = NULL;

	assert(root);
	assert(*root);
	assert(sub);

	if(sub__topic_tokenise(sub, &tokens)) return 1;

	HASH_FIND(hh, *root, UHPA_ACCESS_TOPIC(tokens), tokens->topic_len, subhier);
	if(!subhier){
		subhier = sub__add_hier_entry(NULL, root, UHPA_ACCESS_TOPIC(tokens), tokens->topic_len+1);
		if(!subhier){
			sub__topic_tokens_free(tokens);
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}

	}
	rc = sub__add_recurse(db, context, qos, subhier, tokens);

	sub__topic_tokens_free(tokens);

	/* We aren't worried about -1 (already subscribed) return codes. */
	if(rc == -1) rc = MOSQ_ERR_SUCCESS;
	return rc;
}

int sub__remove(struct mosquitto_db *db, struct mosquitto *context, const char *sub, struct mosquitto__subhier *root)
{
	int rc = 0;
	struct mosquitto__subhier *subhier;
	struct sub__token *tokens = NULL;

	assert(root);
	assert(sub);

	if(sub__topic_tokenise(sub, &tokens)) return 1;

	HASH_FIND(hh, root, UHPA_ACCESS_TOPIC(tokens), tokens->topic_len, subhier);
	if(subhier){
		rc = sub__remove_recurse(db, context, subhier, tokens);
	}

	sub__topic_tokens_free(tokens);

	return rc;
}

int sub__messages_queue(struct mosquitto_db *db, const char *source_id, const char *topic, int qos, int retain, struct mosquitto_msg_store **stored)
{
	int rc = 0;
	struct mosquitto__subhier *subhier;
	struct sub__token *tokens = NULL;

	assert(db);
	assert(topic);

	if(sub__topic_tokenise(topic, &tokens)) return 1;

	/* Protect this message until we have sent it to all
	clients - this is required because websockets client calls
	db__message_write(), which could remove the message if ref_count==0.
	*/
	(*stored)->ref_count++;

	HASH_FIND(hh, db->subs, UHPA_ACCESS_TOPIC(tokens), tokens->topic_len, subhier);
	if(subhier){
		if(retain){
			/* We have a message that needs to be retained, so ensure that the subscription
			 * tree for its topic exists.
			 */
			sub__add_recurse(db, NULL, 0, subhier, tokens);
		}
		sub__search(db, subhier, tokens, source_id, topic, qos, retain, *stored, true);
	}
	sub__topic_tokens_free(tokens);

	/* Remove our reference and free if needed. */
	db__msg_store_deref(db, stored);

	return rc;
}


/* Remove a subhier element, and return its parent if that needs freeing as well. */
static struct mosquitto__subhier *tmp_remove_subs(struct mosquitto__subhier *sub)
{
	struct mosquitto__subhier *parent;

	if(!sub || !sub->parent){
		return NULL;
	}

	if(sub->children || sub->subs || sub->retained){
		return NULL;
	}

	parent = sub->parent;
	HASH_DELETE(hh, parent->children, sub);
	UHPA_FREE_TOPIC(sub);
	mosquitto__free(sub);

	if(parent->subs == NULL
			&& parent->children == NULL
			&& parent->retained == NULL
			&& parent->parent){

		return parent;
	}else{
		return NULL;
	}
}


/* Remove all subscriptions for a client.
 */
int sub__clean_session(struct mosquitto_db *db, struct mosquitto *context)
{
	int i;
	struct mosquitto__subleaf *leaf;
	struct mosquitto__subhier *hier;

	for(i=0; i<context->sub_count; i++){
		if(context->subs[i] == NULL){
			continue;
		}
		leaf = context->subs[i]->subs;
		while(leaf){
			if(leaf->context==context){
#ifdef WITH_SYS_TREE
				db->subscription_count--;
#endif
				if(leaf->prev){
					leaf->prev->next = leaf->next;
				}else{
					context->subs[i]->subs = leaf->next;
				}
				if(leaf->next){
					leaf->next->prev = leaf->prev;
				}
				mosquitto__free(leaf);
				break;
			}
			leaf = leaf->next;
		}
		if(context->subs[i]->subs == NULL
				&& context->subs[i]->children == NULL
				&& context->subs[i]->retained == NULL
				&& context->subs[i]->parent){

			hier = context->subs[i];
			context->subs[i] = NULL;
			do{
				hier = tmp_remove_subs(hier);
			}while(hier);
		}
	}
	mosquitto__free(context->subs);
	context->subs = NULL;
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
		printf("%s", UHPA_ACCESS_TOPIC(branch));
		leaf = branch->subs;
		while(leaf){
			if(leaf->context){
				printf(" (%s, %d)", leaf->context->id, leaf->qos);
			}else{
				printf(" (%s, %d)", "", leaf->qos);
			}
			leaf = leaf->next;
		}
		if(branch->retained){
			printf(" (r)");
		}
		printf("\n");
	}

		sub__tree_print(branch->children, level+1);
	}
}

static int retain__process(struct mosquitto_db *db, struct mosquitto_msg_store *retained, struct mosquitto *context, const char *sub, int sub_qos)
{
	int rc = 0;
	int qos;
	uint16_t mid;

	rc = mosquitto_acl_check(db, context, retained->topic, retained->payloadlen, UHPA_ACCESS(retained->payload, retained->payloadlen),
			retained->qos, retained->retain, MOSQ_ACL_READ);
	if(rc == MOSQ_ERR_ACL_DENIED){
		return MOSQ_ERR_SUCCESS;
	}else if(rc != MOSQ_ERR_SUCCESS){
		return rc;
	}

	if (db->config->upgrade_outgoing_qos){
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
	return db__message_insert(db, context, mid, mosq_md_out, qos, true, retained);
}

static int retain__search(struct mosquitto_db *db, struct mosquitto__subhier *subhier, struct sub__token *tokens, struct mosquitto *context, const char *sub, int sub_qos, int level)
{
	struct mosquitto__subhier *branch, *branch_tmp;
	int flag = 0;

	HASH_ITER(hh, subhier->children, branch, branch_tmp){
		/* Subscriptions with wildcards in aren't really valid topics to publish to
		 * so they can't have retained messages.
		 */
		if(!strcmp(UHPA_ACCESS_TOPIC(tokens), "#") && !tokens->next){
			/* Set flag to indicate that we should check for retained messages
			 * on "foo" when we are subscribing to e.g. "foo/#" and then exit
			 * this function and return to an earlier retain__search().
			 */
			flag = -1;
			if(branch->retained){
				retain__process(db, branch->retained, context, sub, sub_qos);
			}
			if(branch->children){
				retain__search(db, branch, tokens, context, sub, sub_qos, level+1);
			}
		}else if(strcmp(UHPA_ACCESS_TOPIC(branch), "+")
					&& (!strcmp(UHPA_ACCESS_TOPIC(branch), UHPA_ACCESS_TOPIC(tokens))
					|| !strcmp(UHPA_ACCESS_TOPIC(tokens), "+"))){
			if(tokens->next){
				if(retain__search(db, branch, tokens->next, context, sub, sub_qos, level+1) == -1
						|| (!branch_tmp && tokens->next && !strcmp(UHPA_ACCESS_TOPIC(tokens->next), "#") && level>0)){

					if(branch->retained){
						retain__process(db, branch->retained, context, sub, sub_qos);
					}
				}
			}else{
				if(branch->retained){
					retain__process(db, branch->retained, context, sub, sub_qos);
				}
			}
		}
	}
	return flag;
}

int sub__retain_queue(struct mosquitto_db *db, struct mosquitto *context, const char *sub, int sub_qos)
{
	struct mosquitto__subhier *subhier;
	struct sub__token *tokens = NULL, *tail;

	assert(db);
	assert(context);
	assert(sub);

	if(sub__topic_tokenise(sub, &tokens)) return 1;

	HASH_FIND(hh, db->subs, UHPA_ACCESS_TOPIC(tokens), tokens->topic_len, subhier);

	if(subhier){
		retain__search(db, subhier, tokens, context, sub, sub_qos, 0);
	}
	while(tokens){
		tail = tokens->next;
		UHPA_FREE_TOPIC(tokens);
		mosquitto__free(tokens);
		tokens = tail;
	}

	return MOSQ_ERR_SUCCESS;
}

