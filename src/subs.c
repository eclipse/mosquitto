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

#include <config.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <mosquitto_broker.h>
#include <memory_mosq.h>
#include <util_mosq.h>

struct _sub_token {
	struct _sub_token *next;
	char *topic;
};

static int _subs_process(struct mosquitto_db *db, struct _mosquitto_subhier *hier, const char *source_id, const char *topic, int qos, int retain, struct mosquitto_msg_store *stored, bool set_retain)
{
	int rc = 0;
	int rc2;
	int client_qos, msg_qos;
	uint16_t mid;
	struct _mosquitto_subleaf *leaf;
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
			mosquitto__db_msg_store_deref(db, &hier->retained);
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
		rc2 = mosquitto_acl_check(db, leaf->context, topic, MOSQ_ACL_READ);
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
				mid = _mosquitto_mid_generate(leaf->context);
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
			if(mqtt3_db_message_insert(db, leaf->context, mid, mosq_md_out, msg_qos, client_retain, stored) == 1) rc = 1;
		}else{
			return 1; /* Application error */
		}
		leaf = leaf->next;
	}
	return rc;
}

static struct _sub_token *_sub_topic_append(struct _sub_token **tail, struct _sub_token **topics, char *topic)
{
	struct _sub_token *new_topic;

	if(!topic){
		return NULL;
	}
	new_topic = _mosquitto_malloc(sizeof(struct _sub_token));
	if(!new_topic){
		_mosquitto_free(topic);
		return NULL;
	}
	new_topic->next = NULL;
	new_topic->topic = topic;

	if(*tail){
		(*tail)->next = new_topic;
		*tail = (*tail)->next;
	}else{
		*topics = new_topic;
		*tail = new_topic;
	}
	return new_topic;
}

static int _sub_topic_tokenise(const char *subtopic, struct _sub_token **topics)
{
	struct _sub_token *new_topic, *tail = NULL;
	int len;
	int start, stop, tlen;
	int i;
	char *topic;

	assert(subtopic);
	assert(topics);

	if(subtopic[0] != '$'){
		new_topic = _sub_topic_append(&tail, topics, _mosquitto_strdup(""));
		if(!new_topic) goto cleanup;
	}

	len = strlen(subtopic);

	if(subtopic[0] == '/'){
		new_topic = _sub_topic_append(&tail, topics, _mosquitto_strdup(""));
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

				topic = _mosquitto_malloc(tlen+1);
				if(!topic) goto cleanup;
				memcpy(topic, &subtopic[start], tlen);
				topic[tlen] = '\0';
			}else{
				topic = _mosquitto_strdup("");
				if(!topic) goto cleanup;
			}
			new_topic = _sub_topic_append(&tail, topics, topic);
			if(!new_topic) goto cleanup;
			start = i+1;
		}
	}

	return MOSQ_ERR_SUCCESS;

cleanup:
	tail = *topics;
	*topics = NULL;
	while(tail){
		if(tail->topic) _mosquitto_free(tail->topic);
		new_topic = tail->next;
		_mosquitto_free(tail);
		tail = new_topic;
	}
	return 1;
}

static void _sub_topic_tokens_free(struct _sub_token *tokens)
{
	struct _sub_token *tail;

	while(tokens){
		tail = tokens->next;
		if(tokens->topic){
			_mosquitto_free(tokens->topic);
		}
		_mosquitto_free(tokens);
		tokens = tail;
	}
}

static int _sub_add(struct mosquitto_db *db, struct mosquitto *context, int qos, struct _mosquitto_subhier *subhier, struct _sub_token *tokens)
	/* FIXME - this function has the potential to leak subhier, audit calling functions. */
{
	struct _mosquitto_subhier *branch, *last = NULL;
	struct _mosquitto_subleaf *leaf, *last_leaf;
	struct _mosquitto_subhier **subs;
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
			leaf = _mosquitto_malloc(sizeof(struct _mosquitto_subleaf));
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
				subs = _mosquitto_realloc(context->subs, sizeof(struct _mosquitto_subhier *)*(context->sub_count + 1));
				if(!subs){
					_mosquitto_free(leaf);
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

	branch = subhier->children;
	while(branch){
		if(!strcmp(branch->topic, tokens->topic)){
			return _sub_add(db, context, qos, branch, tokens->next);
		}
		last = branch;
		branch = branch->next;
	}
	/* Not found */
	branch = _mosquitto_calloc(1, sizeof(struct _mosquitto_subhier));
	if(!branch) return MOSQ_ERR_NOMEM;
	branch->parent = subhier;
	branch->topic = _mosquitto_strdup(tokens->topic);
	if(!branch->topic){
		_mosquitto_free(branch);
		return MOSQ_ERR_NOMEM;
	}
	if(!last){
		subhier->children = branch;
	}else{
		last->next = branch;
	}
	return _sub_add(db, context, qos, branch, tokens->next);
}

static int _sub_remove(struct mosquitto_db *db, struct mosquitto *context, struct _mosquitto_subhier *subhier, struct _sub_token *tokens)
{
	struct _mosquitto_subhier *branch, *last = NULL;
	struct _mosquitto_subleaf *leaf;
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
				_mosquitto_free(leaf);

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

	branch = subhier->children;
	while(branch){
		if(!strcmp(branch->topic, tokens->topic)){
			_sub_remove(db, context, branch, tokens->next);
			if(!branch->children && !branch->subs && !branch->retained){
				if(last){
					last->next = branch->next;
				}else{
					subhier->children = branch->next;
				}
				_mosquitto_free(branch->topic);
				_mosquitto_free(branch);
			}
			return MOSQ_ERR_SUCCESS;
		}
		last = branch;
		branch = branch->next;
	}
	return MOSQ_ERR_SUCCESS;
}

static void _sub_search(struct mosquitto_db *db, struct _mosquitto_subhier *subhier, struct _sub_token *tokens, const char *source_id, const char *topic, int qos, int retain, struct mosquitto_msg_store *stored, bool set_retain)
{
	/* FIXME - need to take into account source_id if the client is a bridge */
	struct _mosquitto_subhier *branch;
	bool sr;

	branch = subhier->children;
	while(branch){
		sr = set_retain;

		if(tokens && tokens->topic && (!strcmp(branch->topic, tokens->topic) || !strcmp(branch->topic, "+"))){
			/* The topic matches this subscription.
			 * Doesn't include # wildcards */
			if(!strcmp(branch->topic, "+")){
				/* Don't set a retained message where + is in the hierarchy. */
				sr = false;
			}
			_sub_search(db, branch, tokens->next, source_id, topic, qos, retain, stored, sr);
			if(!tokens->next){
				_subs_process(db, branch, source_id, topic, qos, retain, stored, sr);
			}
		}else if(!strcmp(branch->topic, "#") && !branch->children){
			/* The topic matches due to a # wildcard - process the
			 * subscriptions but *don't* return. Although this branch has ended
			 * there may still be other subscriptions to deal with.
			 */
			_subs_process(db, branch, source_id, topic, qos, retain, stored, false);
		}
		branch = branch->next;
	}
}

int mqtt3_sub_add(struct mosquitto_db *db, struct mosquitto *context, const char *sub, int qos, struct _mosquitto_subhier *root)
{
	int rc = 0;
	struct _mosquitto_subhier *subhier, *child;
	struct _sub_token *tokens = NULL;

	assert(root);
	assert(sub);

	if(_sub_topic_tokenise(sub, &tokens)) return 1;

	subhier = root->children;
	while(subhier){
		if(!strcmp(subhier->topic, tokens->topic)){
			rc = _sub_add(db, context, qos, subhier, tokens);
			break;
		}
		subhier = subhier->next;
	}
	if(!subhier){
		child = _mosquitto_malloc(sizeof(struct _mosquitto_subhier));
		if(!child){
			_sub_topic_tokens_free(tokens);
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
		child->parent = root;
		child->topic = _mosquitto_strdup(tokens->topic);
		if(!child->topic){
			_sub_topic_tokens_free(tokens);
			_mosquitto_free(child);
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
		child->subs = NULL;
		child->children = NULL;
		child->retained = NULL;
		if(root->children){
			child->next = root->children;
		}else{
			child->next = NULL;
		}
		root->children = child;

		rc = _sub_add(db, context, qos, child, tokens);
	}

	_sub_topic_tokens_free(tokens);

	/* We aren't worried about -1 (already subscribed) return codes. */
	if(rc == -1) rc = MOSQ_ERR_SUCCESS;
	return rc;
}

int mqtt3_sub_remove(struct mosquitto_db *db, struct mosquitto *context, const char *sub, struct _mosquitto_subhier *root)
{
	int rc = 0;
	struct _mosquitto_subhier *subhier;
	struct _sub_token *tokens = NULL;

	assert(root);
	assert(sub);

	if(_sub_topic_tokenise(sub, &tokens)) return 1;

	subhier = root->children;
	while(subhier){
		if(!strcmp(subhier->topic, tokens->topic)){
			rc = _sub_remove(db, context, subhier, tokens);
			break;
		}
		subhier = subhier->next;
	}

	_sub_topic_tokens_free(tokens);

	return rc;
}

int mqtt3_db_messages_queue(struct mosquitto_db *db, const char *source_id, const char *topic, int qos, int retain, struct mosquitto_msg_store **stored)
{
	int rc = 0;
	struct _mosquitto_subhier *subhier;
	struct _sub_token *tokens = NULL;

	assert(db);
	assert(topic);

	if(_sub_topic_tokenise(topic, &tokens)) return 1;

	/* Protect this message until we have sent it to all
	clients - this is required because websockets client calls
	mqtt3_db_message_write(), which could remove the message if ref_count==0.
	*/
	(*stored)->ref_count++;

	subhier = db->subs.children;
	while(subhier){
		if(!strcmp(subhier->topic, tokens->topic)){
			if(retain){
				/* We have a message that needs to be retained, so ensure that the subscription
				 * tree for its topic exists.
				 */
				_sub_add(db, NULL, 0, subhier, tokens);
			}
			_sub_search(db, subhier, tokens, source_id, topic, qos, retain, *stored, true);
		}
		subhier = subhier->next;
	}
	_sub_topic_tokens_free(tokens);

	/* Remove our reference and free if needed. */
	mosquitto__db_msg_store_deref(db, stored);

	return rc;
}


/* Remove a subhier element, and return its parent if that needs freeing as well. */
static struct _mosquitto_subhier *tmp_remove_subs(struct _mosquitto_subhier *sub)
{
	struct _mosquitto_subhier *parent;
	struct _mosquitto_subhier *hier;
	struct _mosquitto_subhier *last = NULL;

	if(!sub || !sub->parent){
		return NULL;
	}

	if(sub->children || sub->subs){
		return NULL;
	}

	parent = sub->parent;
	hier = sub->parent->children;

	while(hier){
		if(hier == sub){
			if(last){
				last->next = hier->next;
			}else{
				parent->children = hier->next;
			}
			_mosquitto_free(sub->topic);
			_mosquitto_free(sub);
			break;
		}
		last = hier;
		hier = hier->next;
	}
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
int mqtt3_subs_clean_session(struct mosquitto_db *db, struct mosquitto *context)
{
	int i;
	struct _mosquitto_subleaf *leaf;
	struct _mosquitto_subhier *hier;

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
				_mosquitto_free(leaf);
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
	_mosquitto_free(context->subs);
	context->subs = NULL;
	context->sub_count = 0;

	return MOSQ_ERR_SUCCESS;
}

void mqtt3_sub_tree_print(struct _mosquitto_subhier *root, int level)
{
	int i;
	struct _mosquitto_subhier *branch;
	struct _mosquitto_subleaf *leaf;

	for(i=0; i<level*2; i++){
		printf(" ");
	}
	printf("%s", root->topic);
	leaf = root->subs;
	while(leaf){
		if(leaf->context){
			printf(" (%s, %d)", leaf->context->id, leaf->qos);
		}else{
			printf(" (%s, %d)", "", leaf->qos);
		}
		leaf = leaf->next;
	}
	if(root->retained){
		printf(" (r)");
	}
	printf("\n");

	branch = root->children;
	while(branch){
		mqtt3_sub_tree_print(branch, level+1);
		branch = branch->next;
	}
}

static int _retain_process(struct mosquitto_db *db, struct mosquitto_msg_store *retained, struct mosquitto *context, const char *sub, int sub_qos)
{
	int rc = 0;
	int qos;
	uint16_t mid;

	rc = mosquitto_acl_check(db, context, retained->topic, MOSQ_ACL_READ);
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
		mid = _mosquitto_mid_generate(context);
	}else{
		mid = 0;
	}
	return mqtt3_db_message_insert(db, context, mid, mosq_md_out, qos, true, retained);
}

static int _retain_search(struct mosquitto_db *db, struct _mosquitto_subhier *subhier, struct _sub_token *tokens, struct mosquitto *context, const char *sub, int sub_qos, int level)
{
	struct _mosquitto_subhier *branch;
	int flag = 0;

	branch = subhier->children;
	while(branch){
		/* Subscriptions with wildcards in aren't really valid topics to publish to
		 * so they can't have retained messages.
		 */
		if(!strcmp(tokens->topic, "#") && !tokens->next){
			/* Set flag to indicate that we should check for retained messages
			 * on "foo" when we are subscribing to e.g. "foo/#" and then exit
			 * this function and return to an earlier _retain_search().
			 */
			flag = -1;
			if(branch->retained){
				_retain_process(db, branch->retained, context, sub, sub_qos);
			}
			if(branch->children){
				_retain_search(db, branch, tokens, context, sub, sub_qos, level+1);
			}
		}else if(strcmp(branch->topic, "+") && (!strcmp(branch->topic, tokens->topic) || !strcmp(tokens->topic, "+"))){
			if(tokens->next){
				if(_retain_search(db, branch, tokens->next, context, sub, sub_qos, level+1) == -1
						|| (!branch->next && tokens->next && !strcmp(tokens->next->topic, "#") && level>0)){

					if(branch->retained){
						_retain_process(db, branch->retained, context, sub, sub_qos);
					}
				}
			}else{
				if(branch->retained){
					_retain_process(db, branch->retained, context, sub, sub_qos);
				}
			}
		}

		branch = branch->next;
	}
	return flag;
}

int mqtt3_retain_queue(struct mosquitto_db *db, struct mosquitto *context, const char *sub, int sub_qos)
{
	struct _mosquitto_subhier *subhier;
	struct _sub_token *tokens = NULL, *tail;

	assert(db);
	assert(context);
	assert(sub);

	if(_sub_topic_tokenise(sub, &tokens)) return 1;

	subhier = db->subs.children;
	while(subhier){
		if(!strcmp(subhier->topic, tokens->topic)){
			_retain_search(db, subhier, tokens, context, sub, sub_qos, 0);
			break;
		}
		subhier = subhier->next;
	}
	while(tokens){
		tail = tokens->next;
		_mosquitto_free(tokens->topic);
		_mosquitto_free(tokens);
		tokens = tail;
	}

	return MOSQ_ERR_SUCCESS;
}

