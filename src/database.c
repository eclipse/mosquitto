/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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

#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <utlist.h>

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "send_mosq.h"
#include "sys_tree.h"
#include "time_mosq.h"
#include "util_mosq.h"

static unsigned long max_inflight_bytes = 0;
static int max_queued = 100;
static unsigned long max_queued_bytes = 0;

/**
 * Is this context ready to take more in flight messages right now?
 * @param context the client context of interest
 * @param qos qos for the packet of interest
 * @return true if more in flight are allowed.
 */
static bool db__ready_for_flight(struct mosquitto_msg_data *msgs, int qos)
{
	bool valid_bytes;
	bool valid_count;

	if(qos == 0 || (msgs->inflight_maximum == 0 && max_inflight_bytes == 0)){
		return true;
	}

	valid_bytes = msgs->msg_bytes12 < max_inflight_bytes;
	valid_count = msgs->inflight_quota > 0;

	if(msgs->inflight_maximum == 0){
		return valid_bytes;
	}
	if(max_inflight_bytes == 0){
		return valid_count;
	}

	return valid_bytes && valid_count;
}


/**
 * For a given client context, are more messages allowed to be queued?
 * It is assumed that inflight checks and queue_qos0 checks have already
 * been made.
 * @param context client of interest
 * @param qos destination qos for the packet of interest
 * @return true if queuing is allowed, false if should be dropped
 */
static bool db__ready_for_queue(struct mosquitto *context, int qos, struct mosquitto_msg_data *msg_data)
{
	int source_count;
	int adjust_count;
	unsigned long source_bytes;
	unsigned long adjust_bytes = max_inflight_bytes;
	bool valid_bytes;
	bool valid_count;

	if(max_queued == 0 && max_queued_bytes == 0){
		return true;
	}

	if(qos == 0){
		source_bytes = msg_data->msg_bytes;
		source_count = msg_data->msg_count;
	}else{
		source_bytes = msg_data->msg_bytes12;
		source_count = msg_data->msg_count12;
	}
	adjust_count = msg_data->inflight_maximum;

	/* nothing in flight for offline clients */
	if(context->sock == INVALID_SOCKET){
		adjust_bytes = 0;
		adjust_count = 0;
	}

	valid_bytes = source_bytes - adjust_bytes < max_queued_bytes;
	valid_count = source_count - adjust_count < max_queued;

	if(max_queued_bytes == 0){
		return valid_count;
	}
	if(max_queued == 0){
		return valid_bytes;
	}

	return valid_bytes && valid_count;
}


int db__open(struct mosquitto__config *config, struct mosquitto_db *db)
{
	struct mosquitto__subhier *subhier;

	if(!config || !db) return MOSQ_ERR_INVAL;

	db->last_db_id = 0;

	db->contexts_by_id = NULL;
	db->contexts_by_sock = NULL;
	db->contexts_for_free = NULL;
#ifdef WITH_BRIDGE
	db->bridges = NULL;
	db->bridge_count = 0;
#endif

	/* Initialize the hashtable */
	db->clientid_index_hash = NULL;

	db->subs = NULL;

	subhier = sub__add_hier_entry(NULL, &db->subs, "", strlen(""));
	if(!subhier) return MOSQ_ERR_NOMEM;

	subhier = sub__add_hier_entry(NULL, &db->subs, "$SYS", strlen("$SYS"));
	if(!subhier) return MOSQ_ERR_NOMEM;

	db->unpwd = NULL;

#ifdef WITH_PERSISTENCE
	if(persist__restore(db)) return 1;
#endif

	return MOSQ_ERR_SUCCESS;
}

static void subhier_clean(struct mosquitto_db *db, struct mosquitto__subhier **subhier)
{
	struct mosquitto__subhier *peer, *subhier_tmp;
	struct mosquitto__subleaf *leaf, *nextleaf;

	HASH_ITER(hh, *subhier, peer, subhier_tmp){
		leaf = peer->subs;
		while(leaf){
			nextleaf = leaf->next;
			mosquitto__free(leaf);
			leaf = nextleaf;
		}
		if(peer->retained){
			db__msg_store_ref_dec(db, &peer->retained);
		}
		subhier_clean(db, &peer->children);
		mosquitto__free(peer->topic);

		HASH_DELETE(hh, *subhier, peer);
		mosquitto__free(peer);
	}
}

int db__close(struct mosquitto_db *db)
{
	subhier_clean(db, &db->subs);
	db__msg_store_clean(db);

	return MOSQ_ERR_SUCCESS;
}


void db__msg_store_add(struct mosquitto_db *db, struct mosquitto_msg_store *store)
{
	store->next = db->msg_store;
	store->prev = NULL;
	if(db->msg_store){
		db->msg_store->prev = store;
	}
	db->msg_store = store;
}


void db__msg_store_remove(struct mosquitto_db *db, struct mosquitto_msg_store *store)
{
	int i;

	if(store->prev){
		store->prev->next = store->next;
		if(store->next){
			store->next->prev = store->prev;
		}
	}else{
		db->msg_store = store->next;
		if(store->next){
			store->next->prev = NULL;
		}
	}
	db->msg_store_count--;
	db->msg_store_bytes -= store->payloadlen;

	mosquitto__free(store->source_id);
	mosquitto__free(store->source_username);
	if(store->dest_ids){
		for(i=0; i<store->dest_id_count; i++){
			mosquitto__free(store->dest_ids[i]);
		}
		mosquitto__free(store->dest_ids);
	}
	mosquitto__free(store->topic);
	mosquitto_property_free_all(&store->properties);
	UHPA_FREE_PAYLOAD(store);
	mosquitto__free(store);
}


void db__msg_store_clean(struct mosquitto_db *db)
{
	struct mosquitto_msg_store *store, *next;;

	store = db->msg_store;
	while(store){
		next = store->next;
		db__msg_store_remove(db, store);
		store = next;
	}
}

void db__msg_store_ref_inc(struct mosquitto_msg_store *store)
{
	store->ref_count++;
}

void db__msg_store_ref_dec(struct mosquitto_db *db, struct mosquitto_msg_store **store)
{
	(*store)->ref_count--;
	if((*store)->ref_count == 0){
		db__msg_store_remove(db, *store);
		*store = NULL;
	}
}


void db__msg_store_compact(struct mosquitto_db *db)
{
	struct mosquitto_msg_store *store, *next;

	store = db->msg_store;
	while(store){
		next = store->next;
		if(store->ref_count < 1){
			db__msg_store_remove(db, store);
		}
		store = next;
	}
}


static void db__message_remove(struct mosquitto_db *db, struct mosquitto_msg_data *msg_data, struct mosquitto_client_msg *item)
{
	if(!msg_data || !item){
		return;
	}

	DL_DELETE(msg_data->inflight, item);
	if(item->store){
		msg_data->msg_count--;
		msg_data->msg_bytes -= item->store->payloadlen;
		if(item->qos > 0){
			msg_data->msg_count12--;
			msg_data->msg_bytes12 -= item->store->payloadlen;
		}
		db__msg_store_ref_dec(db, &item->store);
	}

	mosquitto_property_free_all(&item->properties);
	mosquitto__free(item);
}


void db__message_dequeue_first(struct mosquitto *context, struct mosquitto_msg_data *msg_data)
{
	struct mosquitto_client_msg *msg;

	msg = msg_data->queued;
	DL_DELETE(msg_data->queued, msg);
	DL_APPEND(msg_data->inflight, msg);
	if(msg_data->inflight_quota > 0){
		msg_data->inflight_quota--;
	}
}


int db__message_delete_outgoing(struct mosquitto_db *db, struct mosquitto *context, uint16_t mid, enum mosquitto_msg_state expect_state, int qos)
{
	struct mosquitto_client_msg *tail, *tmp;
	int msg_index = 0;

	if(!context) return MOSQ_ERR_INVAL;

	DL_FOREACH_SAFE(context->msgs_out.inflight, tail, tmp){
		msg_index++;
		if(tail->mid == mid){
			if(tail->qos != qos){
				return MOSQ_ERR_PROTOCOL;
			}else if(qos == 2 && tail->state != expect_state){
				return MOSQ_ERR_PROTOCOL;
			}
			msg_index--;
			db__message_remove(db, &context->msgs_out, tail);
		}
	}

	DL_FOREACH_SAFE(context->msgs_out.queued, tail, tmp){
		if(context->msgs_out.inflight_maximum != 0 && msg_index >= context->msgs_out.inflight_maximum){
			break;
		}

		msg_index++;
		tail->timestamp = mosquitto_time();
		switch(tail->qos){
			case 0:
				tail->state = mosq_ms_publish_qos0;
				break;
			case 1:
				tail->state = mosq_ms_publish_qos1;
				break;
			case 2:
				tail->state = mosq_ms_publish_qos2;
				break;
		}
		db__message_dequeue_first(context, &context->msgs_out);
	}

	return MOSQ_ERR_SUCCESS;
}

int db__message_insert(struct mosquitto_db *db, struct mosquitto *context, uint16_t mid, enum mosquitto_msg_direction dir, int qos, bool retain, struct mosquitto_msg_store *stored, mosquitto_property *properties)
{
	struct mosquitto_client_msg *msg;
	struct mosquitto_msg_data *msg_data;
	enum mosquitto_msg_state state = mosq_ms_invalid;
	int rc = 0;
	int i;
	char **dest_ids;

	assert(stored);
	if(!context) return MOSQ_ERR_INVAL;
	if(!context->id) return MOSQ_ERR_SUCCESS; /* Protect against unlikely "client is disconnected but not entirely freed" scenario */

	if(dir == mosq_md_out){
		msg_data = &context->msgs_out;
	}else{
		msg_data = &context->msgs_in;
	}

	/* Check whether we've already sent this message to this client
	 * for outgoing messages only.
	 * If retain==true then this is a stale retained message and so should be
	 * sent regardless. FIXME - this does mean retained messages will received
	 * multiple times for overlapping subscriptions, although this is only the
	 * case for SUBSCRIPTION with multiple subs in so is a minor concern.
	 */
	if(context->protocol != mosq_p_mqtt5
			&& db->config->allow_duplicate_messages == false
			&& dir == mosq_md_out && retain == false && stored->dest_ids){

		for(i=0; i<stored->dest_id_count; i++){
			if(!strcmp(stored->dest_ids[i], context->id)){
				/* We have already sent this message to this client. */
				mosquitto_property_free_all(&properties);
				return MOSQ_ERR_SUCCESS;
			}
		}
	}
	if(context->sock == INVALID_SOCKET){
		/* Client is not connected only queue messages with QoS>0. */
		if(qos == 0 && !db->config->queue_qos0_messages){
			if(!context->bridge){
				mosquitto_property_free_all(&properties);
				return 2;
			}else{
				if(context->bridge->start_type != bst_lazy){
					mosquitto_property_free_all(&properties);
					return 2;
				}
			}
		}
	}

	if(context->sock != INVALID_SOCKET){
		if(db__ready_for_flight(msg_data, qos)){
			if(dir == mosq_md_out){
				switch(qos){
					case 0:
						state = mosq_ms_publish_qos0;
						break;
					case 1:
						state = mosq_ms_publish_qos1;
						break;
					case 2:
						state = mosq_ms_publish_qos2;
						break;
				}
			}else{
				if(qos == 2){
					state = mosq_ms_wait_for_pubrel;
				}else{
					mosquitto_property_free_all(&properties);
					return 1;
				}
			}
		}else if(db__ready_for_queue(context, qos, msg_data)){
			state = mosq_ms_queued;
			rc = 2;
		}else{
			/* Dropping message due to full queue. */
			if(context->is_dropping == false){
				context->is_dropping = true;
				log__printf(NULL, MOSQ_LOG_NOTICE,
						"Outgoing messages are being dropped for client %s.",
						context->id);
			}
			G_MSGS_DROPPED_INC();
			mosquitto_property_free_all(&properties);
			return 2;
		}
	}else{
		if (db__ready_for_queue(context, qos, msg_data)){
			state = mosq_ms_queued;
		}else{
			G_MSGS_DROPPED_INC();
			if(context->is_dropping == false){
				context->is_dropping = true;
				log__printf(NULL, MOSQ_LOG_NOTICE,
						"Outgoing messages are being dropped for client %s.",
						context->id);
			}
			mosquitto_property_free_all(&properties);
			return 2;
		}
	}
	assert(state != mosq_ms_invalid);

#ifdef WITH_PERSISTENCE
	if(state == mosq_ms_queued){
		db->persistence_changes++;
	}
#endif

	msg = mosquitto__malloc(sizeof(struct mosquitto_client_msg));
	if(!msg) return MOSQ_ERR_NOMEM;
	msg->prev = NULL;
	msg->next = NULL;
	msg->store = stored;
	db__msg_store_ref_inc(msg->store);
	msg->mid = mid;
	msg->timestamp = mosquitto_time();
	msg->direction = dir;
	msg->state = state;
	msg->dup = false;
	if(qos > context->maximum_qos){
		msg->qos = context->maximum_qos;
	}else{
		msg->qos = qos;
	}
	msg->retain = retain;
	msg->properties = properties;

	if(state == mosq_ms_queued){
		DL_APPEND(msg_data->queued, msg);
	}else{
		DL_APPEND(msg_data->inflight, msg);
	}
	msg_data->msg_count++;
	msg_data->msg_bytes+= msg->store->payloadlen;
	if(qos > 0){
		msg_data->msg_count12++;
		msg_data->msg_bytes12 += msg->store->payloadlen;
	}

	if(db->config->allow_duplicate_messages == false && dir == mosq_md_out && retain == false){
		/* Record which client ids this message has been sent to so we can avoid duplicates.
		 * Outgoing messages only.
		 * If retain==true then this is a stale retained message and so should be
		 * sent regardless. FIXME - this does mean retained messages will received
		 * multiple times for overlapping subscriptions, although this is only the
		 * case for SUBSCRIPTION with multiple subs in so is a minor concern.
		 */
		dest_ids = mosquitto__realloc(stored->dest_ids, sizeof(char *)*(stored->dest_id_count+1));
		if(dest_ids){
			stored->dest_ids = dest_ids;
			stored->dest_id_count++;
			stored->dest_ids[stored->dest_id_count-1] = mosquitto__strdup(context->id);
			if(!stored->dest_ids[stored->dest_id_count-1]){
				return MOSQ_ERR_NOMEM;
			}
		}else{
			return MOSQ_ERR_NOMEM;
		}
	}
#ifdef WITH_BRIDGE
	if(context->bridge && context->bridge->start_type == bst_lazy
			&& context->sock == INVALID_SOCKET
			&& context->msgs_out.msg_count >= context->bridge->threshold){

		context->bridge->lazy_reconnect = true;
	}
#endif

	if(dir == mosq_md_out && msg->qos > 0){
		util__decrement_send_quota(context);
	}
#ifdef WITH_WEBSOCKETS
	if(context->wsi && rc == 0){
		return db__message_write(db, context);
	}else{
		return rc;
	}
#else
	return rc;
#endif
}

int db__message_update_outgoing(struct mosquitto *context, uint16_t mid, enum mosquitto_msg_state state, int qos)
{
	struct mosquitto_client_msg *tail;

	DL_FOREACH(context->msgs_out.inflight, tail){
		if(tail->mid == mid){
			if(tail->qos != qos){
				return MOSQ_ERR_PROTOCOL;
			}
			tail->state = state;
			tail->timestamp = mosquitto_time();
			return MOSQ_ERR_SUCCESS;
		}
	}
	return MOSQ_ERR_NOT_FOUND;
}


void db__messages_delete_list(struct mosquitto_db *db, struct mosquitto_client_msg **head)
{
	struct mosquitto_client_msg *tail, *tmp;

	DL_FOREACH_SAFE(*head, tail, tmp){
		DL_DELETE(*head, tail);
		db__msg_store_ref_dec(db, &tail->store);
		mosquitto_property_free_all(&tail->properties);
		mosquitto__free(tail);
	}
	*head = NULL;
}


int db__messages_delete(struct mosquitto_db *db, struct mosquitto *context)
{
	if(!context) return MOSQ_ERR_INVAL;

	db__messages_delete_list(db, &context->msgs_in.inflight);
	db__messages_delete_list(db, &context->msgs_in.queued);
	db__messages_delete_list(db, &context->msgs_out.inflight);
	db__messages_delete_list(db, &context->msgs_out.queued);

	context->msgs_in.msg_bytes = 0;
	context->msgs_in.msg_bytes12 = 0;
	context->msgs_in.msg_count = 0;
	context->msgs_in.msg_count12 = 0;

	context->msgs_out.msg_bytes = 0;
	context->msgs_out.msg_bytes12 = 0;
	context->msgs_out.msg_count = 0;
	context->msgs_out.msg_count12 = 0;

	return MOSQ_ERR_SUCCESS;
}

int db__messages_easy_queue(struct mosquitto_db *db, struct mosquitto *context, const char *topic, int qos, uint32_t payloadlen, const void *payload, int retain, uint32_t message_expiry_interval, mosquitto_property **properties)
{
	struct mosquitto_msg_store *stored;
	char *source_id;
	char *topic_heap;
	mosquitto__payload_uhpa payload_uhpa;
	mosquitto_property *local_properties = NULL;
	enum mosquitto_msg_origin origin;

	assert(db);

	payload_uhpa.ptr = NULL;

	if(!topic) return MOSQ_ERR_INVAL;
	topic_heap = mosquitto__strdup(topic);
	if(!topic_heap) return MOSQ_ERR_INVAL;

	if(db->config->retain_available == false){
		retain = 0;
	}

	if(UHPA_ALLOC(payload_uhpa, payloadlen) == 0){
		mosquitto__free(topic_heap);
		return MOSQ_ERR_NOMEM;
	}
	memcpy(UHPA_ACCESS(payload_uhpa, payloadlen), payload, payloadlen);

	if(context && context->id){
		source_id = context->id;
	}else{
		source_id = "";
	}
	if(properties){
		local_properties = *properties;
		*properties = NULL;
	}

	if(context){
		origin = mosq_mo_client;
	}else{
		origin = mosq_mo_broker;
	}
	if(db__message_store(db, context, 0, topic_heap, qos, payloadlen, &payload_uhpa, retain, &stored, message_expiry_interval, local_properties, 0, origin)) return 1;

	return sub__messages_queue(db, source_id, topic_heap, qos, retain, &stored);
}

/* This function requires topic to be allocated on the heap. Once called, it owns topic and will free it on error. Likewise payload and properties. */
int db__message_store(struct mosquitto_db *db, const struct mosquitto *source, uint16_t source_mid, char *topic, int qos, uint32_t payloadlen, mosquitto__payload_uhpa *payload, int retain, struct mosquitto_msg_store **stored, uint32_t message_expiry_interval, mosquitto_property *properties, dbid_t store_id, enum mosquitto_msg_origin origin)
{
	struct mosquitto_msg_store *temp = NULL;
	int rc = MOSQ_ERR_SUCCESS;

	assert(db);
	assert(stored);

	temp = mosquitto__calloc(1, sizeof(struct mosquitto_msg_store));
	if(!temp){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		rc = MOSQ_ERR_NOMEM;
		goto error;
	}

	temp->topic = NULL;
	temp->payload.ptr = NULL;

	temp->ref_count = 0;
	if(source && source->id){
		temp->source_id = mosquitto__strdup(source->id);
	}else{
		temp->source_id = mosquitto__strdup("");
	}
	if(!temp->source_id){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		rc = MOSQ_ERR_NOMEM;
		goto error;
	}

	if(source && source->username){
		temp->source_username = mosquitto__strdup(source->username);
		if(!temp->source_username){
			rc = MOSQ_ERR_NOMEM;
			goto error;
		}
	}
	if(source){
		temp->source_listener = source->listener;
	}
	temp->source_mid = source_mid;
	temp->mid = 0;
	temp->qos = qos;
	temp->retain = retain;
	temp->topic = topic;
	topic = NULL;
	temp->payloadlen = payloadlen;
	temp->properties = properties;
	temp->origin = origin;
	if(payloadlen){
		UHPA_MOVE(temp->payload, *payload, payloadlen);
	}else{
		temp->payload.ptr = NULL;
	}
	if(message_expiry_interval > 0){
		temp->message_expiry_time = time(NULL) + message_expiry_interval;
	}else{
		temp->message_expiry_time = 0;
	}

	temp->dest_ids = NULL;
	temp->dest_id_count = 0;
	db->msg_store_count++;
	db->msg_store_bytes += payloadlen;
	(*stored) = temp;

	if(!store_id){
		temp->db_id = ++db->last_db_id;
	}else{
		temp->db_id = store_id;
	}

	db__msg_store_add(db, temp);

	return MOSQ_ERR_SUCCESS;
error:
	mosquitto__free(topic);
	if(temp){
		mosquitto__free(temp->source_id);
		mosquitto__free(temp->source_username);
		mosquitto__free(temp->topic);
		mosquitto__free(temp);
	}
	mosquitto_property_free_all(&properties);
	UHPA_FREE(*payload, payloadlen);
	return rc;
}

int db__message_store_find(struct mosquitto *context, uint16_t mid, struct mosquitto_msg_store **stored)
{
	struct mosquitto_client_msg *tail;

	if(!context) return MOSQ_ERR_INVAL;

	*stored = NULL;
	DL_FOREACH(context->msgs_in.inflight, tail){
		if(tail->store->source_mid == mid){
			*stored = tail->store;
			return MOSQ_ERR_SUCCESS;
		}
	}

	DL_FOREACH(context->msgs_in.queued, tail){
		if(tail->store->source_mid == mid){
			*stored = tail->store;
			return MOSQ_ERR_SUCCESS;
		}
	}

	return 1;
}

/* Called on reconnect to set outgoing messages to a sensible state and force a
 * retry, and to set incoming messages to expect an appropriate retry. */
int db__message_reconnect_reset_outgoing(struct mosquitto_db *db, struct mosquitto *context)
{
	struct mosquitto_client_msg *msg, *tmp;

	context->msgs_out.msg_bytes = 0;
	context->msgs_out.msg_bytes12 = 0;
	context->msgs_out.msg_count = 0;
	context->msgs_out.msg_count12 = 0;
	context->msgs_out.inflight_quota = context->msgs_out.inflight_maximum;

	DL_FOREACH_SAFE(context->msgs_out.inflight, msg, tmp){
		context->msgs_out.msg_count++;
		context->msgs_out.msg_bytes += msg->store->payloadlen;
		if(msg->qos > 0){
			context->msgs_out.msg_count12++;
			context->msgs_out.msg_bytes12 += msg->store->payloadlen;
			util__decrement_send_quota(context);
		}

		switch(msg->qos){
			case 0:
				msg->state = mosq_ms_publish_qos0;
				break;
			case 1:
				msg->state = mosq_ms_publish_qos1;
				break;
			case 2:
				if(msg->state == mosq_ms_wait_for_pubcomp){
					msg->state = mosq_ms_resend_pubrel;
				}else{
					msg->state = mosq_ms_publish_qos2;
				}
				break;
		}
	}
	/* Messages received when the client was disconnected are put
	 * in the mosq_ms_queued state. If we don't change them to the
	 * appropriate "publish" state, then the queued messages won't
	 * get sent until the client next receives a message - and they
	 * will be sent out of order.
	 */
	DL_FOREACH_SAFE(context->msgs_out.queued, msg, tmp){
		context->msgs_out.msg_count++;
		context->msgs_out.msg_bytes += msg->store->payloadlen;
		if(msg->qos > 0){
			context->msgs_out.msg_count12++;
			context->msgs_out.msg_bytes12 += msg->store->payloadlen;
		}
		if(db__ready_for_flight(&context->msgs_out, msg->qos)){
			switch(msg->qos){
				case 0:
					msg->state = mosq_ms_publish_qos0;
					break;
				case 1:
					msg->state = mosq_ms_publish_qos1;
					break;
				case 2:
					msg->state = mosq_ms_publish_qos2;
					break;
			}
			db__message_dequeue_first(context, &context->msgs_out);
		}
	}

	return MOSQ_ERR_SUCCESS;
}


/* Called on reconnect to set incoming messages to expect an appropriate retry. */
int db__message_reconnect_reset_incoming(struct mosquitto_db *db, struct mosquitto *context)
{
	struct mosquitto_client_msg *msg, *tmp;

	context->msgs_in.msg_bytes = 0;
	context->msgs_in.msg_bytes12 = 0;
	context->msgs_in.msg_count = 0;
	context->msgs_in.msg_count12 = 0;
	context->msgs_in.inflight_quota = context->msgs_in.inflight_maximum;

	DL_FOREACH_SAFE(context->msgs_in.inflight, msg, tmp){
		context->msgs_in.msg_count++;
		context->msgs_in.msg_bytes += msg->store->payloadlen;
		if(msg->qos > 0){
			context->msgs_in.msg_count12++;
			context->msgs_in.msg_bytes12 += msg->store->payloadlen;
			util__decrement_receive_quota(context);
		}

		if(msg->qos != 2){
			/* Anything <QoS 2 can be completely retried by the client at
			 * no harm. */
			db__message_remove(db, &context->msgs_in, msg);
		}else{
			/* Message state can be preserved here because it should match
			 * whatever the client has got. */
		}
	}

	/* Messages received when the client was disconnected are put
	 * in the mosq_ms_queued state. If we don't change them to the
	 * appropriate "publish" state, then the queued messages won't
	 * get sent until the client next receives a message - and they
	 * will be sent out of order.
	 */
	DL_FOREACH_SAFE(context->msgs_in.queued, msg, tmp){
		context->msgs_in.msg_count++;
		context->msgs_in.msg_bytes += msg->store->payloadlen;
		if(msg->qos > 0){
			context->msgs_in.msg_count12++;
			context->msgs_in.msg_bytes12 += msg->store->payloadlen;
		}
		if(db__ready_for_flight(&context->msgs_in, msg->qos)){
			switch(msg->qos){
				case 0:
					msg->state = mosq_ms_publish_qos0;
					break;
				case 1:
					msg->state = mosq_ms_publish_qos1;
					break;
				case 2:
					msg->state = mosq_ms_publish_qos2;
					break;
			}
			db__message_dequeue_first(context, &context->msgs_in);
		}
	}

	return MOSQ_ERR_SUCCESS;
}


int db__message_reconnect_reset(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;

	rc = db__message_reconnect_reset_outgoing(db, context);
	if(rc) return rc;
	return db__message_reconnect_reset_incoming(db, context);
}


int db__message_release_incoming(struct mosquitto_db *db, struct mosquitto *context, uint16_t mid)
{
	struct mosquitto_client_msg *tail, *tmp;
	int retain;
	char *topic;
	char *source_id;
	int msg_index = 0;
	bool deleted = false;
	int rc;

	if(!context) return MOSQ_ERR_INVAL;

	DL_FOREACH_SAFE(context->msgs_in.inflight, tail, tmp){
		msg_index++;
		if(tail->mid == mid){
			if(tail->store->qos != 2){
				return MOSQ_ERR_PROTOCOL;
			}
			topic = tail->store->topic;
			retain = tail->retain;
			source_id = tail->store->source_id;

			/* topic==NULL should be a QoS 2 message that was
			 * denied/dropped and is being processed so the client doesn't
			 * keep resending it. That means we don't send it to other
			 * clients. */
			if(!topic){
				db__message_remove(db, &context->msgs_in, tail);
				deleted = true;
			}else{
				rc = sub__messages_queue(db, source_id, topic, 2, retain, &tail->store);
				if(rc == MOSQ_ERR_SUCCESS || rc == MOSQ_ERR_NO_SUBSCRIBERS){
					db__message_remove(db, &context->msgs_in, tail);
					deleted = true;
				}else{
					return 1;
				}
			}
		}
	}

	DL_FOREACH_SAFE(context->msgs_in.queued, tail, tmp){
		if(context->msgs_in.inflight_maximum != 0 && msg_index >= context->msgs_in.inflight_maximum){
			break;
		}

		msg_index++;
		tail->timestamp = mosquitto_time();

		if(tail->qos == 2){
			send__pubrec(context, tail->mid, 0);
			tail->state = mosq_ms_wait_for_pubrel;
			db__message_dequeue_first(context, &context->msgs_in);
		}
	}
	if(deleted){
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_NOT_FOUND;
	}
}

int db__message_write(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;
	struct mosquitto_client_msg *tail, *tmp;
	uint16_t mid;
	int retries;
	int retain;
	const char *topic;
	int qos;
	uint32_t payloadlen;
	const void *payload;
	int msg_count = 0;
	mosquitto_property *cmsg_props = NULL, *store_props = NULL;
	time_t now = 0;
	uint32_t expiry_interval;

	if(!context || context->sock == INVALID_SOCKET
			|| (context->state == mosq_cs_active && !context->id)){
		return MOSQ_ERR_INVAL;
	}

	if(context->state != mosq_cs_active){
		return MOSQ_ERR_SUCCESS;
	}

	DL_FOREACH_SAFE(context->msgs_in.inflight, tail, tmp){
		msg_count++;
		if(tail->store->message_expiry_time){
			if(now == 0){
				now = time(NULL);
			}
			if(now > tail->store->message_expiry_time){
				/* Message is expired, must not send. */
				db__message_remove(db, &context->msgs_in, tail);
				continue;
			}
		}
		mid = tail->mid;

		switch(tail->state){
			case mosq_ms_send_pubrec:
				rc = send__pubrec(context, mid, 0);
				if(!rc){
					tail->state = mosq_ms_wait_for_pubrel;
				}else{
					return rc;
				}
				break;

			case mosq_ms_resend_pubcomp:
				rc = send__pubcomp(context, mid);
				if(!rc){
					tail->state = mosq_ms_wait_for_pubrel;
				}else{
					return rc;
				}
				break;

			case mosq_ms_invalid:
			case mosq_ms_publish_qos0:
			case mosq_ms_publish_qos1:
			case mosq_ms_publish_qos2:
			case mosq_ms_resend_pubrel:
			case mosq_ms_wait_for_puback:
			case mosq_ms_wait_for_pubrec:
			case mosq_ms_wait_for_pubrel:
			case mosq_ms_wait_for_pubcomp:
			case mosq_ms_queued:
				break;
		}
	}

	DL_FOREACH_SAFE(context->msgs_out.inflight, tail, tmp){
		msg_count++;
		if(tail->store->message_expiry_time){
			if(now == 0){
				now = time(NULL);
			}
			if(now > tail->store->message_expiry_time){
				/* Message is expired, must not send. */
				db__message_remove(db, &context->msgs_out, tail);
				continue;
			}else{
				expiry_interval = tail->store->message_expiry_time - now;
			}
		}else{
			expiry_interval = 0;
		}
		mid = tail->mid;
		retries = tail->dup;
		retain = tail->retain;
		topic = tail->store->topic;
		qos = tail->qos;
		payloadlen = tail->store->payloadlen;
		payload = UHPA_ACCESS_PAYLOAD(tail->store);
		cmsg_props = tail->properties;
		store_props = tail->store->properties;

		switch(tail->state){
			case mosq_ms_publish_qos0:
				rc = send__publish(context, mid, topic, payloadlen, payload, qos, retain, retries, cmsg_props, store_props, expiry_interval);
				if(rc == MOSQ_ERR_SUCCESS || rc == MOSQ_ERR_OVERSIZE_PACKET){
					db__message_remove(db, &context->msgs_out, tail);
				}else{
					return rc;
				}
				break;

			case mosq_ms_publish_qos1:
				rc = send__publish(context, mid, topic, payloadlen, payload, qos, retain, retries, cmsg_props, store_props, expiry_interval);
				if(rc == MOSQ_ERR_SUCCESS){
					tail->timestamp = mosquitto_time();
					tail->dup = 1; /* Any retry attempts are a duplicate. */
					tail->state = mosq_ms_wait_for_puback;
				}else if(rc == MOSQ_ERR_OVERSIZE_PACKET){
					db__message_remove(db, &context->msgs_out, tail);
				}else{
					return rc;
				}
				break;

			case mosq_ms_publish_qos2:
				rc = send__publish(context, mid, topic, payloadlen, payload, qos, retain, retries, cmsg_props, store_props, expiry_interval);
				if(rc == MOSQ_ERR_SUCCESS){
					tail->timestamp = mosquitto_time();
					tail->dup = 1; /* Any retry attempts are a duplicate. */
					tail->state = mosq_ms_wait_for_pubrec;
				}else if(rc == MOSQ_ERR_OVERSIZE_PACKET){
					db__message_remove(db, &context->msgs_out, tail);
				}else{
					return rc;
				}
				break;

			case mosq_ms_resend_pubrel:
				rc = send__pubrel(context, mid);
				if(!rc){
					tail->state = mosq_ms_wait_for_pubcomp;
				}else{
					return rc;
				}
				break;

			case mosq_ms_invalid:
			case mosq_ms_send_pubrec:
			case mosq_ms_resend_pubcomp:
			case mosq_ms_wait_for_puback:
			case mosq_ms_wait_for_pubrec:
			case mosq_ms_wait_for_pubrel:
			case mosq_ms_wait_for_pubcomp:
			case mosq_ms_queued:
				break;
		}
	}

	DL_FOREACH_SAFE(context->msgs_in.queued, tail, tmp){
		if(context->msgs_out.inflight_maximum != 0 && context->msgs_in.inflight_quota == 0){
			break;
		}

		msg_count++;

		if(tail->qos == 2){
			tail->state = mosq_ms_send_pubrec;
			db__message_dequeue_first(context, &context->msgs_in);
			rc = send__pubrec(context, tail->mid, 0);
			if(!rc){
				tail->state = mosq_ms_wait_for_pubrel;
			}else{
				return rc;
			}
		}
	}

	DL_FOREACH_SAFE(context->msgs_out.queued, tail, tmp){
		if(context->msgs_out.inflight_maximum != 0 && context->msgs_out.inflight_quota == 0){
			break;
		}

		msg_count++;

		switch(tail->qos){
			case 0:
				tail->state = mosq_ms_publish_qos0;
				break;
			case 1:
				tail->state = mosq_ms_publish_qos1;
				break;
			case 2:
				tail->state = mosq_ms_publish_qos2;
				break;
		}
		db__message_dequeue_first(context, &context->msgs_out);
	}

	return MOSQ_ERR_SUCCESS;
}

void db__limits_set(unsigned long inflight_bytes, int queued, unsigned long queued_bytes)
{
	max_inflight_bytes = inflight_bytes;
	max_queued = queued;
	max_queued_bytes = queued_bytes;
}

