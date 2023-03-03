/*
Copyright (c) 2016-2021 Roger Light <roger@atchoo.org>

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

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "send_mosq.h"
#include "util_mosq.h"
#include "will_mosq.h"
#include "utlist.h"
#include "will_mosq.h"

#ifdef WITH_TLS
#  include <openssl/ssl.h>
#endif

BROKER_EXPORT int mosquitto_plugin_set_info(mosquitto_plugin_id_t *identifier,
		const char *plugin_name,
		const char *plugin_version)
{
	if(identifier == NULL || plugin_name == NULL){
		return MOSQ_ERR_INVAL;
	}

	identifier->plugin_name = mosquitto_strdup(plugin_name);
	if(plugin_version){
		identifier->plugin_version = mosquitto_strdup(plugin_version);
	}else{
		identifier->plugin_version = NULL;
	}

	return MOSQ_ERR_SUCCESS;
}


BROKER_EXPORT const char *mosquitto_client_address(const struct mosquitto *client)
{
	if(client){
		return client->address;
	}else{
		return NULL;
	}
}


BROKER_EXPORT struct mosquitto *mosquitto_client(const char *clientid)
{
	size_t len;
	struct mosquitto *context;

	if(!clientid) return NULL;
	len = strlen(clientid);
	if(len == 0) return NULL;

	HASH_FIND(hh_id, db.contexts_by_id, clientid, strlen(clientid), context);

	return context;
}


BROKER_EXPORT int mosquitto_client_port(const struct mosquitto *client)
{
	if(client && client->listener){
		return client->listener->port;
	}else{
		return 0;
	}
}


BROKER_EXPORT bool mosquitto_client_clean_session(const struct mosquitto *client)
{
	if(client){
		return client->clean_start;
	}else{
		return true;
	}
}


BROKER_EXPORT const char *mosquitto_client_id(const struct mosquitto *client)
{
	if(client){
		return client->id;
	}else{
		return NULL;
	}
}


BROKER_EXPORT int mosquitto_client_keepalive(const struct mosquitto *client)
{
	if(client){
		return client->keepalive;
	}else{
		return -1;
	}
}


BROKER_EXPORT void *mosquitto_client_certificate(const struct mosquitto *client)
{
#ifdef WITH_TLS
	if(client && client->ssl){
		return SSL_get_peer_certificate(client->ssl);
	}else{
		return NULL;
	}
#else
	UNUSED(client);

	return NULL;
#endif
}


BROKER_EXPORT int mosquitto_client_protocol(const struct mosquitto *client)
{
#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_LWS
	if(client && client->wsi){
		return mp_websockets;
	}else
#elif defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_BUILTIN
	if(client && client->transport == mosq_t_ws){
		return mp_websockets;
	}else
#else
	UNUSED(client);
#endif
	{
		return mp_mqtt;
	}
}


BROKER_EXPORT int mosquitto_client_protocol_version(const struct mosquitto *client)
{
	if(client){
		switch(client->protocol){
			case mosq_p_mqtt31:
				return 3;
			case mosq_p_mqtt311:
				return 4;
			case mosq_p_mqtt5:
				return 5;
			default:
				return 0;
		}
	}else{
		return 0;
	}
}


BROKER_EXPORT int mosquitto_client_sub_count(const struct mosquitto *client)
{
	if(client){
		return client->subs_count;
	}else{
		return 0;
	}
}


BROKER_EXPORT const char *mosquitto_client_username(const struct mosquitto *client)
{
	if(client){
#ifdef WITH_BRIDGE
		if(client->bridge){
			return client->bridge->local_username;
		}else
#endif
		{
			return client->username;
		}
	}else{
		return NULL;
	}
}


BROKER_EXPORT int mosquitto_broker_publish(
		const char *clientid,
		const char *topic,
		int payloadlen,
		void *payload,
		int qos,
		bool retain,
		mosquitto_property *properties)
{
	struct mosquitto__message_v5 *msg;

	if(topic == NULL
			|| payloadlen < 0
			|| (payloadlen > 0 && payload == NULL)
			|| qos < 0 || qos > 2){

		return MOSQ_ERR_INVAL;
	}

	msg = mosquitto__malloc(sizeof(struct mosquitto__message_v5));
	if(msg == NULL) return MOSQ_ERR_NOMEM;

	msg->next = NULL;
	msg->prev = NULL;
	if(clientid){
		msg->clientid = mosquitto__strdup(clientid);
		if(msg->clientid == NULL){
			mosquitto__FREE(msg);
			return MOSQ_ERR_NOMEM;
		}
	}else{
		msg->clientid = NULL;
	}
	msg->topic = mosquitto__strdup(topic);
	if(msg->topic == NULL){
		mosquitto__FREE(msg->clientid);
		mosquitto__FREE(msg);
		return MOSQ_ERR_NOMEM;
	}
	msg->payloadlen = payloadlen;
	msg->payload = payload;
	msg->qos = qos;
	msg->retain = retain;
	msg->properties = properties;

	DL_APPEND(db.plugin_msgs, msg);

	loop__update_next_event(1);
	return MOSQ_ERR_SUCCESS;
}


BROKER_EXPORT int mosquitto_broker_publish_copy(
		const char *clientid,
		const char *topic,
		int payloadlen,
		const void *payload,
		int qos,
		bool retain,
		mosquitto_property *properties)
{
	void *payload_out;
	int rc;

	if(topic == NULL
			|| payloadlen < 0
			|| (payloadlen > 0 && payload == NULL)
			|| qos < 0 || qos > 2){

		return MOSQ_ERR_INVAL;
	}

	payload_out = calloc(1, (size_t)(payloadlen+1));
	if(payload_out == NULL){
		return MOSQ_ERR_NOMEM;
	}
	memcpy(payload_out, payload, (size_t)payloadlen);

	rc = mosquitto_broker_publish(
			clientid,
			topic,
			payloadlen,
			payload_out,
			qos,
			retain,
			properties);

	if(rc){
		SAFE_FREE(payload_out);
	}
	return rc;
}


BROKER_EXPORT int mosquitto_set_username(struct mosquitto *client, const char *username)
{
	char *u_dup;
	char *old;
	int rc;

	if(!client) return MOSQ_ERR_INVAL;

	if(username){
		u_dup = mosquitto__strdup(username);
		if(!u_dup) return MOSQ_ERR_NOMEM;
	}else{
		u_dup = NULL;
	}

	old = client->username;
	client->username = u_dup;

	rc = acl__find_acls(client);
	if(rc){
		client->username = old;
		mosquitto__FREE(u_dup);
		return rc;
	}else{
		mosquitto__FREE(old);
		return MOSQ_ERR_SUCCESS;
	}
}

BROKER_EXPORT int mosquitto_set_clientid(struct mosquitto *client, const char *clientid)
{
	struct mosquitto *found_client;
    char *id_dup;
	bool in_by_id;
	int clientid_len;

    if(!client || !clientid) return MOSQ_ERR_INVAL;

	in_by_id = client->in_by_id;
	/* If in_by_id is true, then this client has already authenticated and
	 * completed the connection flow. This means it *cannot* take over an
	 * existing session, and we must remove/add it to the by_id hash table.
	 *
	 * If in_by_id is false, then this client is currently going through
	 * authentication and so it is safe to change the client id to any value
	 * because it will be checked after authentication.
	 */

	if(in_by_id){
		HASH_FIND(hh_id, db.contexts_by_id, clientid, strlen(clientid), found_client);
		if(found_client){
			return MOSQ_ERR_ALREADY_EXISTS;
		}
	}

    clientid_len = (int)strlen(clientid);
    if(mosquitto_validate_utf8(clientid, clientid_len)){
        return MOSQ_ERR_INVAL;
    }

    id_dup = mosquitto__strdup(clientid);
    if(!id_dup) return MOSQ_ERR_NOMEM;

	if(in_by_id){
		context__remove_from_by_id(client);
	}
	mosquitto__free(client->id);
	client->id = id_dup;
	if(in_by_id){
		context__add_to_by_id(client);
	}

    return MOSQ_ERR_SUCCESS;
}

/* Check to see whether durable clients still have rights to their subscriptions. */
static void check_subscription_acls(struct mosquitto *context)
{
	int i;
	int rc;
	uint8_t reason;

	for(i=0; i<context->subs_capacity; i++){
		if(context->subs[i] == NULL){
			continue;
		}
		rc = mosquitto_acl_check(context,
				context->subs[i]->topic_filter,
				0,
				NULL,
				0, /* FIXME */
				false,
				MOSQ_ACL_SUBSCRIBE);

		if(rc != MOSQ_ERR_SUCCESS){
			sub__remove(context, context->subs[i]->topic_filter, &reason);
		}
	}
}



static void disconnect_client(struct mosquitto *context, bool with_will)
{
	if(context->protocol == mosq_p_mqtt5){
		send__disconnect(context, MQTT_RC_ADMINISTRATIVE_ACTION, NULL);
	}
	if(with_will == false){
		mosquitto__set_state(context, mosq_cs_disconnecting);
	}
	if(context->session_expiry_interval > 0){
		check_subscription_acls(context);
	}
	do_disconnect(context, MOSQ_ERR_ADMINISTRATIVE_ACTION);
}

BROKER_EXPORT int mosquitto_kick_client_by_clientid(const char *clientid, bool with_will)
{
	struct mosquitto *ctxt, *ctxt_tmp;

	if(clientid == NULL){
		HASH_ITER(hh_sock, db.contexts_by_sock, ctxt, ctxt_tmp){
			disconnect_client(ctxt, with_will);
		}
		return MOSQ_ERR_SUCCESS;
	}else{
		HASH_FIND(hh_id, db.contexts_by_id, clientid, strlen(clientid), ctxt);
		if(ctxt){
			disconnect_client(ctxt, with_will);
			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_NOT_FOUND;
		}
	}
}

BROKER_EXPORT int mosquitto_kick_client_by_username(const char *username, bool with_will)
{
	struct mosquitto *ctxt, *ctxt_tmp;

	if(username == NULL){
		HASH_ITER(hh_sock, db.contexts_by_sock, ctxt, ctxt_tmp){
			if(ctxt->username == NULL){
				disconnect_client(ctxt, with_will);
			}
		}
	}else{
		HASH_ITER(hh_sock, db.contexts_by_sock, ctxt, ctxt_tmp){
			if(ctxt->username != NULL && !strcmp(ctxt->username, username)){
				disconnect_client(ctxt, with_will);
			}
		}
	}
	return MOSQ_ERR_SUCCESS;
}

BROKER_EXPORT int mosquitto_apply_on_all_clients(int (*FUNC_client_functor)(const struct mosquitto *, void *), void *functor_context)
{
	int rc = MOSQ_ERR_SUCCESS;
	struct mosquitto *ctxt, *ctxt_tmp;

	HASH_ITER(hh_id, db.contexts_by_id, ctxt, ctxt_tmp){
		rc = (*FUNC_client_functor)(ctxt, functor_context);
		if(rc != MOSQ_ERR_SUCCESS){
			break;
		}
	}

	return rc;
}

BROKER_EXPORT int mosquitto_persist_client_add(struct mosquitto_client *client)
{
	struct mosquitto *context;
	int i;
	int rc;

	if(client == NULL){
		return MOSQ_ERR_INVAL;
	}
	if(client->clientid == NULL){
		rc = MOSQ_ERR_INVAL;
		goto error;
	}

	context = NULL;
	HASH_FIND(hh_id, db.contexts_by_id, client->clientid, strlen(client->clientid), context);
	if(context){
		rc = MOSQ_ERR_INVAL;
		goto error;
	}

	context = context__init();
	if(!context){
		rc = MOSQ_ERR_NOMEM;
		goto error;
	}

	context->id = client->clientid;
	client->clientid = NULL;
	context->username = client->username;
	client->username = NULL;
	context->auth_method = client->auth_method;
	client->auth_method = NULL;

	context->clean_start = false;
	context->will_delay_time = client->will_delay_time;
	context->session_expiry_time = client->session_expiry_time;
	context->will_delay_interval = client->will_delay_interval;
	context->session_expiry_interval = client->session_expiry_interval;
	context->max_qos = client->max_qos;
	context->maximum_packet_size = client->max_packet_size;
	context->retain_available = client->retain_available;
	context->is_persisted = true;

	/* in per_listener_settings mode, try to find the listener by persisted port */
	if(db.config->per_listener_settings && client->listener_port > 0){
		for(i=0; i < db.config->listener_count; i++){
			if(db.config->listeners[i].port == client->listener_port){
				context->listener = &db.config->listeners[i];
				break;
			}
		}
	}

	context__add_to_by_id(context);

	return MOSQ_ERR_SUCCESS;
error:
	SAFE_FREE(client->clientid);
	SAFE_FREE(client->username);
	SAFE_FREE(client->auth_method);
	return rc;
}


BROKER_EXPORT int mosquitto_persist_client_update(struct mosquitto_client *client)
{
	struct mosquitto *context;
	int i;
	int rc;

	if(client == NULL){
		return MOSQ_ERR_INVAL;
	}
	if(client->clientid == NULL){
		rc = MOSQ_ERR_INVAL;
		goto error;
	}

	context = NULL;
	HASH_FIND(hh_id, db.contexts_by_id, client->clientid, strlen(client->clientid), context);
	if(context == NULL){
		rc = MOSQ_ERR_NOT_FOUND;
		goto error;
	}

	mosquitto_free(context->username);
	context->username = client->username;
	client->username = NULL;

	context->clean_start = false;
	context->will_delay_time = client->will_delay_time;
	context->session_expiry_time = client->session_expiry_time;
	context->will_delay_interval = client->will_delay_interval;
	context->session_expiry_interval = client->session_expiry_interval;
	context->max_qos = client->max_qos;
	context->maximum_packet_size = client->max_packet_size;
	context->retain_available = client->retain_available;

	/* in per_listener_settings mode, try to find the listener by persisted port */
	if(db.config->per_listener_settings && client->listener_port > 0){
		for(i=0; i < db.config->listener_count; i++){
			if(db.config->listeners[i].port == client->listener_port){
				context->listener = &db.config->listeners[i];
				break;
			}
		}
	}

	return MOSQ_ERR_SUCCESS;
error:
	SAFE_FREE(client->username);
	return rc;
}


BROKER_EXPORT int mosquitto_persist_client_delete(const char *clientid)
{
	struct mosquitto *context;

	if(clientid == NULL) return MOSQ_ERR_INVAL;

	context = NULL;
	HASH_FIND(hh_id, db.contexts_by_id, clientid, strlen(clientid), context);
	if(context == NULL){
		return MOSQ_ERR_SUCCESS;
	}

	session_expiry__remove(context);
	will_delay__remove(context);
	will__clear(context);

	context->clean_start = true;
	context->session_expiry_interval = 0;
	context->is_persisted = false;
	mosquitto__set_state(context, mosq_cs_duplicate);
	do_disconnect(context, MOSQ_ERR_SUCCESS);

	return MOSQ_ERR_SUCCESS;
}


static struct mosquitto__base_msg *find_store_msg(uint64_t store_id)
{
	struct mosquitto__base_msg *base_msg;

	HASH_FIND(hh, db.msg_store, &store_id, sizeof(store_id), base_msg);
	return base_msg;
}

BROKER_EXPORT int mosquitto_persist_client_msg_add(struct mosquitto_client_msg *client_msg)
{
	struct mosquitto *context;
	struct mosquitto__base_msg *base_msg;

	if(client_msg == NULL || client_msg->clientid == NULL){
		return MOSQ_ERR_INVAL;
	}

	HASH_FIND(hh_id, db.contexts_by_id, client_msg->clientid, strlen(client_msg->clientid), context);
	if(context == NULL){
		return MOSQ_ERR_NOT_FOUND;
	}
	base_msg = find_store_msg(client_msg->store_id);
	if(base_msg == NULL){
		return MOSQ_ERR_NOT_FOUND;
	}

	if(client_msg->direction == mosq_md_out){
		if(client_msg->qos > 0){
			context->last_mid = client_msg->mid;
		}
		return db__message_insert_outgoing(context, client_msg->cmsg_id, client_msg->mid,
				client_msg->qos, client_msg->retain,
				base_msg, client_msg->subscription_identifier, false, false);
	}else if(client_msg->direction == mosq_md_in){
		return db__message_insert_incoming(context, client_msg->cmsg_id, base_msg, false);
	}else{
		return MOSQ_ERR_INVAL;
	}
	return MOSQ_ERR_SUCCESS;
}


BROKER_EXPORT int mosquitto_persist_client_msg_delete(struct mosquitto_client_msg *client_msg)
{
	struct mosquitto *context;

	if(client_msg == NULL || client_msg->clientid == NULL) return MOSQ_ERR_INVAL;

	HASH_FIND(hh_id, db.contexts_by_id, client_msg->clientid, strlen(client_msg->clientid), context);
	if(context == NULL){
		return MOSQ_ERR_NOT_FOUND;
	}

	if(client_msg->direction == mosq_md_out){
		return db__message_delete_outgoing(context, client_msg->mid, client_msg->state, client_msg->qos);
	}else if(client_msg->direction == mosq_md_in){
		return db__message_remove_incoming(context, client_msg->mid);
	}else{
		return MOSQ_ERR_INVAL;
	}
	return MOSQ_ERR_SUCCESS;
}


BROKER_EXPORT int mosquitto_persist_client_msg_update(struct mosquitto_client_msg *client_msg)
{
	struct mosquitto *context;

	if(client_msg == NULL || client_msg->clientid == NULL) return MOSQ_ERR_INVAL;

	HASH_FIND(hh_id, db.contexts_by_id, client_msg->clientid, strlen(client_msg->clientid), context);
	if(context == NULL){
		return MOSQ_ERR_NOT_FOUND;
	}

	if(client_msg->direction == mosq_md_out){
		db__message_update_outgoing(context, client_msg->mid, client_msg->state, client_msg->qos, false);
	}else if(client_msg->direction == mosq_md_in){
		// FIXME db__message_update_incoming(context, client_msg->mid, client_msg->state, client_msg->qos, false);
	}else{
		return MOSQ_ERR_INVAL;
	}
	return MOSQ_ERR_SUCCESS;
}


BROKER_EXPORT int mosquitto_persist_client_msg_clear(struct mosquitto_client_msg *client_msg)
{
	struct mosquitto *context;

	if(client_msg == NULL || client_msg->clientid == NULL) return MOSQ_ERR_INVAL;

	HASH_FIND(hh_id, db.contexts_by_id, client_msg->clientid, strlen(client_msg->clientid), context);
	if(context == NULL){
		return MOSQ_ERR_NOT_FOUND;
	}

	if(client_msg->direction == mosq_bmd_in || client_msg->direction == mosq_bmd_all){
		db__messages_delete_incoming(context);
	}else if(client_msg->direction == mosq_bmd_out || client_msg->direction == mosq_bmd_all){
		db__messages_delete_outgoing(context);
	}
	return MOSQ_ERR_SUCCESS;
}


BROKER_EXPORT int mosquitto_subscription_add(const struct mosquitto_subscription *sub)
{
	struct mosquitto *context;

	if(sub == NULL || sub->clientid == NULL || sub->topic_filter == NULL || sub->clientid[0] == '\0' || sub->topic_filter[0] == '\0'){
		return MOSQ_ERR_INVAL;
	}

	HASH_FIND(hh_id, db.contexts_by_id, sub->clientid, strlen(sub->clientid), context);

	if(context){
		return sub__add(context, sub);
	}else{
		return MOSQ_ERR_NOT_FOUND;
	}
}


BROKER_EXPORT int mosquitto_subscription_delete(const char *clientid, const char *topic)
{
	struct mosquitto *context;
	uint8_t reason;

	if(clientid == NULL || topic == NULL || clientid[0] == '\0' || topic[0] == '\0'){
		return MOSQ_ERR_INVAL;
	}

	HASH_FIND(hh_id, db.contexts_by_id, clientid, strlen(clientid), context);

	if(context){
		return sub__remove(context, topic, &reason);
	}else{
		return MOSQ_ERR_NOT_FOUND;
	}
}


BROKER_EXPORT int mosquitto_persist_base_msg_add(struct mosquitto_base_msg *msg_add)
{
	struct mosquitto context;
	struct mosquitto__base_msg *base_msg;
	uint32_t message_expiry_interval;
	time_t message_expiry_interval_tt;
	int i;
	int rc;

	memset(&context, 0, sizeof(context));

	if(msg_add->payloadlen > MQTT_MAX_PAYLOAD){
		return MOSQ_ERR_INVAL;
	}

	/* db__message_store only takes a copy of .id and .username, so it is reasonably safe
	 * to cast the const char * to char * */
	context.id = (char *)msg_add->source_id;
	context.username = (char *)msg_add->source_username;

	if(msg_add->expiry_time == 0){
		message_expiry_interval = 0;
	}else if(msg_add->expiry_time <= db.now_real_s){
		message_expiry_interval = 1;
	}else{
		message_expiry_interval_tt = msg_add->expiry_time - db.now_real_s;
		if(message_expiry_interval_tt > UINT32_MAX){
			message_expiry_interval = UINT32_MAX;
		}else{
			/* coverity[store_truncates_time_t] - we check above whether the value will fit in a uint32_t */
			message_expiry_interval = (uint32_t)message_expiry_interval_tt;
		}
	}

	base_msg = mosquitto_calloc(1, sizeof(struct mosquitto__base_msg));
	if(base_msg == NULL){
		goto error;
	}
	base_msg->data.store_id = msg_add->store_id;
	base_msg->data.payloadlen = msg_add->payloadlen;
	base_msg->data.source_mid = msg_add->source_mid;
	base_msg->data.qos = msg_add->qos;
	base_msg->data.retain = msg_add->retain;

	base_msg->data.payload = msg_add->payload;
	msg_add->payload = NULL;
	base_msg->data.topic = msg_add->topic;
	msg_add->topic = NULL;
	base_msg->data.properties = msg_add->properties;
	msg_add->properties = NULL;

	if(msg_add->source_port){
		for(i=0; i<db.config->listener_count; i++){
			if(db.config->listeners[i].port == msg_add->source_port){
				base_msg->source_listener = &db.config->listeners[i];
				break;
			}
		}
	}

	base_msg->stored = true;
	rc = db__message_store(&context, base_msg, message_expiry_interval, mosq_mo_broker);
	return rc;

error:
	mosquitto_property_free_all(&msg_add->properties);
	mosquitto_free(msg_add->topic);
	mosquitto_free(msg_add->payload);
	mosquitto_free(base_msg);

	return MOSQ_ERR_NOMEM;
}


BROKER_EXPORT int mosquitto_persist_base_msg_delete(uint64_t store_id)
{
	struct mosquitto__base_msg *base_msg;

	base_msg = find_store_msg(store_id);
	if(base_msg && base_msg->ref_count == 0){
		/* If ref count is zero, then we should delete this. It might seem
		 * surprising that the ref count is zero already, but it can be. If ref
		 * count is greater than zero then there may be e.g. a retained message
		 * still referring to this and the retained message persist update is
		 * coming later. If we delete the message now in that case, then when
		 * the retain changes there will be use after free errors. All messages
		 * will eventually hit ref count 0 and be removed in some way or other.
		 */
		db__msg_store_remove(base_msg, false);
	}

	return MOSQ_ERR_SUCCESS;
}


BROKER_EXPORT void mosquitto_complete_basic_auth(const char *clientid, int result)
{
	struct mosquitto *context;

	if(clientid == NULL) return;

	HASH_FIND(hh_id, db.contexts_by_id_delayed_auth, clientid, strlen(clientid), context);
	if(context){
		HASH_DELETE(hh_id, db.contexts_by_id_delayed_auth, context);
		if(result == MOSQ_ERR_SUCCESS){
			connect__on_authorised(context, NULL, 0);
		}else{
			if(context->protocol == mosq_p_mqtt5){
				send__connack(context, 0, MQTT_RC_NOT_AUTHORIZED, NULL);
			}else{
				send__connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED, NULL);
			}
			context->clean_start = true;
			context->session_expiry_interval = 0;
			will__clear(context);
			do_disconnect(context, MOSQ_ERR_AUTH);
		}
	}
}

BROKER_EXPORT int mosquitto_broker_node_id_set(uint16_t id)
{
	if(id > 1023){
		return MOSQ_ERR_INVAL;
	}else{
		db.node_id = id;
		db.node_id_shifted = ((uint64_t)id) << 54;
		return MOSQ_ERR_SUCCESS;
	}
}

BROKER_EXPORT const char *mosquitto_persistence_location(void)
{
	return db.config->persistence_location;
}
