/*
Copyright (c) 2021 Roger Light <roger@atchoo.org>

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
#include "mosquitto_internal.h"
#include "mosquitto_broker.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "send_mosq.h"
#include "util_mosq.h"
#include "utlist.h"
#include "lib_load.h"
#include "will_mosq.h"
#include <stdint.h>


void plugin_persist__handle_restore(void)
{
	struct mosquitto_evt_persist_restore event_data;
	struct mosquitto__callback *cb_base, *cb_next;
	struct mosquitto__security_options *opts;

	opts = &db.config->security_options;
	memset(&event_data, 0, sizeof(event_data));

	DL_FOREACH_SAFE(opts->plugin_callbacks.persist_restore, cb_base, cb_next){
		cb_base->cb(MOSQ_EVT_PERSIST_RESTORE, &event_data, cb_base->userdata);
	}
}


void plugin_persist__handle_client_add(struct mosquitto *context)
{
	struct mosquitto_evt_persist_client event_data;
	struct mosquitto__callback *cb_base, *cb_next;
	struct mosquitto__security_options *opts;
	struct mosquitto_message_v5 will;

	UNUSED(will); /* FIXME */

	if(db.shutdown || context->is_persisted) return;

	opts = &db.config->security_options;
	memset(&event_data, 0, sizeof(event_data));
	event_data.data.clientid = context->id;
	event_data.data.username = context->username;
	event_data.data.auth_method = context->auth_method;
	event_data.data.will_delay_time = context->will_delay_time;
	event_data.data.session_expiry_time = context->session_expiry_time;
	event_data.data.will_delay_interval = context->will_delay_interval;
	event_data.data.session_expiry_interval = context->session_expiry_interval;
	if(context->listener){
		event_data.data.listener_port = context->listener->port;
	}else{
		event_data.data.listener_port = 0;
	}
	event_data.data.max_qos = context->max_qos;
	event_data.data.retain_available = context->retain_available;
	event_data.data.max_packet_size = context->maximum_packet_size;

	DL_FOREACH_SAFE(opts->plugin_callbacks.persist_client_add, cb_base, cb_next){
		cb_base->cb(MOSQ_EVT_PERSIST_CLIENT_ADD, &event_data, cb_base->userdata);
	}
	context->is_persisted = true;
}


void plugin_persist__handle_client_update(struct mosquitto *context)
{
	struct mosquitto_evt_persist_client event_data;
	struct mosquitto__callback *cb_base, *cb_next;
	struct mosquitto__security_options *opts;
	struct mosquitto_message_v5 will;

	UNUSED(will); /* FIXME */

	if(db.shutdown) return;

	opts = &db.config->security_options;
	memset(&event_data, 0, sizeof(event_data));
	event_data.data.clientid = context->id;
	event_data.data.username = context->username;
	event_data.data.auth_method = context->auth_method;
	event_data.data.will_delay_time = context->will_delay_time;
	event_data.data.session_expiry_time = context->session_expiry_time;
	event_data.data.will_delay_interval = context->will_delay_interval;
	event_data.data.session_expiry_interval = context->session_expiry_interval;
	if(context->listener){
		event_data.data.listener_port = context->listener->port;
	}else{
		event_data.data.listener_port = 0;
	}
	event_data.data.max_qos = context->max_qos;
	event_data.data.retain_available = context->retain_available;
	event_data.data.max_packet_size = context->maximum_packet_size;

	DL_FOREACH_SAFE(opts->plugin_callbacks.persist_client_update, cb_base, cb_next){
		cb_base->cb(MOSQ_EVT_PERSIST_CLIENT_UPDATE, &event_data, cb_base->userdata);
	}
}


void plugin_persist__handle_client_delete(struct mosquitto *context)
{
	struct mosquitto_evt_persist_client event_data;
	struct mosquitto__callback *cb_base, *cb_next;
	struct mosquitto__security_options *opts;

	if(context->is_persisted == false
			|| context->session_expiry_interval > 0
			|| context->id == NULL
			|| context->state == mosq_cs_duplicate
			|| db.shutdown){

		return;
	}
	opts = &db.config->security_options;
	memset(&event_data, 0, sizeof(event_data));
	event_data.data.clientid = context->id;

	DL_FOREACH_SAFE(opts->plugin_callbacks.persist_client_delete, cb_base, cb_next){
		cb_base->cb(MOSQ_EVT_PERSIST_CLIENT_DELETE, &event_data, cb_base->userdata);
	}
	context->is_persisted = false;
}


void plugin_persist__handle_subscription_add(struct mosquitto *context, const struct mosquitto_subscription *sub)
{
	struct mosquitto_evt_persist_subscription event_data;
	struct mosquitto__callback *cb_base, *cb_next;
	struct mosquitto__security_options *opts;

	if(db.shutdown || context->is_persisted == false) return;

	opts = &db.config->security_options;
	memset(&event_data, 0, sizeof(event_data));
	event_data.data.clientid = context->id;
	event_data.data.topic_filter = sub->topic_filter;
	event_data.data.identifier = sub->identifier;
	event_data.data.options = sub->options;

	DL_FOREACH_SAFE(opts->plugin_callbacks.persist_subscription_add, cb_base, cb_next){
		cb_base->cb(MOSQ_EVT_PERSIST_SUBSCRIPTION_ADD, &event_data, cb_base->userdata);
	}
}


void plugin_persist__handle_subscription_delete(struct mosquitto *context, char *sub)
{
	struct mosquitto_evt_persist_subscription event_data;
	struct mosquitto__callback *cb_base, *cb_next;
	struct mosquitto__security_options *opts;

	if(db.shutdown || context->is_persisted == false) return;
	if(!sub) return;

	opts = &db.config->security_options;
	memset(&event_data, 0, sizeof(event_data));
	event_data.data.clientid = context->id;
	event_data.data.topic_filter = sub;

	DL_FOREACH_SAFE(opts->plugin_callbacks.persist_subscription_delete, cb_base, cb_next){
		cb_base->cb(MOSQ_EVT_PERSIST_SUBSCRIPTION_DELETE, &event_data, cb_base->userdata);
	}
}


void plugin_persist__handle_client_msg_add(struct mosquitto *context, const struct mosquitto__client_msg *client_msg)
{
	struct mosquitto_evt_persist_client_msg event_data;
	struct mosquitto__callback *cb_base, *cb_next;
	struct mosquitto__security_options *opts;

	if(context->is_persisted == false
			|| (client_msg->data.qos == 0 && db.config->queue_qos0_messages == false)
			|| db.shutdown){

		return;
	}

	opts = &db.config->security_options;
	memset(&event_data, 0, sizeof(event_data));

	event_data.data.clientid = context->id;
	event_data.data.cmsg_id = client_msg->data.cmsg_id;
	event_data.data.store_id = client_msg->base_msg->data.store_id;
	event_data.data.mid = client_msg->data.mid;
	event_data.data.qos = client_msg->data.qos;
	event_data.data.retain = client_msg->data.retain;
	event_data.data.dup = client_msg->data.dup;
	event_data.data.direction = (uint8_t)client_msg->data.direction;
	event_data.data.state = (uint8_t)client_msg->data.state;

	DL_FOREACH_SAFE(opts->plugin_callbacks.persist_client_msg_add, cb_base, cb_next){
		cb_base->cb(MOSQ_EVT_PERSIST_CLIENT_MSG_ADD, &event_data, cb_base->userdata);
	}
}


void plugin_persist__handle_client_msg_delete(struct mosquitto *context, const struct mosquitto__client_msg *client_msg)
{
	struct mosquitto_evt_persist_client_msg event_data;
	struct mosquitto__callback *cb_base, *cb_next;
	struct mosquitto__security_options *opts;

	if(context->is_persisted == false
			|| (client_msg->data.qos == 0 && db.config->queue_qos0_messages == false)
			|| db.shutdown){

		return;
	}

	opts = &db.config->security_options;
	memset(&event_data, 0, sizeof(event_data));

	event_data.data.clientid = context->id;
	event_data.data.cmsg_id = client_msg->data.cmsg_id;
	event_data.data.mid = client_msg->data.mid;
	event_data.data.state = (uint8_t)client_msg->data.state;
	event_data.data.qos = client_msg->data.qos;
	event_data.data.store_id = client_msg->base_msg->data.store_id;
	event_data.data.direction = (uint8_t)client_msg->data.direction;

	DL_FOREACH_SAFE(opts->plugin_callbacks.persist_client_msg_delete, cb_base, cb_next){
		cb_base->cb(MOSQ_EVT_PERSIST_CLIENT_MSG_DELETE, &event_data, cb_base->userdata);
	}
}


void plugin_persist__handle_client_msg_update(struct mosquitto *context, const struct mosquitto__client_msg *client_msg)
{
	struct mosquitto_evt_persist_client_msg event_data;
	struct mosquitto__callback *cb_base, *cb_next;
	struct mosquitto__security_options *opts;

	if(context->is_persisted == false
			|| (client_msg->data.qos == 0 && db.config->queue_qos0_messages == false)
			|| db.shutdown){

		return;
	}

	opts = &db.config->security_options;
	memset(&event_data, 0, sizeof(event_data));

	event_data.data.clientid = context->id;
	event_data.data.cmsg_id = client_msg->data.cmsg_id;
	event_data.data.mid = client_msg->data.mid;
	event_data.data.store_id = client_msg->base_msg->data.store_id;
	event_data.data.state = (uint8_t)client_msg->data.state;
	event_data.data.dup = client_msg->data.dup;
	event_data.data.direction = (uint8_t)client_msg->data.direction;
	event_data.data.qos = client_msg->data.qos;

	DL_FOREACH_SAFE(opts->plugin_callbacks.persist_client_msg_update, cb_base, cb_next){
		cb_base->cb(MOSQ_EVT_PERSIST_CLIENT_MSG_UPDATE, &event_data, cb_base->userdata);
	}
}


void plugin_persist__handle_base_msg_add(struct mosquitto__base_msg *base_msg)
{
	struct mosquitto_evt_persist_base_msg event_data;
	struct mosquitto__callback *cb_base, *cb_next;
	struct mosquitto__security_options *opts;

	if(base_msg->stored || db.shutdown) return;

	opts = &db.config->security_options;
	memset(&event_data, 0, sizeof(event_data));

	event_data.data.store_id = base_msg->data.store_id;
	event_data.data.expiry_time = base_msg->data.expiry_time;
	event_data.data.topic = base_msg->data.topic;
	event_data.data.payload = base_msg->data.payload;
	event_data.data.source_id = base_msg->data.source_id;
	event_data.data.source_username = base_msg->data.source_username;
	event_data.data.properties = base_msg->data.properties;
	event_data.data.payloadlen = base_msg->data.payloadlen;
	event_data.data.source_mid = base_msg->data.source_mid;
	if(base_msg->source_listener){
		event_data.data.source_port = base_msg->source_listener->port;
	}else{
		event_data.data.source_port = 0;
	}
	event_data.data.qos = base_msg->data.qos;
	event_data.data.retain = base_msg->data.retain;

	DL_FOREACH_SAFE(opts->plugin_callbacks.persist_base_msg_add, cb_base, cb_next){
		cb_base->cb(MOSQ_EVT_PERSIST_BASE_MSG_ADD, &event_data, cb_base->userdata);
	}
	base_msg->stored = true;
}


void plugin_persist__handle_base_msg_delete(struct mosquitto__base_msg *base_msg)
{
	struct mosquitto_evt_persist_base_msg event_data;
	struct mosquitto__callback *cb_base, *cb_next;
	struct mosquitto__security_options *opts;

	if(base_msg->stored == false || db.shutdown) return;

	opts = &db.config->security_options;
	memset(&event_data, 0, sizeof(event_data));

	event_data.data.store_id = base_msg->data.store_id;

	DL_FOREACH_SAFE(opts->plugin_callbacks.persist_base_msg_delete, cb_base, cb_next){
		cb_base->cb(MOSQ_EVT_PERSIST_BASE_MSG_DELETE, &event_data, cb_base->userdata);
	}
	base_msg->stored = false;
}


void plugin_persist__handle_retain_msg_set(struct mosquitto__base_msg *base_msg)
{
	struct mosquitto_evt_persist_retain_msg event_data;
	struct mosquitto__callback *cb_base, *cb_next;
	struct mosquitto__security_options *opts;

	if(db.shutdown) return;

	opts = &db.config->security_options;
	memset(&event_data, 0, sizeof(event_data));

	event_data.store_id = base_msg->data.store_id;
	event_data.topic = base_msg->data.topic;

	DL_FOREACH_SAFE(opts->plugin_callbacks.persist_retain_msg_set, cb_base, cb_next){
		cb_base->cb(MOSQ_EVT_PERSIST_RETAIN_MSG_SET, &event_data, cb_base->userdata);
	}
}


void plugin_persist__handle_retain_msg_delete(struct mosquitto__base_msg *base_msg)
{
	struct mosquitto_evt_persist_retain_msg event_data;
	struct mosquitto__callback *cb_base, *cb_next;
	struct mosquitto__security_options *opts;

	if(db.shutdown) return;

	opts = &db.config->security_options;
	memset(&event_data, 0, sizeof(event_data));

	event_data.topic = base_msg->data.topic;

	DL_FOREACH_SAFE(opts->plugin_callbacks.persist_retain_msg_delete, cb_base, cb_next){
		cb_base->cb(MOSQ_EVT_PERSIST_RETAIN_MSG_DELETE, &event_data, cb_base->userdata);
	}
}
