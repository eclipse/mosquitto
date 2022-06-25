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
#include "utlist.h"

struct should_free {
	bool topic;
	bool payload;
	bool properties;
};

static int plugin__handle_message_single(struct mosquitto__callback *callbacks, enum mosquitto_plugin_event ev_type, struct should_free *to_free, struct mosquitto *context, struct mosquitto_base_msg *stored)
{
	struct mosquitto_evt_message event_data;
	struct mosquitto__callback *cb_base;
	int rc = MOSQ_ERR_SUCCESS;

	memset(&event_data, 0, sizeof(event_data));
	event_data.client = context;
	event_data.topic = stored->topic;
	event_data.payloadlen = stored->payloadlen;
	event_data.payload = stored->payload;
	event_data.qos = stored->qos;
	event_data.retain = stored->retain;
	event_data.properties = stored->properties;

	DL_FOREACH(callbacks, cb_base){
		rc = cb_base->cb(ev_type, &event_data, cb_base->userdata);
		if(rc != MOSQ_ERR_SUCCESS){
			break;
		}

		if(stored->topic != event_data.topic){
			if(to_free->topic) mosquitto__FREE(stored->topic);
			stored->topic = event_data.topic;
			to_free->topic = true;
		}

		if(stored->payload != event_data.payload){
			if(to_free->payload) mosquitto__FREE(stored->payload);
			stored->payload = event_data.payload;
			stored->payloadlen = event_data.payloadlen;
			to_free->payload = true;
		}

		if(stored->properties != event_data.properties){
			if(to_free->properties) mosquitto_property_free_all(&stored->properties);
			stored->properties = event_data.properties;
			to_free->properties = true;
		}
	}

	stored->retain = event_data.retain;
	if(ev_type == MOSQ_EVT_MESSAGE_READ){
		stored->qos = event_data.qos;
	}

	return rc;
}

int plugin__handle_message_read(struct mosquitto *context, struct mosquitto_base_msg *stored)
{
	int rc = MOSQ_ERR_SUCCESS;
	struct should_free to_free = {false, false, false}; /* in msg_read, original data will be freed later */

	/* Global plugins */
	rc = plugin__handle_message_single(db.config->security_options.plugin_callbacks.message_read,
			MOSQ_EVT_MESSAGE_READ, &to_free, context, stored);
	if(rc) return rc;

	if(db.config->per_listener_settings && context->listener){
		rc = plugin__handle_message_single(context->listener->security_options.plugin_callbacks.message_read,
			MOSQ_EVT_MESSAGE_READ, &to_free, context, stored);
	}

	return rc;
}

int plugin__handle_message_write(struct mosquitto *context, struct mosquitto_base_msg *stored)
{
	int rc = MOSQ_ERR_SUCCESS;
	struct should_free to_free = {true, true, true}; /* in msg_write, original data should be freed */

	/* Global plugins */
	rc = plugin__handle_message_single(db.config->security_options.plugin_callbacks.message_write,
			MOSQ_EVT_MESSAGE_WRITE, &to_free, context, stored);
	if(rc) return rc;

	if(db.config->per_listener_settings && context->listener){
		rc = plugin__handle_message_single(context->listener->security_options.plugin_callbacks.message_write,
			MOSQ_EVT_MESSAGE_WRITE, &to_free, context, stored);
	}

	return rc;
}
