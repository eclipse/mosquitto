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


static int plugin__handle_message_single(struct mosquitto__security_options *opts, struct mosquitto *context, struct mosquitto_base_msg *stored)
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

	DL_FOREACH(opts->plugin_callbacks.message, cb_base){
		rc = cb_base->cb(MOSQ_EVT_MESSAGE, &event_data, cb_base->userdata);
		if(rc != MOSQ_ERR_SUCCESS){
			break;
		}
	}

	stored->topic = event_data.topic;
	if(stored->payload != event_data.payload){
		mosquitto__FREE(stored->payload);
		stored->payload = event_data.payload;
		stored->payloadlen = event_data.payloadlen;
	}
	stored->retain = event_data.retain;
	stored->properties = event_data.properties;

	return rc;
}

int plugin__handle_message(struct mosquitto *context, struct mosquitto_base_msg *stored)
{
	int rc = MOSQ_ERR_SUCCESS;

	/* Global plugins */
	rc = plugin__handle_message_single(&db.config->security_options,
			context, stored);
	if(rc) return rc;

	if(db.config->per_listener_settings && context->listener){
		rc = plugin__handle_message_single(&context->listener->security_options,
			context, stored);
	}

	return rc;
}
