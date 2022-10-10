/*
Copyright (c) 2016-2022 Roger Light <roger@atchoo.org>
Copyright (c) 2022 Cedalo GmbH

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


static int plugin__handle_unsubscribe_single(struct mosquitto__security_options *opts, struct mosquitto *context, const char *topic, const mosquitto_property *properties)
{
	struct mosquitto_evt_unsubscribe event_data;
	struct mosquitto__callback *cb_base;
	int rc = MOSQ_ERR_SUCCESS;

	memset(&event_data, 0, sizeof(event_data));
	event_data.client = context;
	event_data.topic = topic;
	event_data.properties = properties;

	DL_FOREACH(opts->plugin_callbacks.unsubscribe, cb_base){
		rc = cb_base->cb(MOSQ_EVT_UNSUBSCRIBE, &event_data, cb_base->userdata);
		if(rc != MOSQ_ERR_SUCCESS){
			break;
		}
	}

	return rc;
}


int plugin__handle_unsubscribe(struct mosquitto *context, const char *topic, const mosquitto_property *properties)
{
	int rc = MOSQ_ERR_SUCCESS;

	/* Global plugins */
	rc = plugin__handle_unsubscribe_single(&db.config->security_options,
			context, topic, properties);
	if(rc) return rc;

	if(db.config->per_listener_settings && context->listener){
		rc = plugin__handle_unsubscribe_single(&context->listener->security_options,
				context, topic, properties);
	}

	return rc;
}
