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
#include "mosquitto_internal.h"
#include "utlist.h"


static void plugin__handle_connect_single(struct mosquitto__security_options *opts, struct mosquitto *context)
{
	struct mosquitto_evt_connect event_data;
	struct mosquitto__callback *cb_base;

	memset(&event_data, 0, sizeof(event_data));
	event_data.client = context;
	DL_FOREACH(opts->plugin_callbacks.connect, cb_base){
		cb_base->cb(MOSQ_EVT_CONNECT, &event_data, cb_base->userdata);
	}
}


void plugin__handle_connect(struct mosquitto *context)
{
	/* Global plugins */
	plugin__handle_connect_single(&db.config->security_options, context);

	/* Per listener plugins */
	if(db.config->per_listener_settings && context->listener){
		plugin__handle_connect_single(&context->listener->security_options, context);
	}
}
