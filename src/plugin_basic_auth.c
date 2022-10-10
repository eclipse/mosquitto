/*
Copyright (c) 2011-2021 Roger Light <roger@atchoo.org>

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

#include <stdio.h>
#include <string.h>

#include "mosquitto_broker.h"
#include "mosquitto_broker_internal.h"
#include "mosquitto_plugin.h"
#include "memory_mosq.h"
#include "lib_load.h"
#include "utlist.h"

static int plugin__basic_auth(struct mosquitto__security_options *opts, struct mosquitto *context)
{
	struct mosquitto_evt_basic_auth event_data;
	struct mosquitto__callback *cb_base;
	int rc;
	int rc_final = MOSQ_ERR_PLUGIN_IGNORE;

	DL_FOREACH(opts->plugin_callbacks.basic_auth, cb_base){
		memset(&event_data, 0, sizeof(event_data));
		event_data.client = context;
		event_data.username = context->username;
		event_data.password = context->password;
		rc = cb_base->cb(MOSQ_EVT_BASIC_AUTH, &event_data, cb_base->userdata);
		if(rc == MOSQ_ERR_PLUGIN_IGNORE){
			/* Do nothing, this is as if the plugin doesn't exist */
		}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
			rc_final = MOSQ_ERR_PLUGIN_DEFER;
		}else{
			return rc;
		}
	}
	return rc_final;
}


int mosquitto_basic_auth(struct mosquitto *context)
{
	int rc;
	bool plugin_used = false;

	/* Global plugins */
	if(db.config->security_options.plugin_callbacks.basic_auth){
		rc = plugin__basic_auth(&db.config->security_options, context);

		if(rc == MOSQ_ERR_PLUGIN_IGNORE){
			/* Do nothing */
		}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
			plugin_used = true;
		}else{
			return rc;
		}
	}

	/* Per listener plugins */
	if(db.config->per_listener_settings){
		if(context->listener == NULL){
			return MOSQ_ERR_AUTH;
		}
		if(context->listener->security_options.plugin_callbacks.basic_auth){
			rc = plugin__basic_auth(&context->listener->security_options, context);

			if(rc == MOSQ_ERR_PLUGIN_IGNORE){
				/* Do nothing */
			}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
				plugin_used = true;
			}else{
				return rc;
			}
		}
	}

	/* If all plugins deferred, this is a denial. plugin_used == false
	 * here, then no plugins were configured.
	 * anonymous logins are allowed. */
	if(plugin_used == false){
		if((db.config->per_listener_settings && context->listener->security_options.allow_anonymous != false)
				|| (!db.config->per_listener_settings && db.config->security_options.allow_anonymous != false)){

			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_AUTH;
		}
	}else{
		/* Can't have got here without at least one plugin returning MOSQ_ERR_PLUGIN_DEFER.
		 * This will now be a denial, unless it is anon and allow anon is true. */
		if(context->username == NULL &&
				((db.config->per_listener_settings && context->listener->security_options.allow_anonymous != false)
				|| (!db.config->per_listener_settings && db.config->security_options.allow_anonymous != false))){

			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_AUTH;
		}
	}

	return rc;
}
