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

static int plugin__ext_auth_start(struct mosquitto__security_options *opts, struct mosquitto *context, bool reauth, const void *data_in, uint16_t data_in_len, void **data_out, uint16_t *data_out_len)
{
	struct mosquitto_evt_extended_auth event_data;
	struct mosquitto__callback *cb_base;
	int rc;
	int rc_final = MOSQ_ERR_PLUGIN_DEFER;

	UNUSED(reauth);

	DL_FOREACH(opts->plugin_callbacks.ext_auth_start, cb_base){
		memset(&event_data, 0, sizeof(event_data));
		event_data.client = context;
		event_data.auth_method = context->auth_method;
		event_data.data_in = data_in;
		event_data.data_out = NULL;
		event_data.data_in_len = data_in_len;
		event_data.data_out_len = 0;
		rc = cb_base->cb(MOSQ_EVT_EXT_AUTH_START, &event_data, cb_base->userdata);
		if(rc == MOSQ_ERR_PLUGIN_IGNORE){
			/* Do nothing */
		}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
			rc_final = MOSQ_ERR_PLUGIN_DEFER;
		}else{
			*data_out = event_data.data_out;
			*data_out_len = event_data.data_out_len;
			return rc;
		}
	}
	return rc_final;
}


int mosquitto_security_auth_start(struct mosquitto *context, bool reauth, const void *data_in, uint16_t data_in_len, void **data_out, uint16_t *data_out_len)
{
	int rc;

	if(!context || !context->listener || !context->auth_method) return MOSQ_ERR_INVAL;
	if(!data_out || !data_out_len) return MOSQ_ERR_INVAL;

	/* Global plugins */
	if(db.config->security_options.plugin_callbacks.ext_auth_start){
		rc = plugin__ext_auth_start(&db.config->security_options, context,
				reauth, data_in, data_in_len, data_out, data_out_len);

		if(rc == MOSQ_ERR_PLUGIN_IGNORE || rc == MOSQ_ERR_PLUGIN_DEFER){
			/* Do nothing */
		}else{
			return rc;
		}
	}

	/* Per listener plugins */
	if(db.config->per_listener_settings){
		if(context->listener == NULL){
			return MOSQ_ERR_AUTH;
		}
		if(context->listener->security_options.plugin_callbacks.ext_auth_start){
			rc = plugin__ext_auth_start(&context->listener->security_options, context,
					reauth, data_in, data_in_len, data_out, data_out_len);

			if(rc == MOSQ_ERR_PLUGIN_IGNORE || rc == MOSQ_ERR_PLUGIN_DEFER){
				/* Do nothing */
			}else{
				return rc;
			}
		}
	}

	return MOSQ_ERR_NOT_SUPPORTED;
}


static int plugin__ext_auth_continue(struct mosquitto__security_options *opts, struct mosquitto *context, const void *data_in, uint16_t data_in_len, void **data_out, uint16_t *data_out_len)
{
	int rc;
	struct mosquitto_evt_extended_auth event_data;
	struct mosquitto__callback *cb_base;

	DL_FOREACH(opts->plugin_callbacks.ext_auth_continue, cb_base){
		memset(&event_data, 0, sizeof(event_data));
		event_data.client = context;
		event_data.data_in = data_in;
		event_data.data_out = NULL;
		event_data.data_in_len = data_in_len;
		event_data.data_out_len = 0;
		rc = cb_base->cb(MOSQ_EVT_EXT_AUTH_CONTINUE, &event_data, cb_base->userdata);
		if(rc == MOSQ_ERR_PLUGIN_IGNORE || rc == MOSQ_ERR_PLUGIN_DEFER){
			/* Do nothing */
		}else{
			*data_out = event_data.data_out;
			*data_out_len = event_data.data_out_len;
			return rc;
		}
	}

	return MOSQ_ERR_PLUGIN_DEFER;
}


int mosquitto_security_auth_continue(struct mosquitto *context, const void *data_in, uint16_t data_in_len, void **data_out, uint16_t *data_out_len)
{
	int rc;

	if(!context || !context->listener || !context->auth_method) return MOSQ_ERR_INVAL;
	if(!data_out || !data_out_len) return MOSQ_ERR_INVAL;

	/* Global plugins */
	if(db.config->security_options.plugin_callbacks.ext_auth_continue){
		rc = plugin__ext_auth_continue(&db.config->security_options, context,
				data_in, data_in_len, data_out, data_out_len);

		if(rc == MOSQ_ERR_PLUGIN_IGNORE || rc == MOSQ_ERR_PLUGIN_DEFER){
			/* Do nothing */
		}else{
			return rc;
		}
	}

	/* Per listener plugins */
	if(db.config->per_listener_settings){
		if(context->listener == NULL){
			return MOSQ_ERR_AUTH;
		}
		if(context->listener->security_options.plugin_callbacks.ext_auth_continue){
			rc = plugin__ext_auth_continue(&context->listener->security_options, context,
					data_in, data_in_len, data_out, data_out_len);

			if(rc == MOSQ_ERR_PLUGIN_IGNORE || rc == MOSQ_ERR_PLUGIN_DEFER){
				/* Do nothing */
			}else{
				return rc;
			}
		}
	}

	return MOSQ_ERR_NOT_SUPPORTED;
}
