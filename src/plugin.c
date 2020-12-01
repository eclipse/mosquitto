/*
Copyright (c) 2016-2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
SPDX-License-Identifier: EPL-2.0 OR EDL-1.0

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


static bool check_callback_exists(struct mosquitto__callback *cb_base, MOSQ_FUNC_generic_callback cb_func)
{
	struct mosquitto__callback *tail, *tmp;

	DL_FOREACH_SAFE(cb_base, tail, tmp){
		if(tail->cb == cb_func){
			return true;
		}
	}
	return false;
}


static int remove_callback(struct mosquitto__callback **cb_base, MOSQ_FUNC_generic_callback cb_func)
{
	struct mosquitto__callback *tail, *tmp;

	DL_FOREACH_SAFE(*cb_base, tail, tmp){
		if(tail->cb == cb_func){
			DL_DELETE(*cb_base, tail);
			mosquitto__free(tail);
			return MOSQ_ERR_SUCCESS;
		}
	}
	return MOSQ_ERR_NOT_FOUND;
}


int plugin__load_v5(struct mosquitto__listener *listener, struct mosquitto__auth_plugin *plugin, struct mosquitto_opt *options, int option_count, void *lib)
{
	int rc;
	mosquitto_plugin_id_t *pid;

	if(!(plugin->plugin_init_v5 = (FUNC_plugin_init_v5)LIB_SYM(lib, "mosquitto_plugin_init"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load plugin function mosquitto_plugin_init().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}
	if(!(plugin->plugin_cleanup_v5 = (FUNC_plugin_cleanup_v5)LIB_SYM(lib, "mosquitto_plugin_cleanup"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load plugin function mosquitto_plugin_cleanup().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	pid = mosquitto__calloc(1, sizeof(mosquitto_plugin_id_t));
	if(pid == NULL){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Out of memory.");
		LIB_CLOSE(lib);
		return MOSQ_ERR_NOMEM;
	}
	pid->listener = listener;

	plugin->lib = lib;
	plugin->user_data = NULL;
	plugin->identifier = pid;

	if(plugin->plugin_init_v5){
		rc = plugin->plugin_init_v5(pid, &plugin->user_data, options, option_count);
		if(rc){
			log__printf(NULL, MOSQ_LOG_ERR,
					"Error: Plugin returned %d when initialising.", rc);
			return rc;
		}
	}

	return 0;
}


void plugin__handle_disconnect(struct mosquitto *context, int reason)
{
	struct mosquitto_evt_disconnect event_data;
	struct mosquitto__callback *cb_base;
	struct mosquitto__security_options *opts;

	if(db.config->per_listener_settings){
		if(context->listener == NULL){
			return;
		}
		opts = &context->listener->security_options;
	}else{
		opts = &db.config->security_options;
		memset(&event_data, 0, sizeof(event_data));
	}

	event_data.client = context;
	event_data.reason = reason;
	DL_FOREACH(opts->plugin_callbacks.disconnect, cb_base){
		cb_base->cb(MOSQ_EVT_DISCONNECT, &event_data, cb_base->userdata);
	}
}


int plugin__handle_message(struct mosquitto *context, struct mosquitto_msg_store *stored)
{
	struct mosquitto_evt_message event_data;
	struct mosquitto__callback *cb_base;
	struct mosquitto__security_options *opts;
	int rc = MOSQ_ERR_SUCCESS;

	if(db.config->per_listener_settings){
		if(context->listener == NULL){
			return MOSQ_ERR_SUCCESS;
		}
		opts = &context->listener->security_options;
	}else{
		opts = &db.config->security_options;
	}
	if(opts->plugin_callbacks.message == NULL){
		return MOSQ_ERR_SUCCESS;
	}
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
		mosquitto__free(stored->payload);
		stored->payload = event_data.payload;
		stored->payloadlen = event_data.payloadlen;
	}
	stored->retain = event_data.retain;
	stored->properties = event_data.properties;

	return rc;
}


void plugin__handle_tick(void)
{
	struct mosquitto_evt_tick event_data;
	struct mosquitto__callback *cb_base;
	struct mosquitto__security_options *opts;

	// FIXME - set now_s and now_ns to avoid need for multiple time lookups
	if(db.config->per_listener_settings){
		// FIXME - iterate over all listeners
	}else{
		opts = &db.config->security_options;
		memset(&event_data, 0, sizeof(event_data));

		DL_FOREACH(opts->plugin_callbacks.tick, cb_base){
			cb_base->cb(MOSQ_EVT_TICK, &event_data, cb_base->userdata);
		}
	}
}


int mosquitto_callback_register(
		mosquitto_plugin_id_t *identifier,
		int event,
		MOSQ_FUNC_generic_callback cb_func,
		const void *event_data,
		void *userdata)
{
	struct mosquitto__callback **cb_base = NULL, *cb_new;
	struct mosquitto__security_options *security_options;

	if(cb_func == NULL) return MOSQ_ERR_INVAL;

	if(identifier->listener == NULL){
		security_options = &db.config->security_options;
	}else{
		security_options = &identifier->listener->security_options;
	}

	switch(event){
		case MOSQ_EVT_RELOAD:
			cb_base = &security_options->plugin_callbacks.reload;
			break;
		case MOSQ_EVT_ACL_CHECK:
			cb_base = &security_options->plugin_callbacks.acl_check;
			break;
		case MOSQ_EVT_BASIC_AUTH:
			cb_base = &security_options->plugin_callbacks.basic_auth;
			break;
		case MOSQ_EVT_PSK_KEY:
			cb_base = &security_options->plugin_callbacks.psk_key;
			break;
		case MOSQ_EVT_EXT_AUTH_START:
			cb_base = &security_options->plugin_callbacks.ext_auth_start;
			break;
		case MOSQ_EVT_EXT_AUTH_CONTINUE:
			cb_base = &security_options->plugin_callbacks.ext_auth_continue;
			break;
		case MOSQ_EVT_CONTROL:
			return control__register_callback(security_options, cb_func, event_data, userdata);
			break;
		case MOSQ_EVT_MESSAGE:
			cb_base = &security_options->plugin_callbacks.message;
			break;
		case MOSQ_EVT_TICK:
			cb_base = &security_options->plugin_callbacks.tick;
			break;
		case MOSQ_EVT_DISCONNECT:
			cb_base = &security_options->plugin_callbacks.disconnect;
			break;
		default:
			return MOSQ_ERR_NOT_SUPPORTED;
			break;
	}

	if(check_callback_exists(*cb_base, cb_func)){
		return MOSQ_ERR_ALREADY_EXISTS;
	}

	cb_new = mosquitto__calloc(1, sizeof(struct mosquitto__callback));
	if(cb_new == NULL){
		return MOSQ_ERR_NOMEM;
	}
	DL_APPEND(*cb_base, cb_new);
	cb_new->cb = cb_func;
	cb_new->userdata = userdata;

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_callback_unregister(
		mosquitto_plugin_id_t *identifier,
		int event,
		MOSQ_FUNC_generic_callback cb_func,
		const void *event_data)
{
	struct mosquitto__callback **cb_base = NULL;
	struct mosquitto__security_options *security_options;

	if(cb_func == NULL) return MOSQ_ERR_INVAL;

	if(identifier->listener == NULL){
		security_options = &db.config->security_options;
	}else{
		security_options = &identifier->listener->security_options;
	}
	switch(event){
		case MOSQ_EVT_RELOAD:
			cb_base = &security_options->plugin_callbacks.reload;
			break;
		case MOSQ_EVT_ACL_CHECK:
			cb_base = &security_options->plugin_callbacks.acl_check;
			break;
		case MOSQ_EVT_BASIC_AUTH:
			cb_base = &security_options->plugin_callbacks.basic_auth;
			break;
		case MOSQ_EVT_PSK_KEY:
			cb_base = &security_options->plugin_callbacks.psk_key;
			break;
		case MOSQ_EVT_EXT_AUTH_START:
			cb_base = &security_options->plugin_callbacks.ext_auth_start;
			break;
		case MOSQ_EVT_EXT_AUTH_CONTINUE:
			cb_base = &security_options->plugin_callbacks.ext_auth_continue;
			break;
		case MOSQ_EVT_CONTROL:
			return control__unregister_callback(security_options, cb_func, event_data);
			break;
		case MOSQ_EVT_MESSAGE:
			cb_base = &security_options->plugin_callbacks.message;
			break;
		case MOSQ_EVT_TICK:
			cb_base = &security_options->plugin_callbacks.tick;
			break;
		case MOSQ_EVT_DISCONNECT:
			cb_base = &security_options->plugin_callbacks.disconnect;
			break;
		default:
			return MOSQ_ERR_INVAL;
			break;
	}

	return remove_callback(cb_base, cb_func);
}
