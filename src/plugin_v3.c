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

/* This loads v3 plugins in a v5 wrapper to make the core code cleaner */

#include "config.h"

#include <stdio.h>
#include <string.h>

#include "mosquitto_broker.h"
#include "mosquitto_broker_internal.h"
#include "mosquitto_plugin.h"
#include "memory_mosq.h"
#include "lib_load.h"
#include "utlist.h"

typedef int (*FUNC_auth_plugin_version)(void);
typedef int (*FUNC_plugin_version)(int, const int *);

static int plugin_v3_basic_auth(int event, void *event_data, void *userdata)
{
	struct mosquitto__plugin_config *plugin_config = userdata;
	struct mosquitto_evt_basic_auth *ed = event_data;

	UNUSED(event);

	if(plugin_config->plugin.unpwd_check_v3 == NULL){
		return MOSQ_ERR_INVAL;
	}

	return plugin_config->plugin.unpwd_check_v3(
			plugin_config->plugin.user_data,
			ed->client,
			ed->username,
			ed->password);
}

static int plugin_v3_acl_check(int event, void *event_data, void *userdata)
{
	struct mosquitto__plugin_config *plugin_config = userdata;
	struct mosquitto_evt_acl_check *ed = event_data;
	struct mosquitto_acl_msg msg;
	int rc;

	UNUSED(event);

	if(plugin_config->plugin.acl_check_v3 == NULL){
		return MOSQ_ERR_INVAL;
	}

	memset(&msg, 0, sizeof(msg));
	msg.topic = ed->topic;
	msg.payloadlen = ed->payloadlen;
	msg.payload = ed->payload;
	msg.qos = ed->qos;
	msg.retain = ed->retain;

	rc = acl__pre_check(plugin_config, ed->client, ed->access);
	if(rc == MOSQ_ERR_PLUGIN_DEFER){
		return plugin_config->plugin.acl_check_v3(
				plugin_config->plugin.user_data,
				ed->access,
				ed->client,
				&msg);
	}else{
		return rc;
	}
}

static int plugin_v3_psk_key_get(int event, void *event_data, void *userdata)
{
	struct mosquitto__plugin_config *plugin_config = userdata;
	struct mosquitto_evt_psk_key *ed = event_data;

	UNUSED(event);

	if(plugin_config->plugin.psk_key_get_v3 == NULL){
		return MOSQ_ERR_INVAL;
	}

	return plugin_config->plugin.psk_key_get_v3(
			plugin_config->plugin.user_data,
			ed->client,
			ed->hint,
			ed->identity,
			ed->key,
			ed->max_key_len);
}


static int plugin_v3_reload(int event, void *event_data, void *userdata)
{
	struct mosquitto__plugin_config *plugin_config = userdata;
	int rc;

	UNUSED(event);
	UNUSED(event_data);

	rc = plugin_config->plugin.security_cleanup_v3(
			plugin_config->plugin.user_data,
			plugin_config->options,
			plugin_config->option_count,
			true);
	if(rc) return rc;

	rc = plugin_config->plugin.security_init_v3(
			plugin_config->plugin.user_data,
			plugin_config->options,
			plugin_config->option_count,
			true);
	return rc;
}


int plugin__load_v3(struct mosquitto__listener *listener, struct mosquitto__plugin_config *plugin_config, void *lib)
{
	mosquitto_plugin_id_t *pid;
	int rc;

	if(!(plugin_config->plugin.plugin_init_v3 = (FUNC_auth_plugin_init_v3)LIB_SYM(lib, "mosquitto_auth_plugin_init"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_plugin_init().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}
	if(!(plugin_config->plugin.plugin_cleanup_v3 = (FUNC_auth_plugin_cleanup_v3)LIB_SYM(lib, "mosquitto_auth_plugin_cleanup"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_plugin_cleanup().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin_config->plugin.security_init_v3 = (FUNC_auth_plugin_security_init_v3)LIB_SYM(lib, "mosquitto_auth_security_init"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_security_init().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin_config->plugin.security_cleanup_v3 = (FUNC_auth_plugin_security_cleanup_v3)LIB_SYM(lib, "mosquitto_auth_security_cleanup"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_security_cleanup().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin_config->plugin.acl_check_v3 = (FUNC_auth_plugin_acl_check_v3)LIB_SYM(lib, "mosquitto_auth_acl_check"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_acl_check().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin_config->plugin.unpwd_check_v3 = (FUNC_auth_plugin_unpwd_check_v3)LIB_SYM(lib, "mosquitto_auth_unpwd_check"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_unpwd_check().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	if(!(plugin_config->plugin.psk_key_get_v3 = (FUNC_auth_plugin_psk_key_get_v3)LIB_SYM(lib, "mosquitto_auth_psk_key_get"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_psk_key_get().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	pid = mosquitto__calloc(1, sizeof(mosquitto_plugin_id_t));
	if(pid == NULL){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		LIB_CLOSE(lib);
		return MOSQ_ERR_NOMEM;
	}
	pid->listener = listener;

	plugin_config->plugin.lib = lib;
	plugin_config->plugin.user_data = NULL;
	plugin_config->plugin.identifier = pid;
	if(plugin_config->plugin.plugin_init_v3){
		rc = plugin_config->plugin.plugin_init_v3(&plugin_config->plugin.user_data, plugin_config->options, plugin_config->option_count);
		if(rc){
			log__printf(NULL, MOSQ_LOG_ERR,
					"Error: Authentication plugin returned %d when initialising.", rc);
			return rc;
		}
	}

	mosquitto_callback_register(pid, MOSQ_EVT_RELOAD, plugin_v3_reload, NULL, plugin_config);

	if(plugin_config->plugin.unpwd_check_v3){
		mosquitto_callback_register(pid, MOSQ_EVT_BASIC_AUTH, plugin_v3_basic_auth, NULL, plugin_config);
	}
	if(plugin_config->plugin.acl_check_v3){
		mosquitto_callback_register(pid, MOSQ_EVT_ACL_CHECK, plugin_v3_acl_check, NULL, plugin_config);
	}
	if(plugin_config->plugin.psk_key_get_v3){
		mosquitto_callback_register(pid, MOSQ_EVT_PSK_KEY, plugin_v3_psk_key_get, NULL, plugin_config);
	}

	return 0;
}


