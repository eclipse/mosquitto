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

typedef int (*FUNC_auth_plugin_version)(void);
typedef int (*FUNC_plugin_version)(int, const int *);

void LIB_ERROR(void)
{
#ifdef WIN32
	char *buf;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			NULL, GetLastError(), LANG_NEUTRAL, (LPTSTR)&buf, 0, NULL);
	log__printf(NULL, MOSQ_LOG_ERR, "Load error: %s", buf);
	LocalFree(buf);
#else
	log__printf(NULL, MOSQ_LOG_ERR, "Load error: %s", dlerror());
#endif
}


static int plugin__load_single(mosquitto_plugin_id_t *plugin)
{
	void *lib;
	int (*plugin_version)(int, const int*) = NULL;
	int (*plugin_auth_version)(void) = NULL;
	int version;
	int rc;
	const int plugin_versions[] = {5, 4, 3, 2};
	int plugin_version_count = sizeof(plugin_versions)/sizeof(int);

	if(plugin->config.security_option_count == 0){
		return MOSQ_ERR_SUCCESS;
	}

	memset(&plugin->lib, 0, sizeof(struct mosquitto__plugin_lib));

	log__printf(NULL, MOSQ_LOG_INFO, "Loading plugin: %s", plugin->config.path);

	lib = LIB_LOAD(plugin->config.path);
	if(!lib){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load plugin \"%s\".", plugin->config.path);
		LIB_ERROR();
		return MOSQ_ERR_UNKNOWN;
	}

	plugin->lib.lib = NULL;
	if((plugin_version = (FUNC_plugin_version)LIB_SYM(lib, "mosquitto_plugin_version"))){
		version = plugin_version(plugin_version_count, plugin_versions);
	}else if((plugin_auth_version = (FUNC_auth_plugin_version)LIB_SYM(lib, "mosquitto_auth_plugin_version"))){
		version = plugin_auth_version();
	}else{
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load auth plugin function mosquitto_auth_plugin_version() or mosquitto_plugin_version().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}

	plugin->lib.version = version;
	if(version == 5){
		rc = plugin__load_v5(plugin, lib);
		if(rc) return rc;
	}else if(version == 4){
		rc = plugin__load_v4(plugin, lib);
		if(rc) return rc;
	}else if(version == 3){
		rc = plugin__load_v3(plugin, lib);
		if(rc) return rc;
	}else if(version == 2){
		rc = plugin__load_v2(plugin, lib);
		if(rc) return rc;
	}else{
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unsupported auth plugin version (got %d, expected %d).",
				version, MOSQ_PLUGIN_VERSION);
		LIB_ERROR();

		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}
	return MOSQ_ERR_SUCCESS;
}


int plugin__load_all(void)
{
	int rc = MOSQ_ERR_SUCCESS;
	int i;

	for(i=0; i<db.plugin_count; i++){
		rc = plugin__load_single(db.plugins[i]);
		if(rc) return rc;
	}
	return MOSQ_ERR_SUCCESS;
}


static int plugin__security_init_single(mosquitto_plugin_id_t *plugin, bool reload)
{
	int i;
	int rc;
	struct mosquitto_evt_reload event_data;
	struct mosquitto__callback *cb_base, *cb_next;

	if(reload){
		for(i=0; i<plugin->config.security_option_count; i++){
			DL_FOREACH_SAFE(plugin->config.security_options[i]->plugin_callbacks.reload, cb_base, cb_next){
				memset(&event_data, 0, sizeof(event_data));

				event_data.options = NULL;
				event_data.option_count = 0;
				cb_base->cb(MOSQ_EVT_RELOAD, &event_data, cb_base->userdata);
			}
		}
	}

	if(plugin->lib.version == 5){
		rc = MOSQ_ERR_SUCCESS;
	}else if(plugin->lib.version == 4){
		rc = plugin->lib.security_init_v4(
				plugin->lib.user_data,
				plugin->config.options,
				plugin->config.option_count,
				reload);

	}else if(plugin->lib.version == 3){
		rc = plugin->lib.security_init_v3(
				plugin->lib.user_data,
				plugin->config.options,
				plugin->config.option_count,
				reload);

	}else if(plugin->lib.version == 2){
		rc = plugin->lib.security_init_v2(
				plugin->lib.user_data,
				(struct mosquitto_auth_opt *)plugin->config.options,
				plugin->config.option_count,
				reload);
	}else{
		rc = MOSQ_ERR_INVAL;
	}

	return rc;
}


int mosquitto_security_init(bool reload)
{
	int i;
	int rc;

	for(i=0; i<db.plugin_count; i++){
		rc = plugin__security_init_single(db.plugins[i], reload);
		if(rc != MOSQ_ERR_SUCCESS) return rc;
	}
	rc = mosquitto_security_init_default(reload);
	return rc;
}
