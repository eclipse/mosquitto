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


static int security__module_init_single(struct mosquitto__listener *listener, struct mosquitto__security_options *opts)
{
	void *lib;
	int (*plugin_version)(int, const int*) = NULL;
	int (*plugin_auth_version)(void) = NULL;
	int version;
	int i;
	int rc;
	const int plugin_versions[] = {5, 4, 3, 2};
	int plugin_version_count = sizeof(plugin_versions)/sizeof(int);

	if(opts->plugin_config_count == 0){
		return MOSQ_ERR_SUCCESS;
	}

	for(i=0; i<opts->plugin_config_count; i++){
		if(opts->plugin_configs[i]->path){
			memset(&opts->plugin_configs[i]->plugin, 0, sizeof(struct mosquitto__plugin));

			log__printf(NULL, MOSQ_LOG_INFO, "Loading plugin: %s", opts->plugin_configs[i]->path);

			lib = LIB_LOAD(opts->plugin_configs[i]->path);
			if(!lib){
				log__printf(NULL, MOSQ_LOG_ERR,
						"Error: Unable to load plugin \"%s\".", opts->plugin_configs[i]->path);
				LIB_ERROR();
				return MOSQ_ERR_UNKNOWN;
			}

			opts->plugin_configs[i]->plugin.lib = NULL;
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
			opts->plugin_configs[i]->plugin.version = version;
			if(version == 5){
				rc = plugin__load_v5(
						listener,
						&opts->plugin_configs[i]->plugin,
						opts->plugin_configs[i]->options,
						opts->plugin_configs[i]->option_count,
						lib);

				if(rc){
					return rc;
				}
			}else if(version == 4){
				rc = plugin__load_v4(listener, opts->plugin_configs[i], lib);
				if(rc) return rc;
			}else if(version == 3){
				rc = plugin__load_v3(listener, opts->plugin_configs[i], lib);
				if(rc) return rc;
			}else if(version == 2){
				rc = plugin__load_v2(listener, opts->plugin_configs[i], lib);
				if(rc) return rc;
			}else{
				log__printf(NULL, MOSQ_LOG_ERR,
						"Error: Unsupported auth plugin version (got %d, expected %d).",
						version, MOSQ_PLUGIN_VERSION);
				LIB_ERROR();

				LIB_CLOSE(lib);
				return MOSQ_ERR_UNKNOWN;
			}
		}
	}
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_security_module_init(void)
{
	int rc = MOSQ_ERR_SUCCESS;
	int i;

	if(db.config->per_listener_settings){
		for(i=0; i<db.config->listener_count; i++){
			rc = security__module_init_single(&db.config->listeners[i], &db.config->listeners[i].security_options);
			if(rc) return rc;
		}
	}
	return security__module_init_single(NULL, &db.config->security_options);
}


static int security__init_single(struct mosquitto__security_options *opts, bool reload)
{
	int i;
	int rc;
	struct mosquitto_evt_reload event_data;
	struct mosquitto__callback *cb_base;

	if(reload){
		DL_FOREACH(opts->plugin_callbacks.reload, cb_base){
			memset(&event_data, 0, sizeof(event_data));

			event_data.options = NULL;
			event_data.option_count = 0;
			cb_base->cb(MOSQ_EVT_RELOAD, &event_data, cb_base->userdata);
		}
	}

	for(i=0; i<opts->plugin_config_count; i++){
		if(opts->plugin_configs[i]->plugin.version == 5){
			continue;
		}else if(opts->plugin_configs[i]->plugin.version == 4){
			rc = opts->plugin_configs[i]->plugin.security_init_v4(
					opts->plugin_configs[i]->plugin.user_data,
					opts->plugin_configs[i]->options,
					opts->plugin_configs[i]->option_count,
					reload);

		}else if(opts->plugin_configs[i]->plugin.version == 3){
			rc = opts->plugin_configs[i]->plugin.security_init_v3(
					opts->plugin_configs[i]->plugin.user_data,
					opts->plugin_configs[i]->options,
					opts->plugin_configs[i]->option_count,
					reload);

		}else if(opts->plugin_configs[i]->plugin.version == 2){
			rc = opts->plugin_configs[i]->plugin.security_init_v2(
					opts->plugin_configs[i]->plugin.user_data,
					(struct mosquitto_auth_opt *)opts->plugin_configs[i]->options,
					opts->plugin_configs[i]->option_count,
					reload);
		}else{
			rc = MOSQ_ERR_INVAL;
		}
		if(rc != MOSQ_ERR_SUCCESS){
			return rc;
		}
	}
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_security_init(bool reload)
{
	int i;
	int rc;

	/* Global plugins loaded first */
	rc = security__init_single(&db.config->security_options, reload);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	if(db.config->per_listener_settings){
		for(i=0; i<db.config->listener_count; i++){
			rc = security__init_single(&db.config->listeners[i].security_options, reload);
			if(rc != MOSQ_ERR_SUCCESS) return rc;
		}
	}
	rc = mosquitto_security_init_default(reload);
	return rc;
}
