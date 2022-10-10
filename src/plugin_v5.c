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
#include "lib_load.h"


int plugin__load_v5(struct mosquitto__listener *listener, struct mosquitto__plugin *plugin, struct mosquitto_opt *options, int option_count, void *lib)
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
	/* Optional function */
	plugin->plugin_cleanup_v5 = (FUNC_plugin_cleanup_v5)LIB_SYM(lib, "mosquitto_plugin_cleanup");

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
	if(pid->plugin_name && pid->plugin_version){
		log__printf(NULL, MOSQ_LOG_INFO,
				"Plugin %s version %s loaded.", pid->plugin_name, pid->plugin_version);
	}else if(pid->plugin_name){
		log__printf(NULL, MOSQ_LOG_INFO,
				"Plugin %s loaded.", pid->plugin_name);
	}

	return 0;
}
