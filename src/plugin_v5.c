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


int plugin__load_v5(mosquitto_plugin_id_t *plugin, void *lib)
{
	int rc;

	if(!(plugin->lib.plugin_init_v5 = (FUNC_plugin_init_v5)LIB_SYM(lib, "mosquitto_plugin_init"))){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Unable to load plugin function mosquitto_plugin_init().");
		LIB_ERROR();
		LIB_CLOSE(lib);
		return MOSQ_ERR_UNKNOWN;
	}
	/* Optional function */
	plugin->lib.plugin_cleanup_v5 = (FUNC_plugin_cleanup_v5)LIB_SYM(lib, "mosquitto_plugin_cleanup");

	plugin->lib.lib = lib;
	plugin->lib.user_data = NULL;
	plugin->lib.identifier = plugin;

	if(plugin->lib.plugin_init_v5){
		rc = plugin->lib.plugin_init_v5(plugin, &plugin->lib.user_data, plugin->config.options, plugin->config.option_count);
		if(rc){
			log__printf(NULL, MOSQ_LOG_ERR,
					"Error: Plugin returned %d when initialising.", rc);
			return rc;
		}
	}
	if(plugin->plugin_name && plugin->plugin_version){
		log__printf(NULL, MOSQ_LOG_INFO,
				"Plugin %s version %s loaded.", plugin->plugin_name, plugin->plugin_version);
	}else if(plugin->plugin_name){
		log__printf(NULL, MOSQ_LOG_INFO,
				"Plugin %s loaded.", plugin->plugin_name);
	}

	return 0;
}
