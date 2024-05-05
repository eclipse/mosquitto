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

#include "mosquitto/broker.h"
#include "mosquitto_broker_internal.h"
#include "mosquitto/broker_plugin.h"
#include "lib_load.h"
#include "utlist.h"

static int plugin__security_cleanup_single(mosquitto_plugin_id_t *plugin, bool reload);

static void plugin__unload_single(mosquitto_plugin_id_t *plugin)
{
	struct control_endpoint *ep, *tmp;

	/* Run plugin cleanup function */
	if(plugin->lib.version == 5){
		if(plugin->lib.plugin_cleanup_v5){
			plugin->lib.plugin_cleanup_v5(
					plugin->lib.user_data,
					plugin->config.options,
					plugin->config.option_count);
		}
	}else if(plugin->lib.version == 4){
		if(plugin->lib.plugin_cleanup_v4){
			plugin->lib.plugin_cleanup_v4(
					plugin->lib.user_data,
					plugin->config.options,
					plugin->config.option_count);
		}
	}else if(plugin->lib.version == 3){
		if(plugin->lib.plugin_cleanup_v3){
			plugin->lib.plugin_cleanup_v3(
					plugin->lib.user_data,
					plugin->config.options,
					plugin->config.option_count);
		}
	}else if(plugin->lib.version == 2){
		if(plugin->lib.plugin_cleanup_v2){
			plugin->lib.plugin_cleanup_v2(
					plugin->lib.user_data,
					(struct mosquitto_auth_opt *)plugin->config.options,
					plugin->config.option_count);
		}
	}

	plugin__callback_unregister_all(plugin);
	mosquitto_FREE(plugin->plugin_name);
	mosquitto_FREE(plugin->plugin_version);
	DL_FOREACH_SAFE(plugin->control_endpoints, ep, tmp){
		DL_DELETE(plugin->control_endpoints, ep);
		mosquitto_FREE(ep);
	}

	if(plugin->lib.lib){
		//LIB_CLOSE(plugin->lib.lib);
	}
	memset(&plugin->lib, 0, sizeof(struct mosquitto__plugin_lib));
}


int plugin__unload_all(void)
{
	for(int i=0; i<db.plugin_count; i++){
		plugin__unload_single(db.plugins[i]);
	}

	mosquitto_security_cleanup(false);

	return MOSQ_ERR_SUCCESS;
}


static int plugin__security_cleanup_single(mosquitto_plugin_id_t *plugin, bool reload)
{
	int rc;

	if(plugin->lib.version == 5){
		rc = MOSQ_ERR_SUCCESS;
	}else if(plugin->lib.version == 4){
		rc = plugin->lib.security_cleanup_v4(
				plugin->lib.user_data,
				plugin->config.options,
				plugin->config.option_count,
				reload);

	}else if(plugin->lib.version == 3){
		rc = plugin->lib.security_cleanup_v3(
				plugin->lib.user_data,
				plugin->config.options,
				plugin->config.option_count,
				reload);

	}else if(plugin->lib.version == 2){
		rc = plugin->lib.security_cleanup_v2(
				plugin->lib.user_data,
				(struct mosquitto_auth_opt *)plugin->config.options,
				plugin->config.option_count,
				reload);
	}else{
		rc = MOSQ_ERR_INVAL;
	}

	return rc;
}


int mosquitto_security_cleanup(bool reload)
{
	for(int i=0; i<db.plugin_count; i++){
		plugin__security_cleanup_single(db.plugins[i], reload);
	}

	return mosquitto_security_cleanup_default(reload);
}
