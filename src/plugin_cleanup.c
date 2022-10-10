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

static int security__cleanup_single(struct mosquitto__security_options *opts, bool reload);

static void security__module_cleanup_single(struct mosquitto__security_options *opts)
{
	int i;
	struct control_endpoint *ep, *tmp;
	struct mosquitto__plugin_config *conf;

	for(i=0; i<opts->plugin_config_count; i++){
		conf = opts->plugin_configs[i];

		/* Run plugin cleanup function */
		if(conf->plugin.version == 5){
			if(conf->plugin.plugin_cleanup_v5){
				conf->plugin.plugin_cleanup_v5(
						conf->plugin.user_data,
						conf->options,
						conf->option_count);
			}
		}else if(conf->plugin.version == 4){
			conf->plugin.plugin_cleanup_v4(
					conf->plugin.user_data,
					conf->options,
					conf->option_count);

		}else if(conf->plugin.version == 3){
			conf->plugin.plugin_cleanup_v3(
					conf->plugin.user_data,
					conf->options,
					conf->option_count);

		}else if(conf->plugin.version == 2){
			conf->plugin.plugin_cleanup_v2(
					conf->plugin.user_data,
					(struct mosquitto_auth_opt *)conf->options,
					conf->option_count);
		}

		plugin__callback_unregister_all(conf->plugin.identifier);
		if(conf->plugin.identifier){
			mosquitto__FREE(conf->plugin.identifier->plugin_name);
			mosquitto__FREE(conf->plugin.identifier->plugin_version);
			DL_FOREACH_SAFE(conf->plugin.identifier->control_endpoints, ep, tmp){
				DL_DELETE(conf->plugin.identifier->control_endpoints, ep);
				mosquitto__FREE(ep);
			}
			mosquitto__FREE(conf->plugin.identifier);
		}

		if(conf->plugin.lib){
			LIB_CLOSE(conf->plugin.lib);
		}
		memset(&conf->plugin, 0, sizeof(struct mosquitto__plugin));
	}
}


int mosquitto_security_module_cleanup(void)
{
	int i;

	mosquitto_security_cleanup(false);

	security__module_cleanup_single(&db.config->security_options);

	for(i=0; i<db.config->listener_count; i++){
		security__module_cleanup_single(&db.config->listeners[i].security_options);
	}

	return MOSQ_ERR_SUCCESS;
}


static int security__cleanup_single(struct mosquitto__security_options *opts, bool reload)
{
	int i;
	int rc;

	for(i=0; i<opts->plugin_config_count; i++){
		if(opts->plugin_configs[i]->plugin.version == 5){
			rc = MOSQ_ERR_SUCCESS;
		}else if(opts->plugin_configs[i]->plugin.version == 4){
			rc = opts->plugin_configs[i]->plugin.security_cleanup_v4(
					opts->plugin_configs[i]->plugin.user_data,
					opts->plugin_configs[i]->options,
					opts->plugin_configs[i]->option_count,
					reload);

		}else if(opts->plugin_configs[i]->plugin.version == 3){
			rc = opts->plugin_configs[i]->plugin.security_cleanup_v3(
					opts->plugin_configs[i]->plugin.user_data,
					opts->plugin_configs[i]->options,
					opts->plugin_configs[i]->option_count,
					reload);

		}else if(opts->plugin_configs[i]->plugin.version == 2){
			rc = opts->plugin_configs[i]->plugin.security_cleanup_v2(
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


int mosquitto_security_cleanup(bool reload)
{
	int i;
	int rc;

	rc = security__cleanup_single(&db.config->security_options, reload);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	for(i=0; i<db.config->listener_count; i++){
		rc = security__cleanup_single(&db.config->listeners[i].security_options, reload);
		if(rc != MOSQ_ERR_SUCCESS) return rc;
	}
	return mosquitto_security_cleanup_default(reload);
}
