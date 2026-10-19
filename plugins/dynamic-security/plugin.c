/*
Copyright (c) 2020-2021 Roger Light <roger@atchoo.org>

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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef WIN32
#  include <strings.h>
#endif

#include "mosquitto.h"

#include "dynamic_security.h"
#include "json_help.h"

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

static struct dynsec__data dynsec_data;
static mosquitto_plugin_id_t *plg_id = NULL;

#ifdef WIN32
#  include <winsock2.h>
#  include <aclapi.h>
#  include <io.h>
#  include <lmcons.h>
#  include <fcntl.h>
#  define PATH_MAX MAX_PATH
#else
#  include <sys/stat.h>
#  include <pwd.h>
#  include <grp.h>
#  include <unistd.h>
#endif


int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *options, int option_count)
{
	int i;
	int rc;

	UNUSED(user_data);

	memset(&dynsec_data, 0, sizeof(struct dynsec__data));

	for(i=0; i<option_count; i++){
		if(!strcasecmp(options[i].key, "config_file")){
			dynsec_data.config_file = mosquitto_strdup(options[i].value);
			if(dynsec_data.config_file == NULL){
				return MOSQ_ERR_NOMEM;
			}
		}else if(!strcasecmp(options[i].key, "password_init_file")){
			dynsec_data.password_init_file = mosquitto_strdup(options[i].value);
			if(dynsec_data.password_init_file == NULL){
				return MOSQ_ERR_NOMEM;
			}
		}
	}
	if(dynsec_data.config_file == NULL){
		mosquitto_log_printf(MOSQ_LOG_WARNING, "Warning: Dynamic security plugin has no plugin_opt_config_file defined. The plugin will not be activated.");
		return MOSQ_ERR_SUCCESS;
	}

	plg_id = identifier;
	mosquitto_plugin_set_info(identifier, "dynamic-security", NULL);

	/* Do not activate a partially loaded policy if a configured limit is invalid. */
	rc = dynsec__config_load(&dynsec_data);
	if(rc != MOSQ_ERR_SUCCESS){
		goto error;
	}

	rc = mosquitto_callback_register(plg_id, MOSQ_EVT_CONTROL, dynsec_control_callback, "$CONTROL/dynamic-security/v1", &dynsec_data);
	if(rc == MOSQ_ERR_ALREADY_EXISTS){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Dynamic security plugin can currently only be loaded once.");
		mosquitto_log_printf(MOSQ_LOG_ERR, "Note that this was previously incorrectly allowed but could cause problems with duplicate entries in the config.");
		goto error;
	}else if(rc == MOSQ_ERR_NOMEM){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Out of memory.");
		goto error;
	}else if(rc != MOSQ_ERR_SUCCESS){
		goto error;
	}

	rc = mosquitto_callback_register(plg_id, MOSQ_EVT_BASIC_AUTH, dynsec_auth__basic_auth_callback, NULL, &dynsec_data);
	if(rc == MOSQ_ERR_ALREADY_EXISTS){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Dynamic security plugin can only be loaded once.");
		goto error;
	}else if(rc == MOSQ_ERR_NOMEM){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Out of memory.");
		goto error;
	}else if(rc != MOSQ_ERR_SUCCESS){
		goto error;
	}

	rc = mosquitto_callback_register(plg_id, MOSQ_EVT_ACL_CHECK, dynsec__acl_check_callback, NULL, &dynsec_data);
	if(rc == MOSQ_ERR_ALREADY_EXISTS){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Dynamic security plugin can only be loaded once.");
		goto error;
	}else if(rc == MOSQ_ERR_NOMEM){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Out of memory.");
		goto error;
	}else if(rc != MOSQ_ERR_SUCCESS){
		goto error;
	}

	rc = mosquitto_callback_register(plg_id, MOSQ_EVT_TICK, dynsec__tick_callback, NULL, &dynsec_data);
	if(rc == MOSQ_ERR_NOMEM){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Out of memory.");
		goto error;
	}else if(rc != MOSQ_ERR_SUCCESS){
		goto error;
	}

	rc = mosquitto_callback_register(plg_id, MOSQ_EVT_MESSAGE_IN, dynsec_publish__callback, NULL, &dynsec_data);
	if(rc != MOSQ_ERR_SUCCESS){
		goto error;
	}
	rc = mosquitto_callback_register(plg_id, MOSQ_EVT_DISCONNECT, dynsec_publish__disconnect_callback, NULL, &dynsec_data);
	if(rc != MOSQ_ERR_SUCCESS){
		goto error;
	}

	return MOSQ_ERR_SUCCESS;
error:
	dynsec_groups__cleanup(&dynsec_data);
	dynsec_clients__cleanup(&dynsec_data);
	dynsec_roles__cleanup(&dynsec_data);
	mosquitto_free(dynsec_data.config_file);
	dynsec_data.config_file = NULL;
	mosquitto_free(dynsec_data.password_init_file);
	dynsec_data.password_init_file = NULL;
	return rc;
}


int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *options, int option_count)
{
	UNUSED(user_data);
	UNUSED(options);
	UNUSED(option_count);

	dynsec_groups__cleanup(&dynsec_data);
	dynsec_clients__cleanup(&dynsec_data);
	dynsec_roles__cleanup(&dynsec_data);
	dynsec_kicklist__cleanup(&dynsec_data);

	mosquitto_free(dynsec_data.config_file);
	dynsec_data.config_file = NULL;

	mosquitto_free(dynsec_data.password_init_file);
	dynsec_data.password_init_file = NULL;

	mosquitto_callback_unregister(plg_id, MOSQ_EVT_CONTROL, dynsec_control_callback, "$CONTROL/dynamic-security/v1");
	mosquitto_callback_unregister(plg_id, MOSQ_EVT_BASIC_AUTH, dynsec_auth__basic_auth_callback, NULL);
	mosquitto_callback_unregister(plg_id, MOSQ_EVT_ACL_CHECK, dynsec__acl_check_callback, NULL);
	mosquitto_callback_unregister(plg_id, MOSQ_EVT_TICK, dynsec__tick_callback, NULL);
	mosquitto_callback_unregister(plg_id, MOSQ_EVT_MESSAGE_IN, dynsec_publish__callback, NULL);
	mosquitto_callback_unregister(plg_id, MOSQ_EVT_DISCONNECT, dynsec_publish__disconnect_callback, NULL);

	return MOSQ_ERR_SUCCESS;
}
