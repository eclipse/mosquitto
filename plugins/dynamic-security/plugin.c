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

#include "json_help.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mqtt_protocol.h"

#include "dynamic_security.h"

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

static struct dynsec__data dynsec_data;
static mosquitto_plugin_id_t *plg_id = NULL;

static int str_ends_with(const char *str, const char *suffix) {
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);

    return (str_len >= suffix_len) &&
           (!memcmp(str + str_len - suffix_len, suffix, suffix_len));
}

static int auto_detect_config_file_format(char* filename) {
    if (str_ends_with(filename, ".json")) return CONFIG_FORMAT_JSON;

#ifdef WITH_YAML
    if (str_ends_with(filename, ".yaml")) return CONFIG_FORMAT_YAML;
    if (str_ends_with(filename, ".yml")) return CONFIG_FORMAT_YAML;
#endif

    mosquitto_log_printf(MOSQ_LOG_WARNING, "Warning: Cannot guess dynamic security plugin config file format based on extension of %s. Assuming 'json'", filename);
    return CONFIG_FORMAT_JSON;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *options, int option_count)
{
	int i;
	int rc;

	UNUSED(user_data);

	memset(&dynsec_data, 0, sizeof(struct dynsec__data));
    dynsec_data.config_format = CONFIG_FORMAT_AUTO;

	for(i=0; i<option_count; i++){
		if (!strcasecmp(options[i].key, "config_file")){
			dynsec_data.config_file = mosquitto_strdup(options[i].value);
			if (dynsec_data.config_file == NULL){
				return MOSQ_ERR_NOMEM;
			}
		} else if (!strcasecmp(options[i].key, "password_init_file")){
			dynsec_data.password_init_file = mosquitto_strdup(options[i].value);
			if (dynsec_data.password_init_file == NULL){
				return MOSQ_ERR_NOMEM;
			}
		} else if (!strcasecmp(options[i].key, "config_format")) {
            if (!strcasecmp(options[i].value, "auto")) dynsec_data.config_format = CONFIG_FORMAT_AUTO;
            else if (!strcasecmp(options[i].value, "json")) dynsec_data.config_format = CONFIG_FORMAT_JSON;
#ifdef WITH_YAML
            else if (!strcasecmp(options[i].value, "yaml")) dynsec_data.config_format = CONFIG_FORMAT_YAML;
#endif
            else {
                mosquitto_log_printf(MOSQ_LOG_WARNING, "Warning: Dynamic security plugin has an invalid value for plugin_opt_config_format '%s'. Assuming 'auto'", options[i].value);
                dynsec_data.config_format = CONFIG_FORMAT_AUTO;
            }
        }
	}
	if(dynsec_data.config_file == NULL){
		mosquitto_log_printf(MOSQ_LOG_WARNING, "Warning: Dynamic security plugin has no plugin_opt_config_file defined. The plugin will not be activated.");
		return MOSQ_ERR_SUCCESS;
	}

    if (dynsec_data.config_format == CONFIG_FORMAT_AUTO) dynsec_data.config_format = auto_detect_config_file_format(dynsec_data.config_file);

	plg_id = identifier;
	mosquitto_plugin_set_info(identifier, "dynamic-security", NULL);

	dynsec__config_load(&dynsec_data);

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

	return MOSQ_ERR_SUCCESS;
error:
	mosquitto_free(dynsec_data.config_file);
	mosquitto_free(dynsec_data.password_init_file);
	dynsec_data.config_file = NULL;
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

	return MOSQ_ERR_SUCCESS;
}
