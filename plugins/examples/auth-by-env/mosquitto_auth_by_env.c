/*
Copyright (c) 2021 Frank Villaro-Dixon <frank@villaro-dixon.eu>

This plugin is under the WTFPL. Do what you want with it.

SPDX-License-Identifier: WTFPL

Contributors:
   Frank Villaro-Dixon - initial implementation and documentation.
*/

/*
 * This plugin allows users to authenticate with any username, as long as
 * the provided password matches the MOSQUITTO_PASSWORD environment variable.
 * If the MOSQUITTO_PASSWORD env variable is empty, then authentication is rejected.
 *
 * Compile with:
 *   gcc -I<path to mosquitto-repo/include> -fPIC -shared mosquitto_auth_by_env.c -o mosquitto_auth_by_env.so
 *
 * Use in config with:
 *
 *   plugin /path/to/mosquitto_auth_by_env.so
 *
 * Note that this only works on Mosquitto 2.0 or later.
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

#define ENV_MOSQUITTO_PASSWORD "MOSQUITTO_PASSWORD"

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

static mosquitto_plugin_id_t *mosq_pid = NULL;
static char *environment_password = NULL;

static int basic_auth_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_basic_auth *ed = event_data;

	UNUSED(event);
	UNUSED(userdata);

	if(!environment_password || !ed->password){
		return MOSQ_ERR_PLUGIN_DEFER;
	}
	if(!strcmp(ed->password, environment_password)){
		/* Password matched MOSQUITTO_PASSWORD */
		return MOSQ_ERR_SUCCESS;
	}
	else{
		return MOSQ_ERR_PLUGIN_DEFER;
	}
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	char *env_var_content;

	mosq_pid = identifier;

	env_var_content = getenv(ENV_MOSQUITTO_PASSWORD);
	if(env_var_content && strlen(env_var_content) > 0){
		environment_password = mosquitto_strdup(env_var_content);
		if(!environment_password){
			mosquitto_log_printf(MOSQ_LOG_ERR, "Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
		return mosquitto_callback_register(mosq_pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL, NULL);
	}

	mosquitto_log_printf(MOSQ_LOG_ERR, "auth-by-env plugin called, but " ENV_MOSQUITTO_PASSWORD " environment variable is empty");
	return MOSQ_ERR_INVAL;
}

/* mosquitto_plugin_cleanup() is optional in 2.1 and later. Use it only if you have your own cleanup to do */
int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	return MOSQ_ERR_SUCCESS;
}
