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

static mosquitto_plugin_id_t *mosq_pid = NULL;
static char *environment_password;

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

int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)
{
	int i;

	for(i=0; i<supported_version_count; i++){
		if(supported_versions[i] == 5){
			return 5;
		}
	}
	return -1;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	char *env_var_content;

	mosq_pid = identifier;

	env_var_content = getenv(ENV_MOSQUITTO_PASSWORD);
	if(env_var_content){
		if(strlen(env_var_content) > 0){
			environment_password = strdup(env_var_content);
			return mosquitto_callback_register(mosq_pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL, NULL);
		}
	}

	log__printf(NULL, MOSQ_LOG_INFO, "Auth-by-env plugin called, but "ENV_MOSQUITTO_PASSWORD" env var is empty\n");
	return 0;
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	free(environment_password);

	return mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL);
}
