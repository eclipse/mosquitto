/*
Copyright (c) 2022 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR EDL-1.0

Contributors:
   Roger Light - initial implementation and documentation.
*/

/*
 * This is an example plugin showing how to deny access based on the version of
 * the protocol spec a client connects with. It does no other authentication
 * checks.
 *
 * It could be used with other authentication plugins by specifying it in the
 * config file before another plugin, for example:
 *
 * plugin /usr/lib/mosquitto_deny_protocol_version.so
 * plugin /usr/lib/mosquitto_dynamic_security.so
 *
 * or:
 *
 * plugin /usr/lib/mosquitto_deny_protocol_version.so
 * password_file pwfile
 *
 * It will *not* work on its own.
 *
 * In Mosquitto 2.1, this can be achieved with the `accept_protocol_version`
 * option instead.
 *
 *
 * To compile:
 *
 *   gcc -I<path to mosquitto-repo/include> -fPIC -shared mosquitto_deny_protocol_version.c -o mosquitto_deny_protocol_version.so
 *
 * Note that this only works on Mosquitto 2.0 or later.
 */
#include "config.h"

#include <stdio.h>
#include <string.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

static mosquitto_plugin_id_t *mosq_pid = NULL;

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

static int basic_auth_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_basic_auth *ed = event_data;
	int protocol_version;

	UNUSED(event);
	UNUSED(userdata);

	protocol_version = mosquitto_client_protocol_version(ed->client);

	if(protocol_version == 5 || protocol_version == 4){
		/* Allow access to MQTT v5.0 and v3.1.1 - this passes on responsibility
		 * for the actual auth checks to the next plugin/password file in the
		 * config list. If no other plugins/password file is defined, then
		 * access will be denied. */
		return MOSQ_ERR_PLUGIN_DEFER;
	}else{
		/* Deny access to all others */
		return MOSQ_ERR_AUTH;
	}
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	mosq_pid = identifier;
	return mosquitto_callback_register(mosq_pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL, NULL);
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	return mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_MESSAGE, basic_auth_callback, NULL);
}
