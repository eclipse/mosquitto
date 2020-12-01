/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>

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
 * Add an MQTT v5 user-property with key "timestamp" and value of timestamp in ISO-8601 format to all messages.
 *
 * Compile with:
 *   gcc -I<path to mosquitto-repo/include> -fPIC -shared mosquitto_timestamp.c -o mosquitto_timestamp.so
 *
 * Use in config with:
 *
 *   plugin /path/to/mosquitto_timestamp.so
 *
 * Note that this only works on Mosquitto 2.0 or later.
 */


#include <stdio.h>
#include <time.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

static mosquitto_plugin_id_t *mosq_pid = NULL;

static int callback_message(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_message *ed = event_data;
	struct timespec ts;
	struct tm *ti;
	char time_buf[25];

	clock_gettime(CLOCK_REALTIME, &ts);
	ti = gmtime(&ts.tv_sec);
	strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", ti);

	return mosquitto_property_add_string_pair(&ed->properties, MQTT_PROP_USER_PROPERTY, "timestamp", time_buf);
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
	mosq_pid = identifier;
	return mosquitto_callback_register(mosq_pid, MOSQ_EVT_MESSAGE, callback_message, NULL, NULL);
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
	return mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_MESSAGE, callback_message, NULL);
}
