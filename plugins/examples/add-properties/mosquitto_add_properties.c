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
   Simon Christmann - use timestamp in unix epoch milliseconds; add client properties
*/

/*
 * Adds MQTT v5 user-properties to incoming messages:
 *  - $timestamp: unix epoch in milliseconds
 *  - $client_id: client id of the publishing client
 *  - $client_username: username that the publishing client used to authenticate
 *
 * Compile with:
 *   gcc -I<path to mosquitto-repo/include> -fPIC -shared add_properties.c -o add_properties.so
 *
 * Use in config with:
 *
 *   plugin /path/to/add_properties.so
 *
 * Note that this only works on Mosquitto 2.0 or later.
 */
#include "config.h"

#include <stdio.h>
#include <time.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

#define TS_BUF_LEN (14+1)  // 14 characters in unix epoch (ms) is ≈16 Nov 5138
#define PLUGIN_NAME "add-properties"
#define PLUGIN_VERSION "1.0"

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

static mosquitto_plugin_id_t *mosq_pid = NULL;

static int callback_message(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_message *ed = event_data;
	int result;
	struct timespec ts;
	char ts_buf[TS_BUF_LEN];

	UNUSED(event);
	UNUSED(userdata);

	// Add timestamp in unix epoch (ms)
	clock_gettime(CLOCK_REALTIME, &ts);
	snprintf(ts_buf, TS_BUF_LEN, "%li%03lu", ts.tv_sec, ts.tv_nsec / 1000 / 1000);
	
	result = mosquitto_property_add_string_pair(
		&ed->properties,
		MQTT_PROP_USER_PROPERTY,
		"$timestamp",
		ts_buf);
	if (result != MOSQ_ERR_SUCCESS) return result;

	// Add client id
	result = mosquitto_property_add_string_pair(
		&ed->properties,
		MQTT_PROP_USER_PROPERTY,
		"$client_id",
		mosquitto_client_id(ed->client));
	if (result != MOSQ_ERR_SUCCESS) return result;

	// Add client username
	result = mosquitto_property_add_string_pair(
		&ed->properties,
		MQTT_PROP_USER_PROPERTY,
		"$client_username",
		mosquitto_client_username(ed->client));
	if (result != MOSQ_ERR_SUCCESS) return result;

	// If no return occurred up to this point, we were successful
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	mosq_pid = identifier;
	mosquitto_plugin_set_info(identifier, PLUGIN_NAME, PLUGIN_VERSION);
	return mosquitto_callback_register(mosq_pid, MOSQ_EVT_MESSAGE, callback_message, NULL, NULL);
}
