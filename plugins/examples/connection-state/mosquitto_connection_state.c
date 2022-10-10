/*
Copyright (c) 2021 Roger Light <roger@atchoo.org>

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
 * This is an example plugin showing how you could publish online/offline
 * state for all clients.
 *
 * Compile with:
 *   gcc -I<path to mosquitto-repo/include> -fPIC -shared mosquitto_connection_state.c -o mosquitto_connection_state.so
 *
 * Use in config with:
 *
 *   plugin /path/to/mosquitto_connection_state.so
 *
 * Note that this only works on Mosquitto 2.0 or later.
 */


#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

#define PLUGIN_NAME "connection-state"
#define PLUGIN_VERSION "1.0"

#define UNUSED(A) (void)(A)

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

static mosquitto_plugin_id_t *mosq_pid = NULL;

static int connect_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_connect *ed = event_data;
	const char *client_id;
	char topic[1024];
	int len;

	UNUSED(event);
	UNUSED(userdata);

	client_id = mosquitto_client_id(ed->client);
	len = snprintf(topic, sizeof(topic), "$SYS/broker/connection/client/%s/state", client_id);
	if(len < (int)sizeof(topic)){
		mosquitto_broker_publish_copy(NULL, topic, 1, "1", 0, true, NULL);
	}else{
		/* client id too large */
	}

	return MOSQ_ERR_SUCCESS;
}

static int disconnect_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_disconnect *ed = event_data;
	const char *client_id;
	char topic[1024];
	int len;
	mosquitto_property *proplist = NULL;
	int rc;

	UNUSED(event);
	UNUSED(userdata);

	client_id = mosquitto_client_id(ed->client);
	len = snprintf(topic, sizeof(topic), "$SYS/broker/connection/client/%s/state", client_id);
	if(len < (int)sizeof(topic)){
		/* Expire our "disconnected" message after a day. */
		mosquitto_property_add_int32(&proplist, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, 86400);
		rc = mosquitto_broker_publish_copy(NULL, topic, 1, "0", 0, true, proplist);
		if(rc){
			mosquitto_property_free_all(&proplist);
		}
	}else{
		/* client id too large */
	}

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
	int rc;

	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	mosq_pid = identifier;
	mosquitto_plugin_set_info(identifier, PLUGIN_NAME, PLUGIN_VERSION);

	rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_CONNECT, connect_callback, NULL, NULL);
	if(rc) return rc;
	rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_DISCONNECT, disconnect_callback, NULL, NULL);
	return rc;
}
