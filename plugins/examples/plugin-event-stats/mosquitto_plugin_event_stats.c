/*
Copyright (c) 2022 Cedalo Gmbh

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

/*
 * Publish statistics on plugin event counts
 *
 * Compile with:
 *   gcc -I<path to mosquitto-repo/include> -fPIC -shared mosquitto_plugin_event_stats.c -o mosquitto_plugin_event_stats.so
 *
 * Use in config with:
 *
 *   plugin /path/to/mosquitto_plugin_event_stats.so
 *
 * Note that this only works on Mosquitto 2.1 or later.
 */
#include "config.h"

#include <stdio.h>
#include <string.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"

#define PLUGIN_NAME "plugin-event-stats"
#define PLUGIN_VERSION "1.0"

#define MAX_EVT MOSQ_EVT_PERSIST_CLIENT_MSG_LOAD
MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

static mosquitto_plugin_id_t *mosq_pid = NULL;

static uint64_t evt_counts[MAX_EVT+1];
static uint64_t last_evt_counts[MAX_EVT+1];
static time_t last_report = 0;

#define TOPIC_BASE "$SYS/broker/plugin/events/"

const char evt_topics[][60] = {
	"", /* No event */
	TOPIC_BASE "reload", /* MOSQ_EVT_RELOAD */
	TOPIC_BASE "acl_check", /* MOSQ_EVT_ACL_CHECK */
	TOPIC_BASE "auth/basic", /* MOSQ_EVT_BASIC_AUTH */
	TOPIC_BASE "auth/ext/start", /* MOSQ_EVT_EXT_AUTH_START */
	TOPIC_BASE "auth/ext/continue", /* MOSQ_EVT_EXT_AUTH_CONTINUE */
	TOPIC_BASE "control", /* MOSQ_EVT_CONTROL */
	TOPIC_BASE "message", /* MOSQ_EVT_MESSAGE */
	TOPIC_BASE "psk_key", /* MOSQ_EVT_PSK_KEY */
	TOPIC_BASE "tick", /* MOSQ_EVT_TICK */
	TOPIC_BASE "disconnect", /* MOSQ_EVT_DISCONNECT */
	TOPIC_BASE "connect", /* MOSQ_EVT_CONNECT */
	TOPIC_BASE "subscribe", /* MOSQ_EVT_SUBSCRIBE */
	TOPIC_BASE "unsubscribe", /* MOSQ_EVT_UNSUBSCRIBE */
	TOPIC_BASE "persist/restore", /* MOSQ_EVT_PERSIST_RESTORE */
	TOPIC_BASE "persist/config/add", /* MOSQ_EVT_PERSIST_CONFIG_ADD */
	TOPIC_BASE "persist/message/base/add", /* MOSQ_EVT_PERSIST_MSG_ADD */
	TOPIC_BASE "persist/message/base/delete", /* MOSQ_EVT_PERSIST_MSG_DELETE */
	TOPIC_BASE "persist/message/base/load", /* MOSQ_EVT_PERSIST_MSG_LOAD */
	TOPIC_BASE "persist/message/retain/set", /* MOSQ_EVT_PERSIST_RETAIN_SET */
	TOPIC_BASE "persist/message/retain/delete", /* MOSQ_EVT_PERSIST_RETAIN_DELETE */
	TOPIC_BASE "persist/client/add", /* MOSQ_EVT_PERSIST_CLIENT_ADD */
	TOPIC_BASE "persist/client/delete", /* MOSQ_EVT_PERSIST_CLIENT_DELETE */
	TOPIC_BASE "persist/client/update", /* MOSQ_EVT_PERSIST_CLIENT_UPDATE */
	TOPIC_BASE "persist/subscription/add", /* MOSQ_EVT_PERSIST_SUBSCRIPTION_ADD */
	TOPIC_BASE "persist/subscription/delete", /* MOSQ_EVT_PERSIST_SUBSCRIPTION_DELETE */
	TOPIC_BASE "persist/message/client/add", /* MOSQ_EVT_PERSIST_CLIENT_MSG_ADD */
	TOPIC_BASE "persist/message/client/delete", /* MOSQ_EVT_PERSIST_CLIENT_MSG_DELETE */
	TOPIC_BASE "persist/message/client/update", /* MOSQ_EVT_PERSIST_CLIENT_MSG_UPDATE */
	TOPIC_BASE "persist/message/client/clear", /* MOSQ_EVT_PERSIST_CLIENT_MSG_CLEAR */
	TOPIC_BASE "persist/message/client/load", /* MOSQ_EVT_PERSIST_CLIENT_MSG_LOAD */
};

static int callback_tick(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_tick *ed = event_data;
	char payload[40];
	int slen;

	UNUSED(event);
	UNUSED(userdata);

	if(last_report + 10 < ed->now_s){
		last_report = ed->now_s;

		for(int i=1; i<MAX_EVT+1; i++){
			if(evt_counts[i] != last_evt_counts[i]){
				slen = snprintf(payload, sizeof(payload), "%ld", evt_counts[i]);
				mosquitto_broker_publish_copy(NULL, evt_topics[i], slen, payload, 0, 1, NULL);
				last_evt_counts[i] = evt_counts[i];
			}
		}
	}

	return MOSQ_ERR_SUCCESS;
}


static int callback_counter(int event, void *event_data, void *userdata)
{
	UNUSED(event_data);
	UNUSED(userdata);

	if(event < 0 || event > MAX_EVT){
		return MOSQ_ERR_SUCCESS;
	}else{
		evt_counts[event]++;
	}

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	memset(evt_counts, 0, sizeof(evt_counts));
	memset(last_evt_counts, 0, sizeof(last_evt_counts));

	mosq_pid = identifier;
	mosquitto_plugin_set_info(identifier, PLUGIN_NAME, PLUGIN_VERSION);

	mosquitto_callback_register(mosq_pid, MOSQ_EVT_TICK, callback_tick, NULL, NULL);
	for(int i=1; i<MAX_EVT+1; i++){
		if(i != MOSQ_EVT_TICK){
			mosquitto_callback_register(mosq_pid, i, callback_counter, NULL, NULL);
		}
	}

	return MOSQ_ERR_SUCCESS;
}
