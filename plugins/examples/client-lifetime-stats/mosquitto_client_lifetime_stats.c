/*
Copyright (c) 2021 Roger Light <roger@atchoo.org>

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
 * Publish statistics on client session lifetimes.
 *
 * Compile with:
 *   gcc -I<path to mosquitto-repo/include> -fPIC -shared mosquitto_client_lifetime_stats.c -o mosquitto_client_lifetime_stats.so
 *
 * Use in config with:
 *
 *   plugin /path/to/mosquitto_client_lifetime_stats.so
 *
 * Note that this only works on Mosquitto 2.0 or later.
 */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <uthash.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

static mosquitto_plugin_id_t *mosq_pid = NULL;

struct lifetime_s{
	UT_hash_handle hh;
	char *id;
	time_t connect;
};
struct lifetime_s *local_lifetimes = NULL;

#define LIFETIME_COUNT 28
static const char *lifetime_strs[LIFETIME_COUNT] = {
	"0",
	"1", "2", "5",
	"10", "20", "50",
	"100", "200", "500",
	"1k", "2k", "5k",
	"10k", "20k", "50k",
	"100k", "200k", "500k",
	"1M", "2M", "5M",
	"10M", "20M", "50M",
	"100M", "200M", "500M"
};

static uint32_t lifetime_values[LIFETIME_COUNT] = {
	0,
	1, 2, 5,
	10, 20, 50,
	100, 200, 500,
	1000, 2000, 5000,
	10000, 20000, 50000,
	100000, 200000, 500000,
	1000000, 2000000, 5000000,
	10000000, 20000000, 50000000,
	100000000, 200000000, 500000000
};

static long lifetime_counts[LIFETIME_COUNT];
static long last_lifetime_counts[LIFETIME_COUNT];
static time_t last_report = 0;


static int callback_tick(int event, void *event_data, void *userdata)
{
	struct timespec ts;
	char topic[40];
	char payload[40];
	int slen;
	int i;

	UNUSED(event);
	UNUSED(event_data);
	UNUSED(userdata);

	clock_gettime(CLOCK_REALTIME, &ts);
	if(last_report + 10 < ts.tv_sec){
		last_report = ts.tv_sec;

		for(i=0; i<LIFETIME_COUNT; i++){
			if(lifetime_counts[i] != last_lifetime_counts[i]){
				snprintf(topic, sizeof(topic), "$SYS/broker/client/lifetimes/%s", lifetime_strs[i]);
				slen = snprintf(payload, sizeof(payload), "%ld", lifetime_counts[i]);
				mosquitto_broker_publish_copy(NULL, topic, slen, payload, 0, 1, NULL);
				last_lifetime_counts[i] = lifetime_counts[i];
			}
		}
	}

	return MOSQ_ERR_SUCCESS;
}


static int callback_connect(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_connect *ed = event_data;
	const char *id;
	struct lifetime_s *client;

	UNUSED(event);
	UNUSED(userdata);

	id = mosquitto_client_id(ed->client);
	if(id){
		HASH_FIND(hh, local_lifetimes, id, strlen(id), client);
		if(!client){
			client = malloc(sizeof(struct lifetime_s));
			if(client == NULL){
				return MOSQ_ERR_SUCCESS;
			}
			client->id = strdup(id);
			if(client->id == NULL){
				free(client);
				return MOSQ_ERR_SUCCESS;
			}
			client->connect = time(NULL);
			HASH_ADD_KEYPTR(hh, local_lifetimes, client->id, strlen(client->id), client);
		}
	}

	return MOSQ_ERR_SUCCESS;
}


static int callback_disconnect(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_disconnect *ed = event_data;
	int i;
	const char *id;
	struct lifetime_s *client;
	time_t lifetime;

	UNUSED(event);
	UNUSED(userdata);

	id = mosquitto_client_id(ed->client);
	if(id){
		HASH_FIND(hh, local_lifetimes, id, strlen(id), client);
		if(client){
			HASH_DELETE(hh, local_lifetimes, client);

			lifetime = time(NULL) - client->connect;
			free(client->id);
			free(client);

			for(i=0; i<LIFETIME_COUNT; i++){
				if(lifetime <= lifetime_values[i]){
					lifetime_counts[i]++;
					break;
				}
			}
		}
	}

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	memset(lifetime_counts, 0, sizeof(lifetime_counts));
	memset(last_lifetime_counts, 0, sizeof(last_lifetime_counts));

	mosq_pid = identifier;
	mosquitto_callback_register(mosq_pid, MOSQ_EVT_CONNECT, callback_connect, NULL, NULL);
	mosquitto_callback_register(mosq_pid, MOSQ_EVT_DISCONNECT, callback_disconnect, NULL, NULL);
	mosquitto_callback_register(mosq_pid, MOSQ_EVT_TICK, callback_tick, NULL, NULL);

	return MOSQ_ERR_SUCCESS;
}
