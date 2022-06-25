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
 * Publish statistics on message payload size.
 *
 * Compile with:
 *   gcc -I<path to mosquitto-repo/include> -fPIC -shared mosquitto_payload_size_stats.c -o mosquitto_payload_size_stats.so
 *
 * Use in config with:
 *
 *   plugin /path/to/mosquitto_payload_size_stats.so
 *
 * Note that this only works on Mosquitto 2.0 or later.
 */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

static mosquitto_plugin_id_t *mosq_pid = NULL;

#define SIZE_COUNT 28
static const char *size_strs[SIZE_COUNT] = {
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

static uint32_t size_values[SIZE_COUNT] = {
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

static long size_counts[SIZE_COUNT];
static long last_size_counts[SIZE_COUNT];
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

		for(i=0; i<SIZE_COUNT; i++){
			if(size_counts[i] != last_size_counts[i]){
				snprintf(topic, sizeof(topic), "$SYS/broker/publish/sizes/%s", size_strs[i]);
				slen = snprintf(payload, sizeof(payload), "%ld", size_counts[i]);
				mosquitto_broker_publish_copy(NULL, topic, slen, payload, 0, 1, NULL);
				last_size_counts[i] = size_counts[i];
			}
		}
	}

	return MOSQ_ERR_SUCCESS;
}


static int callback_message(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_message *ed = event_data;
	int i;

	UNUSED(event);
	UNUSED(userdata);

	for(i=0; i<SIZE_COUNT; i++){
		if(ed->payloadlen <= size_values[i]){
			size_counts[i]++;
			break;
		}
	}

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	memset(size_counts, 0, sizeof(size_counts));
	memset(last_size_counts, 0, sizeof(last_size_counts));

	mosq_pid = identifier;
	mosquitto_callback_register(mosq_pid, MOSQ_EVT_MESSAGE_WRITE, callback_message, NULL, NULL);
	mosquitto_callback_register(mosq_pid, MOSQ_EVT_TICK, callback_tick, NULL, NULL);

	return MOSQ_ERR_SUCCESS;
}
