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
 * This is an example plugin showing how to carry out delayed authentication.
 * The "authentication" in this example makes no checks whatsoever, but delays
 * the response by 5 seconds, and randomly chooses whether it should succeed.
 *
 * Compile with:
 *   gcc -I<path to mosquitto-repo/include> -fPIC -shared mosquitto_delayed_auth.c -o mosquitto_delayed_auth.so
 *
 * Use in config with:
 *
 *   plugin /path/to/mosquitto_delayed_auth.so
 *
 * Note that this only works on Mosquitto 2.0 or later.
 */


#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <uthash.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

#define PLUGIN_NAME "delayed-auth"
#define PLUGIN_VERSION "1.0"

#ifndef UNUSED
#  define UNUSED(A) (void)(A)
#endif

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

struct client_list{
	UT_hash_handle hh;
	char *id;
	time_t request_time;
};

static mosquitto_plugin_id_t *mosq_pid = NULL;
static struct client_list *clients = NULL;
static time_t last_check = 0;

static bool authentication_check(struct client_list *client, time_t now)
{
	time_t secs;

	secs = now - client->request_time;

	return secs > 5 ? true : false;
}

static int basic_auth_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_basic_auth *ed = event_data;
	static struct client_list *client;
	const char *id;

	UNUSED(event);
	UNUSED(userdata);

	id = mosquitto_client_id(ed->client);

	HASH_FIND(hh, clients, id, strlen(id), client);
	if(client){
		client->request_time = time(NULL);
	}else{
		client = mosquitto_malloc(sizeof(struct client_list));
		if(client == NULL){
			return MOSQ_ERR_NOMEM;
		}

		client->id = mosquitto_strdup(id);
		if(client->id == NULL){
			mosquitto_free(client);
			return MOSQ_ERR_NOMEM;
		}
		client->request_time = time(NULL);
		HASH_ADD_KEYPTR(hh, clients, client->id, strlen(client->id), client);

		mosquitto_log_printf(MOSQ_LOG_DEBUG, "Starting auth for %s at %ld", client->id, time(NULL));
	}

	return MOSQ_ERR_AUTH_DELAYED;
}


static int tick_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_tick *ed = event_data;
	struct client_list *client, *client_tmp;
	time_t now;
	long r;

	UNUSED(event);
	UNUSED(userdata);

	now = time(NULL);
	if(now >= last_check){
		HASH_ITER(hh, clients, client, client_tmp){
			if(authentication_check(client, now)){
				/* Deny access 1/4 of the time, yes it's biased number generation. */
#ifdef WIN32
				r = rand() % 1000;
#else
				 r = random() % 1000;
#endif
				if(r > 740){
					mosquitto_complete_basic_auth(client->id, MOSQ_ERR_AUTH);
				}else{
					mosquitto_complete_basic_auth(client->id, MOSQ_ERR_SUCCESS);
				}
				mosquitto_log_printf(MOSQ_LOG_DEBUG, "Completing auth for %s at %ld", client->id, now);
				HASH_DELETE(hh, clients, client);
				mosquitto_free(client->id);
				mosquitto_free(client);
			}
		}
		last_check = now;
	}
	/* Declare that we want another call in at most 1 second */
	ed->next_s = 1;

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

	rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL, NULL);
	if(rc) return rc;
	rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_TICK, tick_callback, NULL, NULL);
	return rc;
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
	struct client_list *client, *client_tmp;

	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	HASH_ITER(hh, clients, client, client_tmp){
		HASH_DELETE(hh, clients, client);
		mosquitto_free(client->id);
		mosquitto_free(client);
	}

	return MOSQ_ERR_SUCCESS;
}
