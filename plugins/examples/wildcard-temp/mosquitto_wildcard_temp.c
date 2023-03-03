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
 * This is an example plugin that denies subscriptions to the '#' topic filter,
 * but with special behaviour for clients that connect with the username
 * `wildcard`.
 *
 * The first time per session that clients with this username attempt to
 * subscribe to the '#' topic filter, it will succeed. They will then have 20
 * seconds of access to that subscription, subject to any other access controls
 * that are in place, after which the subscription will be automatically
 * removed.
 *
 * The intention is to allow temporary access to the '#' topic filter so that
 * topic discovery can be done on public servers such as test.mosquitto.org,
 * but also to limit bandwidth use.
 *
 * Compile with:
 *   gcc -I<path to mosquitto-repo/include> -fPIC -shared mosquitto_wildcard_temp.c -o mosquitto_wildcard_temp.so
 *
 * Use in config with:
 *
 *   plugin /path/to/mosquitto_wildcard_temp.so
 *
 * Note that this only works on Mosquitto 2.1 or later.
 */


#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <uthash.h>
#include <utlist.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

#define PLUGIN_NAME "wildcard-temp"
#define PLUGIN_VERSION "1.0"

/* How long the client has '#' access for, in seconds */
#define ACCESS_PERIOD 20

#ifndef UNUSED
#  define UNUSED(A) (void)(A)
#endif

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

struct client_list{
	UT_hash_handle hh;
	struct client_list *next, *prev;
	time_t sub_end;
	uint8_t sub_status;
	char id[];
};

static mosquitto_plugin_id_t *mosq_pid = NULL;
static struct client_list *clients = NULL;
static struct client_list *active_subs = NULL;

static int connect_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_basic_auth *ed = event_data;
	static struct client_list *client;
	const char *id, *username;
	size_t idlen;

	UNUSED(event);
	UNUSED(userdata);

	username = mosquitto_client_username(ed->client);
	if(!username || strcmp(username, "wildcard")){
		return MOSQ_ERR_SUCCESS;
	}

	id = mosquitto_client_id(ed->client);
	idlen = strlen(id);

	HASH_FIND(hh, clients, id, idlen, client);
	if(client){
		return MOSQ_ERR_SUCCESS;
	}else{
		client = mosquitto_calloc(1, sizeof(struct client_list) + idlen+1);
		if(client == NULL){
			return MOSQ_ERR_NOMEM;
		}

		memcpy(client->id, id, idlen);
		HASH_ADD_KEYPTR(hh, clients, client->id, idlen, client);
	}

	return MOSQ_ERR_SUCCESS;
}


static int disconnect_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_basic_auth *ed = event_data;
	static struct client_list *client;
	const char *id;
	size_t idlen;

	UNUSED(event);
	UNUSED(userdata);

	id = mosquitto_client_id(ed->client);
	idlen = strlen(id);

	HASH_FIND(hh, clients, id, idlen, client);
	if(client){
		HASH_DELETE(hh, clients, client);
		if(active_subs){
			DL_DELETE(active_subs, client);
		}
		mosquitto_free(client);
	}

	return MOSQ_ERR_SUCCESS;
}


static int acl_check_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_acl_check *ed = event_data;
	static struct client_list *client;
	const char *id;

	UNUSED(event);
	UNUSED(userdata);

	if(ed->access == MOSQ_ACL_SUBSCRIBE && !strcmp(ed->topic, "#")){
		id = mosquitto_client_id(ed->client);
		HASH_FIND(hh, clients, id, strlen(id), client);
		if(client && client->sub_status == 0){
			client->sub_status = 1;
			client->sub_end = time(NULL) + ACCESS_PERIOD;
			DL_APPEND(active_subs, client);
			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_ACL_DENIED;
		}
	}

	return MOSQ_ERR_PLUGIN_IGNORE;
}


static int tick_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_tick *ed = event_data;
	struct client_list *client, *client_tmp;
	time_t now;

	UNUSED(event);
	UNUSED(userdata);

	now = time(NULL);
	DL_FOREACH_SAFE(active_subs, client, client_tmp){
		if(client->sub_end < now){
			mosquitto_subscription_delete(client->id, "#");
			DL_DELETE(active_subs, client);
		}else{
			break;
		}
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

	rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_CONNECT, connect_callback, NULL, NULL);
	rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_DISCONNECT, disconnect_callback, NULL, NULL);
	rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_ACL_CHECK, acl_check_callback, NULL, NULL);
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
		mosquitto_free(client);
	}

	return MOSQ_ERR_SUCCESS;
}
