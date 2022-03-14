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
   Abilio Marques - initial implementation and documentation.
*/

/*
 * This is an *example* plugin which demonstrates how to jail a client.
 * It mounts such client topics in a subtree starting with the client id.
 * It modifies it's subscriptions and the topics of the messages destined to
 * that client. It also modifies the topics of the messages published
 * by the client.
 *
 *  client | event | destination | original topic       | modified topic
 *  -------|-------|-------------|----------------------|--------------------
 *  jailed |  sub  |     ---     | topic                | ${jailed_id}/topic
 *  normal |  pub  |   jailed    | ${jailed_id}/topic   | topic
 *  jailed |  pub  |   normal    | topic                | ${jailed_id}/topic
 *
 * For simplicity of this example, all clients with id starting with "jailed"
 * will be jailed. All other clients will work as normal.
 * 
 * Two jailed clients cannot interact with each other. Normal clients can interact
 * with any jailed client by publishing or subscribing to the mounted topic.
 *
 * You should be very sure of what you are doing before making use of this feature.
 *
 * Compile with:
 *   gcc -I<path to mosquitto-repo/include> -fPIC -shared mosquitto_topic_jail.c -o mosquitto_topic_jail.so
 *
 * Use in config with:
 *
 *   plugin /path/to/mosquitto_topic_jail.so
 *
 * Note that this only works on Mosquitto 2.0 or later.
 */
#include <stdio.h>
#include <string.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

#define PLUGIN_NAME "topic-jail"
#define PLUGIN_VERSION "1.0"

#define UNUSED(A) (void)(A)

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

static mosquitto_plugin_id_t *mosq_pid = NULL;

static bool is_jailed(const char *str)
{
	return strncmp("jailed", str, 6) == 0;
}


static int callback_message_write(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_message *ed = event_data;
	char *new_topic;
	size_t new_topic_len;

	UNUSED(event);
	UNUSED(userdata);

	const char *client_id = mosquitto_client_id(ed->client);

	if(!is_jailed(client_id)){
		/* will only modify the topic of jailed clients */
		return MOSQ_ERR_SUCCESS;
	}

	/* put the client_id on front of the topic */

	/* calculate the length of the new payload */
	new_topic_len = strlen(client_id) + sizeof('/') + strlen(ed->topic) + 1;

	/* Allocate some memory - use
	 * mosquitto_calloc/mosquitto_malloc/mosquitto_strdup when allocating, to
	 * allow the broker to track memory usage */
	new_topic = mosquitto_calloc(1, new_topic_len);
	if(new_topic == NULL){
		return MOSQ_ERR_NOMEM;
	}

	/* prepend the client_id to the topic */
	snprintf(new_topic, new_topic_len, "%s/%s", client_id, ed->topic);

	/* Assign the new topic to the event data structure. You
	 * must *not* free the original topic, it will be handled by the
	 * broker. */
	ed->topic = new_topic;

	return MOSQ_ERR_SUCCESS;
}

static int callback_message_read(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_message *ed = event_data;
	size_t client_id_len;

	UNUSED(event);
	UNUSED(userdata);

	const char *client_id = mosquitto_client_id(ed->client);

	if(!is_jailed(client_id)){
		/* will only modify the topic of jailed clients */
		return MOSQ_ERR_SUCCESS;
	}

	/* remove the client_id from the front of the topic */
	client_id_len = strlen(client_id);

	if(strlen(ed->topic) <= client_id_len + 1){
		/* the topic is not long enough to contain the
		 * client_id + '/' */
		return MOSQ_ERR_SUCCESS;
	}

	if(!strncmp(client_id, ed->topic, client_id_len) && ed->topic[client_id_len] == '/'){
		/* Allocate some memory - use
		 * mosquitto_calloc/mosquitto_malloc/mosquitto_strdup when allocating, to
		 * allow the broker to track memory usage */

		/* skip the client_id + '/' */
		char *new_topic = mosquitto_strdup(ed->topic + client_id_len + 1);

		if(new_topic == NULL){
			return MOSQ_ERR_NOMEM;
		}

		/* Assign the new topic to the event data structure. You
		 * must *not* free the original topic, it will be handled by the
		 * broker. */
		ed->topic = new_topic;
	}

	return MOSQ_ERR_SUCCESS;
}

static int callback_subscribe(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_subscribe *ed = event_data;
	char *new_sub;
	size_t new_sub_len;

	UNUSED(event);
	UNUSED(userdata);

	const char *client_id = mosquitto_client_id(ed->client);

	if(!is_jailed(client_id)){
		/* will only modify the topic of jailed clients */
		return MOSQ_ERR_SUCCESS;
	}

	/* put the client_id on front of the topic */

	/* calculate the length of the new payload */
	new_sub_len = strlen(client_id) + sizeof('/') + strlen(ed->topic) + 1;

	/* Allocate some memory - use
	 * mosquitto_calloc/mosquitto_malloc/mosquitto_strdup when allocating, to
	 * allow the broker to track memory usage */
	new_sub = mosquitto_calloc(1, new_sub_len);
	if(new_sub == NULL){
		return MOSQ_ERR_NOMEM;
	}

	/* prepend the client_id to the subscription */
	snprintf(new_sub, new_sub_len, "%s/%s", client_id, ed->topic);

	/* Assign the new topic to the event data structure. You
	 * must *not* free the original topic, it will be handled by the
	 * broker. */
	ed->topic = new_sub;

	return MOSQ_ERR_SUCCESS;
}

static int callback_unsubscribe(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_unsubscribe *ed = event_data;
	char *new_sub;
	size_t new_sub_len;

	UNUSED(event);
	UNUSED(userdata);

	const char *client_id = mosquitto_client_id(ed->client);

	if(!is_jailed(client_id)){
		/* will only modify the topic of jailed clients */
		return MOSQ_ERR_SUCCESS;
	}

	/* put the client_id on front of the topic */

	/* calculate the length of the new payload */
	new_sub_len = strlen(client_id) + sizeof('/') + strlen(ed->topic) + 1;

	/* Allocate some memory - use
	 * mosquitto_calloc/mosquitto_malloc/mosquitto_strdup when allocating, to
	 * allow the broker to track memory usage */
	new_sub = mosquitto_calloc(1, new_sub_len);
	if(new_sub == NULL){
		return MOSQ_ERR_NOMEM;
	}

	/* prepend the client_id to the subscription */
	snprintf(new_sub, new_sub_len, "%s/%s", client_id, ed->topic);

	/* Assign the new topic to the event data structure. You
	 * must *not* free the original topic, it will be handled by the
	 * broker. */
	ed->topic = new_sub;

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	mosq_pid = identifier;
	mosquitto_plugin_set_info(identifier, PLUGIN_NAME, PLUGIN_VERSION);

	int rc;

	rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_MESSAGE_WRITE, callback_message_write, NULL, NULL);
	if(rc) return rc;
	rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_MESSAGE_READ, callback_message_read, NULL, NULL);
	if(rc) return rc;
	rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_SUBSCRIBE, callback_subscribe, NULL, NULL);
	if(rc) return rc;
	rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_UNSUBSCRIBE, callback_unsubscribe, NULL, NULL);
	return rc;
}
