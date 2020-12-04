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

#include "config.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <uthash.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "json_help.h"

#include "dynamic_security.h"

/* ################################################################
 * #
 * # Plugin global variables
 * #
 * ################################################################ */

/* ################################################################
 * #
 * # Function declarations
 * #
 * ################################################################ */

/* ################################################################
 * #
 * # Local variables
 * #
 * ################################################################ */


/* ################################################################
 * #
 * # Utility functions
 * #
 * ################################################################ */

static int dynsec_clientlist__cmp(void *a, void *b)
{
	struct dynsec__clientlist *clientlist_a = a;
	struct dynsec__clientlist *clientlist_b = b;

	return strcmp(clientlist_a->client->username, clientlist_b->client->username);
}


void dynsec_clientlist__kick_all(struct dynsec__clientlist *base_clientlist)
{
	struct dynsec__clientlist *clientlist, *clientlist_tmp;

	HASH_ITER(hh, base_clientlist, clientlist, clientlist_tmp){
		mosquitto_kick_client_by_username(clientlist->client->username, false);
	}
}

cJSON *dynsec_clientlist__all_to_json(struct dynsec__clientlist *base_clientlist)
{
	struct dynsec__clientlist *clientlist, *clientlist_tmp;
	cJSON *j_clients, *j_client;

	j_clients = cJSON_CreateArray();
	if(j_clients == NULL) return NULL;

	HASH_ITER(hh, base_clientlist, clientlist, clientlist_tmp){
		j_client = cJSON_CreateObject();
		if(j_client == NULL){
			cJSON_Delete(j_clients);
			return NULL;
		}
		cJSON_AddItemToArray(j_clients, j_client);

		if(cJSON_AddStringToObject(j_client, "username", clientlist->client->username) == NULL
				|| (clientlist->priority != -1 && cJSON_AddIntToObject(j_client, "priority", clientlist->priority) == NULL)
				){

			cJSON_Delete(j_clients);
			return NULL;
		}
	}
	return j_clients;
}


int dynsec_clientlist__add(struct dynsec__clientlist **base_clientlist, struct dynsec__client *client, int priority)
{
	struct dynsec__clientlist *clientlist;

	HASH_FIND(hh, *base_clientlist, client->username, strlen(client->username), clientlist);
	if(clientlist != NULL){
		/* Client is already in the group */
		return MOSQ_ERR_SUCCESS;
	}

	clientlist = mosquitto_malloc(sizeof(struct dynsec__clientlist));
	if(clientlist == NULL){
		return MOSQ_ERR_NOMEM;
	}

	clientlist->client = client;
	clientlist->priority = priority;
	HASH_ADD_KEYPTR_INORDER(hh, *base_clientlist, client->username, strlen(client->username), clientlist, dynsec_clientlist__cmp);

	return MOSQ_ERR_SUCCESS;
}


void dynsec_clientlist__cleanup(struct dynsec__clientlist **base_clientlist)
{
	struct dynsec__clientlist *clientlist, *clientlist_tmp;

	HASH_ITER(hh, *base_clientlist, clientlist, clientlist_tmp){
		HASH_DELETE(hh, *base_clientlist, clientlist);
		mosquitto_free(clientlist);
	}
}


void dynsec_clientlist__remove(struct dynsec__clientlist **base_clientlist, struct dynsec__client *client)
{
	struct dynsec__clientlist *clientlist;

	HASH_FIND(hh, *base_clientlist, client->username, strlen(client->username), clientlist);
	if(clientlist){
		HASH_DELETE(hh, *base_clientlist, clientlist);
		mosquitto_free(clientlist);
	}
}
