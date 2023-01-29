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

void dynsec_clientlist__kick_all(struct dynsec__data *data, struct dynsec__clientlist *base_clientlist)
{
	struct dynsec__clientlist *clientlist, *clientlist_tmp;

	HASH_ITER(hh, base_clientlist, clientlist, clientlist_tmp){
		dynsec_kicklist__add(data, clientlist->client->username);
	}
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
