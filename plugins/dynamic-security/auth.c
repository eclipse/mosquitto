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

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "dynamic_security.h"

/* ################################################################
 * #
 * # Username/password check
 * #
 * ################################################################ */

int dynsec_auth__basic_auth_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_basic_auth *ed = event_data;
	struct dynsec__data *data = userdata;
	struct dynsec__client *client;
	const char *clientid;

	UNUSED(event);
	UNUSED(userdata);

	if(ed->username == NULL || ed->password == NULL) return MOSQ_ERR_PLUGIN_DEFER;

	client = dynsec_clients__find(data, ed->username);
	if(client){
		if(client->disabled){
			return MOSQ_ERR_AUTH;
		}
		if(client->clientid){
			clientid = mosquitto_client_id(ed->client);
			if(clientid == NULL || strcmp(client->clientid, clientid)){
				return MOSQ_ERR_AUTH;
			}
		}
		if(mosquitto_pw_verify(client->pw, ed->password) == MOSQ_ERR_SUCCESS){
			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_AUTH;
		}
	}else{
		return MOSQ_ERR_PLUGIN_DEFER;
	}
}
