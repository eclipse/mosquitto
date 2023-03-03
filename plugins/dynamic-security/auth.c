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
#include "mosquitto.h"
#include "mosquitto_broker.h"


/* ################################################################
 * #
 * # Username/password check
 * #
 * ################################################################ */

static int memcmp_const(const void *a, const void *b, size_t len)
{
	size_t i;
	int rc = 0;

	if(!a || !b) return 1;

	for(i=0; i<len; i++){
		if( ((char *)a)[i] != ((char *)b)[i] ){
			rc = 1;
		}
	}
	return rc;
}


int dynsec_auth__basic_auth_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_basic_auth *ed = event_data;
	struct dynsec__data *data = userdata;
	struct dynsec__client *client;
	unsigned char password_hash[64]; /* For SHA512 */
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
		if(client->pw.valid && dynsec_auth__pw_hash(client, ed->password, password_hash, sizeof(password_hash), false) == MOSQ_ERR_SUCCESS){
			if(memcmp_const(client->pw.password_hash, password_hash, sizeof(password_hash)) == 0){
				return MOSQ_ERR_SUCCESS;
			}else{
				return MOSQ_ERR_AUTH;
			}
		}else{
			return MOSQ_ERR_PLUGIN_DEFER;
		}
	}else{
		return MOSQ_ERR_PLUGIN_DEFER;
	}
}
