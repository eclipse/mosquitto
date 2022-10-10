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
 * # Password functions
 * #
 * ################################################################ */

int dynsec_auth__pw_hash(struct dynsec__client *client, const char *password, unsigned char *password_hash, int password_hash_len, bool new_password)
{
	const EVP_MD *digest;
	int iterations;

	if(new_password){
		client->pw.salt_len = HASH_LEN;
		if(RAND_bytes(client->pw.salt, (int)client->pw.salt_len) != 1){
			return MOSQ_ERR_UNKNOWN;
		}
		if(client->pw.iterations > 0){
			iterations = client->pw.iterations;
		}else{
			iterations = PW_DEFAULT_ITERATIONS;
		}
	}else{
		iterations = client->pw.iterations;
	}
	if(iterations < 1){
		return MOSQ_ERR_INVAL;
	}
	client->pw.iterations = iterations;

	digest = EVP_get_digestbyname("sha512");
	if(!digest){
		return MOSQ_ERR_UNKNOWN;
	}

	return !PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
			client->pw.salt, (int)client->pw.salt_len, iterations,
			digest, password_hash_len, password_hash);
}
