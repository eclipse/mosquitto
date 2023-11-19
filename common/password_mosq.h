#ifndef PASSWORD_MOSQ_H
#define PASSWORD_MOSQ_H
/*
Copyright (c) 2012-2021 Roger Light <roger@atchoo.org>

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

#include <stdbool.h>

#ifdef WITH_TLS
#  include <openssl/evp.h>
#  define HASH_LEN EVP_MAX_MD_SIZE
#else
   /* 64 bytes big enough for SHA512 */
#  define HASH_LEN 64
#endif

enum mosquitto_pwhash_type{
	pw_sha512 = 6,
	pw_sha512_pbkdf2 = 7,
	pw_argon2id = 8,
};

#define PW_DEFAULT_ITERATIONS 101

struct mosquitto_pw{
	union {
		struct {
			unsigned char password_hash[HASH_LEN]; /* For SHA512 */
			unsigned char salt[HASH_LEN];
			size_t salt_len;
		} sha512;
		struct {
			unsigned char password_hash[HASH_LEN]; /* For SHA512 */
			unsigned char salt[HASH_LEN];
			size_t salt_len;
			int iterations;
		} sha512_pbkdf2;
		struct {
			unsigned char password_hash[HASH_LEN];
			unsigned char salt[HASH_LEN];
			size_t salt_len;
			int iterations;
		} argon2id;
	} params;
	char *encoded_password;
	enum mosquitto_pwhash_type hashtype;
	bool valid;
};

int pw__create(struct mosquitto_pw *pw, const char *password);
int pw__encode(struct mosquitto_pw *pw);
int pw__decode(struct mosquitto_pw *pw, const char *password);
int pw__verify(struct mosquitto_pw *pw, const char *password);

#endif
