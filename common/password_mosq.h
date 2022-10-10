#ifndef PASSWORD_COMMON_H
#define PASSWORD_COMMON_H
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
};

#define PW_DEFAULT_ITERATIONS 101

struct mosquitto_pw{
	unsigned char password_hash[HASH_LEN]; /* For SHA512 */
	unsigned char salt[HASH_LEN];
	size_t salt_len;
	int iterations;
	enum mosquitto_pwhash_type hashtype;
	bool valid;
};

int pw__hash(const char *password, struct mosquitto_pw *pw, bool new_password, int new_iterations);
int pw__memcmp_const(const void *ptr1, const void *b, size_t len);

#endif
