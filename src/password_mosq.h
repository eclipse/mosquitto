#ifndef PASSWORD_COMMON_H
#define PASSWORD_COMMON_H
/*
Copyright (c) 2012-2020 Roger Light <roger@atchoo.org>

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

#include <stdbool.h>

enum mosquitto_pwhash_type{
	pw_sha512 = 6,
	pw_sha512_pbkdf2 = 7,
};

#define SALT_LEN 12
#define PW_DEFAULT_ITERATIONS 101

struct mosquitto_pw{
	unsigned char password_hash[64]; /* For SHA512 */
	unsigned char salt[SALT_LEN];
	int iterations;
	enum mosquitto_pwhash_type hashtype;
	bool valid;
};

int pw__hash(const char *password, struct mosquitto_pw *pw, bool new_password, int new_iterations);
int pw__memcmp_const(const void *ptr1, const void *b, size_t len);
int base64__encode(unsigned char *in, unsigned int in_len, char **encoded);
int base64__decode(char *in, unsigned char **decoded, unsigned int *decoded_len);

#endif
