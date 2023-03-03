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

#include "config.h"

#include <errno.h>
#ifdef WITH_TLS
#  include <openssl/opensslv.h>
#  include <openssl/evp.h>
#  include <openssl/rand.h>
#  include <openssl/buffer.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "password_mosq.h"

#ifdef WIN32
#  include <windows.h>
#  include <process.h>
#	ifndef __cplusplus
#		if defined(_MSC_VER) && _MSC_VER < 1900
#			define bool char
#			define true 1
#			define false 0
#		else
#			include <stdbool.h>
#		endif
#	endif
#   define snprintf sprintf_s
#	include <io.h>
#	include <windows.h>
#else
#  include <stdbool.h>
#  include <unistd.h>
#  include <termios.h>
#  include <sys/stat.h>
#endif

#ifdef WITH_TLS
int pw__hash(const char *password, struct mosquitto_pw *pw, bool new_password, int new_iterations)
{
	int rc;
	unsigned int hash_len;
	const EVP_MD *digest;
	int iterations;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX context;
#else
	EVP_MD_CTX *context;
#endif

	if(new_password){
		pw->salt_len = HASH_LEN;
		rc = RAND_bytes(pw->salt, (int)pw->salt_len);
		if(!rc){
			return MOSQ_ERR_UNKNOWN;
		}
		iterations = new_iterations;
	}else{
		iterations = pw->iterations;
	}
	if(iterations < 1){
		return MOSQ_ERR_INVAL;
	}

	digest = EVP_get_digestbyname("sha512");
	if(!digest){
		return MOSQ_ERR_UNKNOWN;
	}

	if(pw->hashtype == pw_sha512){
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		EVP_MD_CTX_init(&context);
		EVP_DigestInit_ex(&context, digest, NULL);
		EVP_DigestUpdate(&context, password, strlen(password));
		EVP_DigestUpdate(&context, pw->salt, pw->salt_len);
		EVP_DigestFinal_ex(&context, pw->password_hash, &hash_len);
		EVP_MD_CTX_cleanup(&context);
#else
		context = EVP_MD_CTX_new();
		EVP_DigestInit_ex(context, digest, NULL);
		EVP_DigestUpdate(context, password, strlen(password));
		EVP_DigestUpdate(context, pw->salt, pw->salt_len);
		EVP_DigestFinal_ex(context, pw->password_hash, &hash_len);
		EVP_MD_CTX_free(context);
#endif
	}else{
		pw->iterations = iterations;
		hash_len = sizeof(pw->password_hash);
		PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
			pw->salt, (int)pw->salt_len, iterations,
			digest, (int)hash_len, pw->password_hash);
	}

	return MOSQ_ERR_SUCCESS;
}
#endif

int pw__memcmp_const(const void *a, const void *b, size_t len)
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
