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

#define MAX_BUFFER_LEN 65536
#define SALT_LEN 12

#ifdef WITH_TLS
int base64__encode(unsigned char *in, unsigned int in_len, char **encoded)
{
	BIO *bmem, *b64;
	BUF_MEM *bptr;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, in, (int)in_len);
	if(BIO_flush(b64) != 1){
		BIO_free_all(b64);
		return 1;
	}
	BIO_get_mem_ptr(b64, &bptr);
	*encoded = malloc(bptr->length+1);
	if(!(*encoded)){
		BIO_free_all(b64);
		return 1;
	}
	memcpy(*encoded, bptr->data, bptr->length);
	(*encoded)[bptr->length] = '\0';
	BIO_free_all(b64);

	return 0;
}


int base64__decode(char *in, unsigned char **decoded, unsigned int *decoded_len)
{
	BIO *bmem, *b64;
	size_t slen;
	int len;

	slen = strlen(in);

	b64 = BIO_new(BIO_f_base64());
	if(!b64){
		return 1;
	}
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bmem = BIO_new(BIO_s_mem());
	if(!bmem){
		BIO_free_all(b64);
		return 1;
	}
	b64 = BIO_push(b64, bmem);
	BIO_write(bmem, in, (int)slen);

	if(BIO_flush(bmem) != 1){
		BIO_free_all(b64);
		return 1;
	}
	*decoded = mosquitto_calloc(slen, 1);
	if(!(*decoded)){
		BIO_free_all(b64);
		return 1;
	}
	len = BIO_read(b64, *decoded, (int)slen);
	BIO_free_all(b64);

	if(len <= 0){
		mosquitto_free(*decoded);
		*decoded = NULL;
		*decoded_len = 0;
		return 1;
	}
	*decoded_len = (unsigned int)len;

	return 0;
}



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
		rc = RAND_bytes(pw->salt, sizeof(pw->salt));
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
		EVP_DigestUpdate(&context, pw->salt, sizeof(pw->salt));
		EVP_DigestFinal_ex(&context, pw->password_hash, &hash_len);
		EVP_MD_CTX_cleanup(&context);
#else
		context = EVP_MD_CTX_new();
		EVP_DigestInit_ex(context, digest, NULL);
		EVP_DigestUpdate(context, password, strlen(password));
		EVP_DigestUpdate(context, pw->salt, sizeof(pw->salt));
		EVP_DigestFinal_ex(context, pw->password_hash, &hash_len);
		EVP_MD_CTX_free(context);
#endif
	}else{
		pw->iterations = iterations;
		hash_len = sizeof(pw->password_hash);
		PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
			pw->salt, sizeof(pw->salt), iterations,
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
