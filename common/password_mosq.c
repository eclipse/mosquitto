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

#ifdef WITH_TLS
#  include <openssl/opensslv.h>
#  include <openssl/evp.h>
#  include <openssl/rand.h>
#endif
#include <string.h>

#include "mosquitto.h"
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
#endif

#ifdef WITH_ARGON2
#  include <argon2.h>
#  define MOSQ_ARGON2_T 1
#  define MOSQ_ARGON2_M 47104
#  define MOSQ_ARGON2_P 1
#endif

int pw__memcmp_const(const void *a, const void *b, size_t len)
{
#ifdef WITH_TLS
	return CRYPTO_memcmp(a, b, len);
#else
	int rc = 0;
	const volatile char *ac = a;
	const volatile char *bc = b;

	if(!a || !b) return 1;

	for(size_t i=0; i<len; i++){
		rc |= ((char *)ac)[i] ^ ((char *)bc)[i];
	}
	return rc;
#endif
}

/* ==================================================
 * ARGON2
 * ================================================== */

static int pw__create_argon2id(struct mosquitto_pw *pw, const char *password)
{
#ifdef WITH_ARGON2
	pw->hashtype = pw_argon2id;
	pw->params.argon2id.salt_len = HASH_LEN;
	int rc = RAND_bytes(pw->params.argon2id.salt, (int)pw->params.argon2id.salt_len);
	if(!rc){
		return MOSQ_ERR_UNKNOWN;
	}

	size_t encoded_len = argon2_encodedlen(MOSQ_ARGON2_T, MOSQ_ARGON2_M, MOSQ_ARGON2_P,
			(uint32_t)pw->params.argon2id.salt_len, sizeof(pw->params.argon2id.password_hash), Argon2_id);

	mosquitto_free(pw->encoded_password);
	pw->encoded_password = mosquitto_calloc(1, encoded_len+1);

	rc = argon2id_hash_encoded(MOSQ_ARGON2_T, MOSQ_ARGON2_M, MOSQ_ARGON2_P,
			password, strlen(password),
			pw->params.argon2id.salt, pw->params.argon2id.salt_len,
			HASH_LEN,
			pw->encoded_password, encoded_len+1);

	if(rc == ARGON2_OK){
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_UNKNOWN;
	}
#else
	UNUSED(pw);
	UNUSED(password);
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}

static int pw__verify_argon2id(struct mosquitto_pw *pw, const char *password)
{
#ifdef WITH_ARGON2
	int rc = argon2id_verify(pw->encoded_password,
			password, strlen(password));

	if(rc == ARGON2_OK){
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_AUTH;
	}
#else
	UNUSED(pw);
	UNUSED(password);
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}

static int pw__decode_argon2id(struct mosquitto_pw *pw, const char *password)
{
#ifdef WITH_ARGON2
	char *new_password = mosquitto_strdup(password);

	if(new_password){
		mosquitto_free(pw->encoded_password);
		pw->encoded_password = new_password;
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_NOMEM;
	}
#else
	UNUSED(pw);
	UNUSED(password);
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}


/* ==================================================
 * SHA512 PBKDF2
 * ================================================== */
#ifdef WITH_TLS
static int pw__hash_sha512_pbkdf2(const char *password, struct mosquitto_pw *pw, unsigned char *password_hash, unsigned int hash_len, int iterations)
{
	const EVP_MD *digest;

	digest = EVP_get_digestbyname("sha512");
	if(!digest){
		return MOSQ_ERR_UNKNOWN;
	}

	PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
		pw->params.sha512.salt, (int)pw->params.sha512.salt_len, iterations,
		digest, (int)hash_len, password_hash);

	return MOSQ_ERR_SUCCESS;
}
#endif

static int pw__create_sha512_pbkdf2(struct mosquitto_pw *pw, const char *password)
{
#ifdef WITH_TLS
	pw->hashtype = pw_sha512_pbkdf2;
	pw->params.sha512_pbkdf2.salt_len = HASH_LEN;
	int rc = RAND_bytes(pw->params.sha512_pbkdf2.salt, (int)pw->params.sha512_pbkdf2.salt_len);
	if(!rc){
		return MOSQ_ERR_UNKNOWN;
	}

	if(pw->params.sha512_pbkdf2.iterations == 0){
		pw->params.sha512_pbkdf2.iterations = PW_DEFAULT_ITERATIONS;
	}
	return pw__hash_sha512_pbkdf2(password, pw,
			pw->params.sha512_pbkdf2.password_hash,
			sizeof(pw->params.sha512_pbkdf2.password_hash),
			pw->params.sha512_pbkdf2.iterations);
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}


static int pw__verify_sha512_pbkdf2(struct mosquitto_pw *pw, const char *password)
{
#ifdef WITH_TLS
	int rc;
	unsigned char password_hash[HASH_LEN];

	rc = pw__hash_sha512_pbkdf2(password, pw,
			password_hash, sizeof(password_hash),
			pw->params.sha512_pbkdf2.iterations);

	if(rc != MOSQ_ERR_SUCCESS) return MOSQ_ERR_AUTH;

	if(!pw__memcmp_const(pw->params.sha512_pbkdf2.password_hash, password_hash, HASH_LEN)){
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_AUTH;
	}
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}

static int pw__encode_sha512_pbkdf2(struct mosquitto_pw *pw)
{
#ifdef WITH_TLS
	int rc;
	char *salt64 = NULL, *hash64 = NULL;

	rc = mosquitto_base64_encode(pw->params.sha512_pbkdf2.salt, pw->params.sha512_pbkdf2.salt_len, &salt64);
	if(rc){
		return MOSQ_ERR_UNKNOWN;
	}

	rc = mosquitto_base64_encode(pw->params.sha512_pbkdf2.password_hash, sizeof(pw->params.sha512_pbkdf2.password_hash), &hash64);
	if(rc){
		mosquitto_free(salt64);
		return MOSQ_ERR_UNKNOWN;
	}

	mosquitto_free(pw->encoded_password);
	size_t len = strlen("$6$$") + strlen("1,000,000,000,000") + strlen(salt64) + strlen(hash64) + 1;
	pw->encoded_password = mosquitto_calloc(1, len);
	if(!pw->encoded_password) return MOSQ_ERR_NOMEM;

	snprintf(pw->encoded_password, len, "$%d$%d$%s$%s", pw->hashtype, pw->params.sha512_pbkdf2.iterations, salt64, hash64);

	mosquitto_free(salt64);
	mosquitto_free(hash64);

	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}

static int pw__decode_sha512_pbkdf2(struct mosquitto_pw *pw, const char *salt_password)
{
#ifdef WITH_TLS
	char *sp_heap, *saveptr = NULL;
	char *iterations_s;
	char *salt_b64, *password_b64;
	unsigned char *salt, *password;
	unsigned int salt_len, password_len;
	int rc;

	sp_heap = mosquitto_strdup(salt_password);
	if(!sp_heap) return MOSQ_ERR_NOMEM;

	iterations_s = strtok_r(sp_heap, "$", &saveptr);
	if(iterations_s == NULL){
		mosquitto_free(sp_heap);
		return MOSQ_ERR_INVAL;
	}
	pw->params.sha512_pbkdf2.iterations = atoi(iterations_s);
	if(pw->params.sha512_pbkdf2.iterations < 1){
		mosquitto_free(sp_heap);
		return MOSQ_ERR_INVAL;
	}

	salt_b64 = strtok_r(NULL, "$", &saveptr);
	if(salt_b64 == NULL){
		mosquitto_free(sp_heap);
		return MOSQ_ERR_INVAL;
	}

	rc = mosquitto_base64_decode(salt_b64, &salt, &salt_len);
	if(rc != MOSQ_ERR_SUCCESS || (salt_len != 12 && salt_len != HASH_LEN)){
		mosquitto_free(sp_heap);
		mosquitto_free(salt);
		return MOSQ_ERR_INVAL;
	}
	memcpy(pw->params.sha512_pbkdf2.salt, salt, salt_len);
	mosquitto_free(salt);
	pw->params.sha512_pbkdf2.salt_len = salt_len;

	password_b64 = strtok_r(NULL, "$", &saveptr);
	if(password_b64 == NULL){
		mosquitto_free(sp_heap);
		return MOSQ_ERR_INVAL;
	}

	rc = mosquitto_base64_decode(password_b64, &password, &password_len);
	mosquitto_free(sp_heap);

	if(rc != MOSQ_ERR_SUCCESS || password_len != HASH_LEN){
		mosquitto_free(password);
		return MOSQ_ERR_INVAL;
	}
	memcpy(pw->params.sha512_pbkdf2.password_hash, password, password_len);
	mosquitto_free(password);

	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}


/* ==================================================
 * SHA512
 * ================================================== */
#ifdef WITH_TLS
static int pw__hash_sha512(const char *password, struct mosquitto_pw *pw, unsigned char *password_hash, unsigned int hash_len)
{
	const EVP_MD *digest;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX context;
#else
	EVP_MD_CTX *context;
#endif

	digest = EVP_get_digestbyname("sha512");
	if(!digest){
		return MOSQ_ERR_UNKNOWN;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX_init(&context);
	EVP_DigestInit_ex(&context, digest, NULL);
	EVP_DigestUpdate(&context, password, strlen(password));
	EVP_DigestUpdate(&context, pw->params.sha512.salt, pw->params.sha512.salt_len);
	EVP_DigestFinal_ex(&context, password_hash, &hash_len);
	EVP_MD_CTX_cleanup(&context);
#else
	context = EVP_MD_CTX_new();
	EVP_DigestInit_ex(context, digest, NULL);
	EVP_DigestUpdate(context, password, strlen(password));
	EVP_DigestUpdate(context, pw->params.sha512.salt, pw->params.sha512.salt_len);
	EVP_DigestFinal_ex(context, password_hash, &hash_len);
	EVP_MD_CTX_free(context);
#endif

	return MOSQ_ERR_SUCCESS;
}
#endif

static int pw__create_sha512(struct mosquitto_pw *pw, const char *password)
{
#ifdef WITH_TLS
	pw->hashtype = pw_sha512;
	pw->params.sha512.salt_len = HASH_LEN;
	int rc = RAND_bytes(pw->params.sha512.salt, (int)pw->params.sha512.salt_len);
	if(!rc){
		return MOSQ_ERR_UNKNOWN;
	}

	return pw__hash_sha512(password, pw, pw->params.sha512.password_hash, sizeof(pw->params.sha512.password_hash));
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}


static int pw__verify_sha512(struct mosquitto_pw *pw, const char *password)
{
#ifdef WITH_TLS
	int rc;
	unsigned char password_hash[HASH_LEN];

	rc = pw__hash_sha512(password, pw, password_hash, sizeof(password_hash));
	if(rc != MOSQ_ERR_SUCCESS) return MOSQ_ERR_AUTH;

	if(!pw__memcmp_const(pw->params.sha512.password_hash, password_hash, HASH_LEN)){
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_AUTH;
	}
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}

static int pw__encode_sha512(struct mosquitto_pw *pw)
{
#ifdef WITH_TLS
	int rc;
	char *salt64 = NULL, *hash64 = NULL;

	rc = mosquitto_base64_encode(pw->params.sha512.salt, pw->params.sha512.salt_len, &salt64);
	if(rc){
		return MOSQ_ERR_UNKNOWN;
	}

	rc = mosquitto_base64_encode(pw->params.sha512.password_hash, sizeof(pw->params.sha512.password_hash), &hash64);
	if(rc){
		return MOSQ_ERR_UNKNOWN;
	}

	mosquitto_free(pw->encoded_password);
	size_t len = strlen("$6$$") + strlen(salt64) + strlen(hash64) + 1;
	pw->encoded_password = mosquitto_calloc(1, len);
	if(!pw->encoded_password) return MOSQ_ERR_NOMEM;

	snprintf(pw->encoded_password, len, "$%d$%s$%s", pw->hashtype, salt64, hash64);

	mosquitto_free(salt64);
	mosquitto_free(hash64);

	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}

static int pw__decode_sha512(struct mosquitto_pw *pw, const char *salt_password)
{
#ifdef WITH_TLS
	char *sp_heap, *saveptr = NULL;
	char *salt_b64, *password_b64;
	unsigned char *salt, *password;
	unsigned int salt_len, password_len;
	int rc;

	sp_heap = mosquitto_strdup(salt_password);
	if(!sp_heap) return MOSQ_ERR_NOMEM;

	salt_b64 = strtok_r(sp_heap, "$", &saveptr);
	if(salt_b64 == NULL){
		mosquitto_free(sp_heap);
		return MOSQ_ERR_INVAL;
	}

	rc = mosquitto_base64_decode(salt_b64, &salt, &salt_len);
	if(rc != MOSQ_ERR_SUCCESS || (salt_len != 12 && salt_len != HASH_LEN)){
		mosquitto_free(sp_heap);
		mosquitto_free(salt);
		return MOSQ_ERR_INVAL;
	}
	memcpy(pw->params.sha512.salt, salt, salt_len);
	mosquitto_free(salt);
	pw->params.sha512.salt_len = salt_len;

	password_b64 = strtok_r(NULL, "$", &saveptr);
	if(password_b64 == NULL){
		mosquitto_free(sp_heap);
		return MOSQ_ERR_INVAL;
	}

	rc = mosquitto_base64_decode(password_b64, &password, &password_len);
	mosquitto_free(sp_heap);

	if(rc != MOSQ_ERR_SUCCESS || password_len != HASH_LEN){
		mosquitto_free(password);
		return MOSQ_ERR_INVAL;
	}
	memcpy(pw->params.sha512.password_hash, password, password_len);
	mosquitto_free(password);

	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}

/* ==================================================
 * Public
 * ================================================== */

int pw__create(struct mosquitto_pw *pw, const char *password)
{
	switch(pw->hashtype){
		case pw_argon2id:
			return pw__create_argon2id(pw, password);
		case pw_sha512_pbkdf2:
			return pw__create_sha512_pbkdf2(pw, password);
		case pw_sha512:
			return pw__create_sha512(pw, password);
		default:
#ifdef WITH_ARGON2
			return pw__create_argon2id(pw, password);
#else
			return pw__create_sha512_pbkdf2(pw, password);
#endif
	}

	return MOSQ_ERR_INVAL;
}

int pw__verify(struct mosquitto_pw *pw, const char *password)
{
	switch(pw->hashtype){
		case pw_argon2id:
			return pw__verify_argon2id(pw, password);
		case pw_sha512_pbkdf2:
			return pw__verify_sha512_pbkdf2(pw, password);
		case pw_sha512:
			return pw__verify_sha512(pw, password);
	}

	return MOSQ_ERR_AUTH;
}

int pw__encode(struct mosquitto_pw *pw)
{
	switch(pw->hashtype){
		case pw_argon2id:
			return MOSQ_ERR_SUCCESS;
		case pw_sha512_pbkdf2:
			return pw__encode_sha512_pbkdf2(pw);
		case pw_sha512:
			return pw__encode_sha512(pw);
	}

	return MOSQ_ERR_AUTH;
}

int pw__decode(struct mosquitto_pw *pw, const char *password)
{
	if(password[0] != '$'){
		return MOSQ_ERR_INVAL;
	}

	if(password[1] == '6' && password[2] == '$'){
		pw->hashtype = pw_sha512;
		return pw__decode_sha512(pw, &password[3]);
	}else if(password[1] == '7' && password[2] == '$'){
		pw->hashtype = pw_sha512_pbkdf2;
		return pw__decode_sha512_pbkdf2(pw, &password[3]);
	}else if(!strncmp(password, "$argon2id$", strlen("$argon2id$"))){
		pw->hashtype = pw_argon2id;
		return pw__decode_argon2id(pw, password);
	}else{
		return MOSQ_ERR_INVAL;
	}
}

void pw__cleanup(struct mosquitto_pw *pw)
{
	if(pw){
		mosquitto_free(pw->encoded_password);
		pw->encoded_password = NULL;
	}
}
