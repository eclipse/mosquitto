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

#include <stdbool.h>
#include <string.h>

#ifdef WITH_TLS
#  include <openssl/opensslv.h>
#  include <openssl/evp.h>
#  include <openssl/rand.h>
#  define HASH_LEN EVP_MAX_MD_SIZE
#endif

#include "mosquitto.h"

#ifdef WITH_TLS
#  define HASH_LEN EVP_MAX_MD_SIZE
#else
   /* 64 bytes big enough for SHA512 */
#  define HASH_LEN 64
#endif

#ifdef WITH_ARGON2
#  include <argon2.h>
#  define MOSQ_ARGON2_T 1
#  define MOSQ_ARGON2_M 47104
#  define MOSQ_ARGON2_P 1
#endif

#define PW_DEFAULT_ITERATIONS 210000
static int pw__encode(struct mosquitto_pw *pw);

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

static int pw__memcmp_const(const void *a, const void *b, size_t len)
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
	pw->hashtype = MOSQ_PW_ARGON2ID;
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
		pw->valid = true;
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
		pw->valid = true;
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
	pw->hashtype = MOSQ_PW_SHA512_PBKDF2;
	pw->params.sha512_pbkdf2.salt_len = HASH_LEN;
	int rc = RAND_bytes(pw->params.sha512_pbkdf2.salt, (int)pw->params.sha512_pbkdf2.salt_len);
	if(!rc){
		return MOSQ_ERR_UNKNOWN;
	}

	if(pw->params.sha512_pbkdf2.iterations == 0){
		pw->params.sha512_pbkdf2.iterations = PW_DEFAULT_ITERATIONS;
	}
	rc = pw__hash_sha512_pbkdf2(password, pw,
			pw->params.sha512_pbkdf2.password_hash,
			sizeof(pw->params.sha512_pbkdf2.password_hash),
			pw->params.sha512_pbkdf2.iterations);

	pw->valid = (rc == MOSQ_ERR_SUCCESS);
	return rc;
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

	pw->valid = true;
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
	pw->hashtype = MOSQ_PW_SHA512;
	pw->params.sha512.salt_len = HASH_LEN;
	int rc = RAND_bytes(pw->params.sha512.salt, (int)pw->params.sha512.salt_len);
	if(!rc){
		return MOSQ_ERR_UNKNOWN;
	}

	rc = pw__hash_sha512(password, pw, pw->params.sha512.password_hash, sizeof(pw->params.sha512.password_hash));
	pw->valid = (rc == MOSQ_ERR_SUCCESS);
	return rc;
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

	pw->valid = true;
	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}

static int pw__encode(struct mosquitto_pw *pw)
{
	switch(pw->hashtype){
		case MOSQ_PW_ARGON2ID:
			return MOSQ_ERR_SUCCESS;
		case MOSQ_PW_SHA512_PBKDF2:
			return pw__encode_sha512_pbkdf2(pw);
		case MOSQ_PW_SHA512:
			return pw__encode_sha512(pw);
		case MOSQ_PW_DEFAULT:
			break;
	}

	return MOSQ_ERR_AUTH;
}

/* ==================================================
 * Public
 * ================================================== */

int mosquitto_pw_new(struct mosquitto_pw **pw, enum mosquitto_pwhash_type hashtype)
{
	*pw = mosquitto_calloc(1, sizeof(struct mosquitto_pw));
	if(*pw){
		(*pw)->hashtype = hashtype;
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_NOMEM;
	}
}


int mosquitto_pw_hash_encoded(struct mosquitto_pw *pw, const char *password)
{
	int rc = MOSQ_ERR_INVAL;

	switch(pw->hashtype){
		case MOSQ_PW_DEFAULT:
		case MOSQ_PW_ARGON2ID:
			rc = pw__create_argon2id(pw, password);
			break;
		case MOSQ_PW_SHA512_PBKDF2:
			rc = pw__create_sha512_pbkdf2(pw, password);
			break;
		case MOSQ_PW_SHA512:
			rc = pw__create_sha512(pw, password);
			break;
		default:
#ifdef WITH_ARGON2
			rc = pw__create_argon2id(pw, password);
#else
			rc = pw__create_sha512_pbkdf2(pw, password);
#endif
			break;
	}
	if(rc == MOSQ_ERR_SUCCESS){
		return pw__encode(pw);
	}else{
		return rc;
	}
}

int mosquitto_pw_verify(struct mosquitto_pw *pw, const char *password)
{
	if(pw && pw->valid){
		switch(pw->hashtype){
			case MOSQ_PW_ARGON2ID:
				return pw__verify_argon2id(pw, password);
			case MOSQ_PW_SHA512_PBKDF2:
				return pw__verify_sha512_pbkdf2(pw, password);
			case MOSQ_PW_SHA512:
				return pw__verify_sha512(pw, password);
			case MOSQ_PW_DEFAULT:
				return MOSQ_ERR_AUTH;
		}
	}

	return MOSQ_ERR_AUTH;
}

void mosquitto_pw_set_valid(struct mosquitto_pw *pw, bool valid)
{
	if(pw){
		pw->valid = valid;
	}
}

bool mosquitto_pw_is_valid(struct mosquitto_pw *pw)
{
	return pw && pw->valid;
}

int mosquitto_pw_decode(struct mosquitto_pw *pw, const char *password)
{
	if(!pw) return MOSQ_ERR_INVAL;

	pw->valid = false;
	if(password[0] != '$'){
		return MOSQ_ERR_INVAL;
	}
	pw->encoded_password = mosquitto_strdup(password);
	if(!pw->encoded_password){
		return MOSQ_ERR_NOMEM;
	}

	if(password[1] == '6' && password[2] == '$'){
		pw->hashtype = MOSQ_PW_SHA512;
		return pw__decode_sha512(pw, &password[3]);
	}else if(password[1] == '7' && password[2] == '$'){
		pw->hashtype = MOSQ_PW_SHA512_PBKDF2;
		return pw__decode_sha512_pbkdf2(pw, &password[3]);
	}else if(!strncmp(password, "$argon2id$", strlen("$argon2id$"))){
		pw->hashtype = MOSQ_PW_ARGON2ID;
		return pw__decode_argon2id(pw, password);
	}else{
		mosquitto_FREE(pw->encoded_password);
		return MOSQ_ERR_INVAL;
	}
}

const char *mosquitto_pw_get_encoded(struct mosquitto_pw *pw)
{
	return pw?pw->encoded_password:NULL;
}

int mosquitto_pw_set_param(struct mosquitto_pw *pw, int param, int value)
{
	if(!pw) return MOSQ_ERR_INVAL;

	switch(param){
		case MOSQ_PW_PARAM_ITERATIONS:
			if(pw->hashtype != MOSQ_PW_SHA512_PBKDF2) return MOSQ_ERR_INVAL;
			pw->params.sha512_pbkdf2.iterations = value;
			break;
	}

	return MOSQ_ERR_SUCCESS;
}

void mosquitto_pw_cleanup(struct mosquitto_pw *pw)
{
	if(pw){
		mosquitto_free(pw->encoded_password);
		pw->encoded_password = NULL;
		mosquitto_free(pw);
	}
}
