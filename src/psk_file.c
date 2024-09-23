/*
Copyright (c) 2011-2021 Roger Light <roger@atchoo.org>

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

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "mosquitto_broker_internal.h"
#include "mosquitto/mqtt_protocol.h"
#include "send_mosq.h"
#include "util_mosq.h"

static int psk__cleanup(struct mosquitto__psk **psk);
static int psk__file_parse(struct mosquitto__psk **psk_id, const char *psk_file);


int psk_file__init(void)
{
	int rc;
	char *pskf = NULL;

	/* Load psk data if required. */
	if(db.config->per_listener_settings){
		for(int i=0; i<db.config->listener_count; i++){
			pskf = db.config->listeners[i].security_options->psk_file;
			if(pskf){
				rc = psk__file_parse(&db.config->listeners[i].security_options->psk_id, pskf);
				if(rc){
					log__printf(NULL, MOSQ_LOG_ERR, "Error opening psk file \"%s\".", pskf);
					return rc;
				}
			}
		}
	}else{
		pskf = db.config->security_options.psk_file;
		if(pskf){
			rc = psk__file_parse(&db.config->security_options.psk_id, pskf);
			if(rc){
				log__printf(NULL, MOSQ_LOG_ERR, "Error opening psk file \"%s\".", pskf);
				return rc;
			}
		}
	}

	return MOSQ_ERR_SUCCESS;
}

int psk_file__cleanup(void)
{
	int rc;

	rc = psk__cleanup(&db.config->security_options.psk_id);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	for(int i=0; i<db.config->listener_count; i++){
		if(db.config->listeners[i].security_options->psk_id){
			rc = psk__cleanup(&db.config->listeners[i].security_options->psk_id);
			if(rc != MOSQ_ERR_SUCCESS) return rc;
		}
	}

	return MOSQ_ERR_SUCCESS;
}


static int pwfile__parse(const char *file, struct mosquitto__psk **root)
{
	FILE *pwfile;
	struct mosquitto__psk *psk;
	char *username, *password;
	char *saveptr = NULL;
	char *buf;
	int buflen = 256;

	buf = mosquitto_malloc((size_t)buflen);
	if(buf == NULL){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}

	pwfile = mosquitto_fopen(file, "rt", true);
	if(!pwfile){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open pwfile \"%s\".", file);
		mosquitto_FREE(buf);
		return MOSQ_ERR_UNKNOWN;
	}

	while(!feof(pwfile)){
		if(mosquitto_fgets(&buf, &buflen, pwfile)){
			if(buf[0] == '#') continue;
			if(!strchr(buf, ':')) continue;

			username = strtok_r(buf, ":", &saveptr);
			if(username){
				username = mosquitto_trimblanks(username);
				if(strlen(username) > 65535){
					log__printf(NULL, MOSQ_LOG_NOTICE, "Warning: Invalid line in password file '%s', username too long.", file);
					continue;
				}
				if(strlen(username) <= 0){
					log__printf(NULL, MOSQ_LOG_NOTICE, "Warning: Empty username in password file '%s', ingoring.", file);
					continue;
				}

				HASH_FIND(hh, *root, username, strlen(username), psk);
				if(psk){
					log__printf(NULL, MOSQ_LOG_NOTICE, "Error: Duplicate user '%s' in password file '%s', ignoring.", username, file);
					continue;
				}

				psk = mosquitto_calloc(1, sizeof(struct mosquitto__psk));
				if(!psk){
					fclose(pwfile);
					mosquitto_FREE(buf);
					return MOSQ_ERR_NOMEM;
				}

				psk->username = mosquitto_strdup(username);
				if(!psk->username){
					mosquitto_FREE(psk);
					mosquitto_FREE(buf);
					fclose(pwfile);
					return MOSQ_ERR_NOMEM;
				}
				password = strtok_r(NULL, ":", &saveptr);
				if(password){
					password = mosquitto_trimblanks(password);

					if(strlen(password) > 65535){
						log__printf(NULL, MOSQ_LOG_NOTICE, "Warning: Invalid line in password file '%s', password too long.", file);
						mosquitto_FREE(psk->username);
						mosquitto_FREE(psk);
						continue;
					}

					psk->password = mosquitto_strdup(password);
					if(!psk->password){
						log__printf(NULL, MOSQ_LOG_NOTICE, "Warning: Unable to decode line in password file '%s'.", file);
						mosquitto_FREE(psk->username);
						mosquitto_FREE(psk);
						continue;
					}

					HASH_ADD_KEYPTR(hh, *root, psk->username, strlen(psk->username), psk);
				}else{
					log__printf(NULL, MOSQ_LOG_NOTICE, "Warning: Invalid line in psk file '%s': %s", file, buf);
					mosquitto_FREE(psk->username);
					mosquitto_FREE(psk->password);
					mosquitto_FREE(psk);
				}
			}
		}
	}
	fclose(pwfile);
	mosquitto_FREE(buf);

	return MOSQ_ERR_SUCCESS;
}


void psk__free_item(struct mosquitto__psk **psk, struct mosquitto__psk *item)
{
	mosquitto_FREE(item->username);
	mosquitto_FREE(item->password);
	HASH_DEL(*psk, item);
	mosquitto_FREE(item);
}


static int psk__file_parse(struct mosquitto__psk **psk_id, const char *psk_file)
{
	int rc;
	struct mosquitto__psk *psk, *tmp = NULL;

	if(!db.config || !psk_id) return MOSQ_ERR_INVAL;

	/* We haven't been asked to parse a psk file. */
	if(!psk_file) return MOSQ_ERR_SUCCESS;

	rc = pwfile__parse(psk_file, psk_id);
	if(rc) return rc;

	HASH_ITER(hh, (*psk_id), psk, tmp){
		/* Check for hex only digits */
		if(!psk->password){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty psk for identity \"%s\".", psk->username);
			return MOSQ_ERR_INVAL;
		}
		if(strspn(psk->password, "0123456789abcdefABCDEF") < strlen(psk->password)){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: psk for identity \"%s\" contains non-hexadecimal characters.", psk->username);
			return MOSQ_ERR_INVAL;
		}
	}
	return MOSQ_ERR_SUCCESS;
}


static int psk__cleanup(struct mosquitto__psk **root)
{
	struct mosquitto__psk *psk, *tmp = NULL;

	if(!root) return MOSQ_ERR_INVAL;

	HASH_ITER(hh, *root, psk, tmp){
		HASH_DEL(*root, psk);
		mosquitto_FREE(psk->username);
		mosquitto_FREE(psk->password);
		mosquitto_FREE(psk);
	}

	*root = NULL;

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_psk_key_get_default(struct mosquitto *context, const char *hint, const char *identity, char *key, int max_key_len)
{
	struct mosquitto__psk *psk;
	struct mosquitto__psk *psk_id_ref = NULL;

	if(!hint || !identity || !key) return MOSQ_ERR_INVAL;

	if(db.config->per_listener_settings){
		if(!context->listener) return MOSQ_ERR_INVAL;
		psk_id_ref = context->listener->security_options->psk_id;
	}else{
		psk_id_ref = db.config->security_options.psk_id;
	}
	if(!psk_id_ref) return MOSQ_ERR_PLUGIN_IGNORE;

	HASH_FIND(hh, psk_id_ref, identity, strlen(identity), psk);
	if(psk){
		strncpy(key, psk->password, (size_t)max_key_len);
		return MOSQ_ERR_SUCCESS;
	}

	return MOSQ_ERR_AUTH;
}
