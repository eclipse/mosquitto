/*
Copyright (c) 2011-2020 Roger Light <roger@atchoo.org>

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

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "send_mosq.h"
#include "misc_mosq.h"
#include "util_mosq.h"

static int aclfile__parse(struct mosquitto__security_options *security_opts);
static int unpwd__file_parse(struct mosquitto__unpwd **unpwd, const char *password_file);
static int acl__cleanup(bool reload);
static int unpwd__cleanup(struct mosquitto__unpwd **unpwd, bool reload);
static int psk__file_parse(struct mosquitto__unpwd **psk_id, const char *psk_file);
#ifdef WITH_TLS
static int pw__digest(const char *password, const unsigned char *salt, unsigned int salt_len, unsigned char *hash, unsigned int *hash_len, enum mosquitto_pwhash_type hashtype, int iterations);
#endif
static int mosquitto_unpwd_check_default(int event, void *event_data, void *userdata);
static int mosquitto_acl_check_default(int event, void *event_data, void *userdata);



int mosquitto_security_init_default(bool reload)
{
	int rc;
	int i;
	char *pwf;
	char *pskf;

	UNUSED(reload);

	/* Configure plugin identifier */
	if(db.config->per_listener_settings){
		for(i=0; i<db.config->listener_count; i++){
			db.config->listeners[i].security_options.pid = mosquitto__calloc(1, sizeof(mosquitto_plugin_id_t));
			if(db.config->listeners[i].security_options.pid == NULL){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				return MOSQ_ERR_NOMEM;
			}
			db.config->listeners[i].security_options.pid->listener = &db.config->listeners[i];
		}
	}else{
		db.config->security_options.pid = mosquitto__calloc(1, sizeof(mosquitto_plugin_id_t));
		if(db.config->security_options.pid == NULL){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
	}

	/* Load username/password data if required. */
	if(db.config->per_listener_settings){
		for(i=0; i<db.config->listener_count; i++){
			pwf = db.config->listeners[i].security_options.password_file;
			if(pwf){
				rc = unpwd__file_parse(&db.config->listeners[i].security_options.unpwd, pwf);
				if(rc){
					log__printf(NULL, MOSQ_LOG_ERR, "Error opening password file \"%s\".", pwf);
					return rc;
				}
				mosquitto_callback_register(db.config->listeners[i].security_options.pid,
						MOSQ_EVT_BASIC_AUTH, mosquitto_unpwd_check_default, NULL, NULL);
			}
		}
	}else{
		if(db.config->security_options.password_file){
			pwf = db.config->security_options.password_file;
			if(pwf){
				rc = unpwd__file_parse(&db.config->security_options.unpwd, pwf);
				if(rc){
					log__printf(NULL, MOSQ_LOG_ERR, "Error opening password file \"%s\".", pwf);
					return rc;
				}
			}
			mosquitto_callback_register(db.config->security_options.pid,
					MOSQ_EVT_BASIC_AUTH, mosquitto_unpwd_check_default, NULL, NULL);
		}
	}

	/* Load acl data if required. */
	if(db.config->per_listener_settings){
		for(i=0; i<db.config->listener_count; i++){
			if(db.config->listeners[i].security_options.acl_file){
				rc = aclfile__parse(&db.config->listeners[i].security_options);
				if(rc){
					log__printf(NULL, MOSQ_LOG_ERR, "Error opening acl file \"%s\".", db.config->listeners[i].security_options.acl_file);
					return rc;
				}
				mosquitto_callback_register(db.config->listeners[i].security_options.pid,
						MOSQ_EVT_ACL_CHECK, mosquitto_acl_check_default, NULL, NULL);
			}
		}
	}else{
		if(db.config->security_options.acl_file){
			rc = aclfile__parse(&db.config->security_options);
			if(rc){
				log__printf(NULL, MOSQ_LOG_ERR, "Error opening acl file \"%s\".", db.config->security_options.acl_file);
				return rc;
			}
			mosquitto_callback_register(db.config->security_options.pid,
					MOSQ_EVT_ACL_CHECK, mosquitto_acl_check_default, NULL, NULL);
		}
	}

	/* Load psk data if required. */
	if(db.config->per_listener_settings){
		for(i=0; i<db.config->listener_count; i++){
			pskf = db.config->listeners[i].security_options.psk_file;
			if(pskf){
				rc = psk__file_parse(&db.config->listeners[i].security_options.psk_id, pskf);
				if(rc){
					log__printf(NULL, MOSQ_LOG_ERR, "Error opening psk file \"%s\".", pskf);
					return rc;
				}
			}
		}
	}else{
		char *pskf = db.config->security_options.psk_file;
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

int mosquitto_security_cleanup_default(bool reload)
{
	int rc;
	int i;

	rc = acl__cleanup(reload);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	rc = unpwd__cleanup(&db.config->security_options.unpwd, reload);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	for(i=0; i<db.config->listener_count; i++){
		if(db.config->listeners[i].security_options.unpwd){
			rc = unpwd__cleanup(&db.config->listeners[i].security_options.unpwd, reload);
			if(rc != MOSQ_ERR_SUCCESS) return rc;
		}
	}

	rc = unpwd__cleanup(&db.config->security_options.psk_id, reload);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	for(i=0; i<db.config->listener_count; i++){
		if(db.config->listeners[i].security_options.psk_id){
			rc = unpwd__cleanup(&db.config->listeners[i].security_options.psk_id, reload);
			if(rc != MOSQ_ERR_SUCCESS) return rc;
		}
	}

	if(db.config->per_listener_settings){
		for(i=0; i<db.config->listener_count; i++){
			if(db.config->listeners[i].security_options.pid){
				mosquitto_callback_unregister(db.config->listeners[i].security_options.pid,
						MOSQ_EVT_BASIC_AUTH, mosquitto_unpwd_check_default, NULL);

				mosquitto__free(db.config->listeners[i].security_options.pid);
			}
		}
	}else{
		if(db.config->security_options.pid){
			mosquitto_callback_unregister(db.config->security_options.pid,
					MOSQ_EVT_BASIC_AUTH, mosquitto_unpwd_check_default, NULL);

			mosquitto__free(db.config->security_options.pid);
		}
	}
	return MOSQ_ERR_SUCCESS;
}


int add__acl(struct mosquitto__security_options *security_opts, const char *user, const char *topic, int access)
{
	struct mosquitto__acl_user *acl_user=NULL, *user_tail;
	struct mosquitto__acl *acl, *acl_tail;
	char *local_topic;
	bool new_user = false;

	if(!security_opts || !topic) return MOSQ_ERR_INVAL;

	local_topic = mosquitto__strdup(topic);
	if(!local_topic){
		return MOSQ_ERR_NOMEM;
	}

	if(security_opts->acl_list){
		user_tail = security_opts->acl_list;
		while(user_tail){
			if(user == NULL){
				if(user_tail->username == NULL){
					acl_user = user_tail;
					break;
				}
			}else if(user_tail->username && !strcmp(user_tail->username, user)){
				acl_user = user_tail;
				break;
			}
			user_tail = user_tail->next;
		}
	}
	if(!acl_user){
		acl_user = mosquitto__malloc(sizeof(struct mosquitto__acl_user));
		if(!acl_user){
			mosquitto__free(local_topic);
			return MOSQ_ERR_NOMEM;
		}
		new_user = true;
		if(user){
			acl_user->username = mosquitto__strdup(user);
			if(!acl_user->username){
				mosquitto__free(local_topic);
				mosquitto__free(acl_user);
				return MOSQ_ERR_NOMEM;
			}
		}else{
			acl_user->username = NULL;
		}
		acl_user->next = NULL;
		acl_user->acl = NULL;
	}

	acl = mosquitto__malloc(sizeof(struct mosquitto__acl));
	if(!acl){
		mosquitto__free(local_topic);
		mosquitto__free(acl_user->username);
		mosquitto__free(acl_user);
		return MOSQ_ERR_NOMEM;
	}
	acl->access = access;
	acl->topic = local_topic;
	acl->next = NULL;
	acl->ccount = 0;
	acl->ucount = 0;

	/* Add acl to user acl list */
	if(acl_user->acl){
		acl_tail = acl_user->acl;
		if(access == MOSQ_ACL_NONE){
			/* Put "deny" acls at front of the list */
			acl->next = acl_tail;
			acl_user->acl = acl;
		}else{
			while(acl_tail->next){
				acl_tail = acl_tail->next;
			}
			acl_tail->next = acl;
		}
	}else{
		acl_user->acl = acl;
	}

	if(new_user){
		/* Add to end of list */
		if(security_opts->acl_list){
			user_tail = security_opts->acl_list;
			while(user_tail->next){
				user_tail = user_tail->next;
			}
			user_tail->next = acl_user;
		}else{
			security_opts->acl_list = acl_user;
		}
	}

	return MOSQ_ERR_SUCCESS;
}

int add__acl_pattern(struct mosquitto__security_options *security_opts, const char *topic, int access)
{
	struct mosquitto__acl *acl, *acl_tail;
	char *local_topic;
	char *s;

	if(!security_opts| !topic) return MOSQ_ERR_INVAL;

	local_topic = mosquitto__strdup(topic);
	if(!local_topic){
		return MOSQ_ERR_NOMEM;
	}

	acl = mosquitto__malloc(sizeof(struct mosquitto__acl));
	if(!acl){
		mosquitto__free(local_topic);
		return MOSQ_ERR_NOMEM;
	}
	acl->access = access;
	acl->topic = local_topic;
	acl->next = NULL;

	acl->ccount = 0;
	s = local_topic;
	while(s){
		s = strstr(s, "%c");
		if(s){
			acl->ccount++;
			s+=2;
		}
	}

	acl->ucount = 0;
	s = local_topic;
	while(s){
		s = strstr(s, "%u");
		if(s){
			acl->ucount++;
			s+=2;
		}
	}

	if(acl->ccount == 0 && acl->ucount == 0){
		log__printf(NULL, MOSQ_LOG_WARNING,
				"Warning: ACL pattern '%s' does not contain '%%c' or '%%u'.",
				topic);
	}

	if(security_opts->acl_patterns){
		acl_tail = security_opts->acl_patterns;
		if(access == MOSQ_ACL_NONE){
			/* Put "deny" acls at front of the list */
			acl->next = acl_tail;
			security_opts->acl_patterns = acl;
		}else{
			while(acl_tail->next){
				acl_tail = acl_tail->next;
			}
			acl_tail->next = acl;
		}
	}else{
		security_opts->acl_patterns = acl;
	}

	return MOSQ_ERR_SUCCESS;
}

static int mosquitto_acl_check_default(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_acl_check *ed = event_data;
	char *local_acl;
	struct mosquitto__acl *acl_root;
	bool result;
	int i;
	size_t len, tlen, clen, ulen;
	char *s;
	struct mosquitto__security_options *security_opts = NULL;

	if(ed->client->bridge) return MOSQ_ERR_SUCCESS;
	if(ed->access == MOSQ_ACL_SUBSCRIBE || ed->access == MOSQ_ACL_UNSUBSCRIBE) return MOSQ_ERR_SUCCESS; /* FIXME - implement ACL subscription strings. */

	if(db.config->per_listener_settings){
		if(!ed->client->listener) return MOSQ_ERR_ACL_DENIED;
		security_opts = &ed->client->listener->security_options;
	}else{
		security_opts = &db.config->security_options;
	}
	if(!security_opts->acl_file && !security_opts->acl_list && !security_opts->acl_patterns){
		return MOSQ_ERR_PLUGIN_DEFER;
	}

	if(!ed->client->acl_list && !security_opts->acl_patterns) return MOSQ_ERR_ACL_DENIED;

	if(ed->client->acl_list){
		acl_root = ed->client->acl_list->acl;
	}else{
		acl_root = NULL;
	}

	/* Loop through all ACLs for this client. ACL denials are iterated over first. */
	while(acl_root){
		/* Loop through the topic looking for matches to this ACL. */

		/* If subscription starts with $, acl_root->topic must also start with $. */
		if(ed->topic[0] == '$' && acl_root->topic[0] != '$'){
			acl_root = acl_root->next;
			continue;
		}
		mosquitto_topic_matches_sub(acl_root->topic, ed->topic, &result);
		if(result){
			if(acl_root->access == MOSQ_ACL_NONE){
				/* Access was explicitly denied for this topic. */
				return MOSQ_ERR_ACL_DENIED;
			}
			if(ed->access & acl_root->access){
				/* And access is allowed. */
				return MOSQ_ERR_SUCCESS;
			}
		}
		acl_root = acl_root->next;
	}

	acl_root = security_opts->acl_patterns;

	if(acl_root){
		/* We are using pattern based acls. Check whether the username or
		 * client id contains a + or # and if so deny access.
		 *
		 * Without this, a malicious client may configure its username/client
		 * id to bypass ACL checks (or have a username/client id that cannot
		 * publish or receive messages to its own place in the hierarchy).
		 */
		if(ed->client->username && strpbrk(ed->client->username, "+#")){
			log__printf(NULL, MOSQ_LOG_NOTICE, "ACL denying access to client with dangerous username \"%s\"", ed->client->username);
			return MOSQ_ERR_ACL_DENIED;
		}

		if(ed->client->id && strpbrk(ed->client->id, "+#")){
			log__printf(NULL, MOSQ_LOG_NOTICE, "ACL denying access to client with dangerous client id \"%s\"", ed->client->id);
			return MOSQ_ERR_ACL_DENIED;
		}
	}

	/* Loop through all pattern ACLs. ACL denial patterns are iterated over first. */
	if(!ed->client->id) return MOSQ_ERR_ACL_DENIED;
	clen = strlen(ed->client->id);

	while(acl_root){
		tlen = strlen(acl_root->topic);

		if(acl_root->ucount && !ed->client->username){
			acl_root = acl_root->next;
			continue;
		}

		if(ed->client->username){
			ulen = strlen(ed->client->username);
			len = tlen + (size_t)acl_root->ccount*(clen-2) + (size_t)acl_root->ucount*(ulen-2);
		}else{
			ulen = 0;
			len = tlen + (size_t)acl_root->ccount*(clen-2);
		}
		local_acl = mosquitto__malloc(len+1);
		if(!local_acl) return MOSQ_ERR_NOMEM;
		s = local_acl;
		for(i=0; i<tlen; i++){
			if(i<tlen-1 && acl_root->topic[i] == '%'){
				if(acl_root->topic[i+1] == 'c'){
					i++;
					strncpy(s, ed->client->id, clen);
					s+=clen;
					continue;
				}else if(ed->client->username && acl_root->topic[i+1] == 'u'){
					i++;
					strncpy(s, ed->client->username, ulen);
					s+=ulen;
					continue;
				}
			}
			s[0] = acl_root->topic[i];
			s++;
		}
		local_acl[len] = '\0';

		mosquitto_topic_matches_sub(local_acl, ed->topic, &result);
		mosquitto__free(local_acl);
		if(result){
			if(acl_root->access == MOSQ_ACL_NONE){
				/* Access was explicitly denied for this topic pattern. */
				return MOSQ_ERR_ACL_DENIED;
			}
			if(ed->access & acl_root->access){
				/* And access is allowed. */
				return MOSQ_ERR_SUCCESS;
			}
		}

		acl_root = acl_root->next;
	}

	return MOSQ_ERR_ACL_DENIED;
}


static int aclfile__parse(struct mosquitto__security_options *security_opts)
{
	FILE *aclfptr = NULL;
	char *token;
	char *user = NULL;
	char *topic;
	char *access_s;
	int access;
	int rc = MOSQ_ERR_SUCCESS;
	size_t slen;
	int topic_pattern;
	char *saveptr = NULL;
	char *buf = NULL;
	int buflen = 256;

	if(!db.config) return MOSQ_ERR_INVAL;
	if(!security_opts) return MOSQ_ERR_INVAL;
	if(!security_opts->acl_file) return MOSQ_ERR_SUCCESS;

	buf = mosquitto__malloc((size_t)buflen);
	if(buf == NULL){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}

	aclfptr = mosquitto__fopen(security_opts->acl_file, "rt", false);
	if(!aclfptr){
		mosquitto__free(buf);
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open acl_file \"%s\".", security_opts->acl_file);
		return MOSQ_ERR_UNKNOWN;
	}

	/* topic [read|write] <topic>
	 * user <user>
	 */

	while(fgets_extending(&buf, &buflen, aclfptr)){
		slen = strlen(buf);
		while(slen > 0 && isspace(buf[slen-1])){
			buf[slen-1] = '\0';
			slen = strlen(buf);
		}
		if(buf[0] == '#'){
			continue;
		}
		token = strtok_r(buf, " ", &saveptr);
		if(token){
			if(!strcmp(token, "topic") || !strcmp(token, "pattern")){
				if(!strcmp(token, "topic")){
					topic_pattern = 0;
				}else{
					topic_pattern = 1;
				}

				access_s = strtok_r(NULL, " ", &saveptr);
				if(!access_s){
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty topic in acl_file \"%s\".", security_opts->acl_file);
					rc = MOSQ_ERR_INVAL;
					break;
				}
				token = strtok_r(NULL, "", &saveptr);
				if(token){
					topic = misc__trimblanks(token);
				}else{
					topic = access_s;
					access_s = NULL;
				}
				if(access_s){
					if(!strcmp(access_s, "read")){
						access = MOSQ_ACL_READ;
					}else if(!strcmp(access_s, "write")){
						access = MOSQ_ACL_WRITE;
					}else if(!strcmp(access_s, "readwrite")){
						access = MOSQ_ACL_READ | MOSQ_ACL_WRITE;
					}else if(!strcmp(access_s, "deny")){
						access = MOSQ_ACL_NONE;
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid topic access type \"%s\" in acl_file \"%s\".", access_s, security_opts->acl_file);
						rc = MOSQ_ERR_INVAL;
						break;
					}
				}else{
					access = MOSQ_ACL_READ | MOSQ_ACL_WRITE;
				}
				rc = mosquitto_sub_topic_check(topic);
				if(rc != MOSQ_ERR_SUCCESS){
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid ACL topic \"%s\" in acl_file \"%s\".", topic, security_opts->acl_file);
					rc = MOSQ_ERR_INVAL;
					break;
				}

				if(topic_pattern == 0){
					rc = add__acl(security_opts, user, topic, access);
				}else{
					rc = add__acl_pattern(security_opts, topic, access);
				}
				if(rc){
					break;
				}
			}else if(!strcmp(token, "user")){
				token = strtok_r(NULL, "", &saveptr);
				if(token){
					token = misc__trimblanks(token);
					if(slen == 0){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Missing username in acl_file \"%s\".", security_opts->acl_file);
						rc = MOSQ_ERR_INVAL;
						break;
					}
					mosquitto__free(user);
					user = mosquitto__strdup(token);
					if(!user){
						rc = MOSQ_ERR_NOMEM;
						break;
					}
				}else{
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Missing username in acl_file \"%s\".", security_opts->acl_file);
					rc = MOSQ_ERR_INVAL;
					break;
				}
			}else{
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid line in acl_file \"%s\": %s.", security_opts->acl_file, buf);
				rc = MOSQ_ERR_INVAL;
				break;
			}
		}
	}

	mosquitto__free(buf);
	mosquitto__free(user);
	fclose(aclfptr);

	return rc;
}

static void free__acl(struct mosquitto__acl *acl)
{
	if(!acl) return;

	if(acl->next){
		free__acl(acl->next);
	}
	mosquitto__free(acl->topic);
	mosquitto__free(acl);
}


static void acl__cleanup_single(struct mosquitto__security_options *security_opts)
{
	struct mosquitto__acl_user *user_tail;

	while(security_opts->acl_list){
		user_tail = security_opts->acl_list->next;

		free__acl(security_opts->acl_list->acl);
		mosquitto__free(security_opts->acl_list->username);
		mosquitto__free(security_opts->acl_list);

		security_opts->acl_list = user_tail;
	}

	if(security_opts->acl_patterns){
		free__acl(security_opts->acl_patterns);
		security_opts->acl_patterns = NULL;
	}
}


static int acl__cleanup(bool reload)
{
	struct mosquitto *context, *ctxt_tmp;
	int i;

	UNUSED(reload);

	/* As we're freeing ACLs, we must clear context->acl_list to ensure no
	 * invalid memory accesses take place later.
	 * This *requires* the ACLs to be reapplied after acl__cleanup()
	 * is called if we are reloading the config. If this is not done, all 
	 * access will be denied to currently connected clients.
	 */
	HASH_ITER(hh_id, db.contexts_by_id, context, ctxt_tmp){
		context->acl_list = NULL;
	}

	if(db.config->per_listener_settings){
		for(i=0; i<db.config->listener_count; i++){
			acl__cleanup_single(&db.config->listeners[i].security_options);
		}
	}else{
		acl__cleanup_single(&db.config->security_options);
	}

	return MOSQ_ERR_SUCCESS;
}


int acl__find_acls(struct mosquitto *context)
{
	struct mosquitto__acl_user *acl_tail;
	struct mosquitto__security_options *security_opts;

	/* Associate user with its ACL, assuming we have ACLs loaded. */
	if(db.config->per_listener_settings){
		if(!context->listener){
			return MOSQ_ERR_INVAL;
		}
		security_opts = &context->listener->security_options;
	}else{
		security_opts = &db.config->security_options;
	}

	if(security_opts->acl_list){
		acl_tail = security_opts->acl_list;
		while(acl_tail){
			if(context->username){
				if(acl_tail->username && !strcmp(context->username, acl_tail->username)){
					context->acl_list = acl_tail;
					break;
				}
			}else{
				if(acl_tail->username == NULL){
					context->acl_list = acl_tail;
					break;
				}
			}
			acl_tail = acl_tail->next;
		}
	}else{
		context->acl_list = NULL;
	}

	return MOSQ_ERR_SUCCESS;
}


static int pwfile__parse(const char *file, struct mosquitto__unpwd **root)
{
	FILE *pwfile;
	struct mosquitto__unpwd *unpwd;
	char *username, *password;
	char *saveptr = NULL;
	char *buf;
	int buflen = 256;

	buf = mosquitto__malloc((size_t)buflen);
	if(buf == NULL){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}
	
	pwfile = mosquitto__fopen(file, "rt", false);
	if(!pwfile){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open pwfile \"%s\".", file);
		mosquitto__free(buf);
		return MOSQ_ERR_UNKNOWN;
	}

	while(!feof(pwfile)){
		if(fgets_extending(&buf, &buflen, pwfile)){
			if(buf[0] == '#') continue;
			if(!strchr(buf, ':')) continue;

			username = strtok_r(buf, ":", &saveptr);
			if(username){
				unpwd = mosquitto__calloc(1, sizeof(struct mosquitto__unpwd));
				if(!unpwd){
					fclose(pwfile);
					mosquitto__free(buf);
					return MOSQ_ERR_NOMEM;
				}
				username = misc__trimblanks(username);
				if(strlen(username) > 65535){
					log__printf(NULL, MOSQ_LOG_NOTICE, "Warning: Invalid line in password file '%s', username too long.", file);
					mosquitto__free(unpwd);
					continue;
				}

				unpwd->username = mosquitto__strdup(username);
				if(!unpwd->username){
					mosquitto__free(unpwd);
					mosquitto__free(buf);
					fclose(pwfile);
					return MOSQ_ERR_NOMEM;
				}
				password = strtok_r(NULL, ":", &saveptr);
				if(password){
					password = misc__trimblanks(password);

					if(strlen(password) > 65535){
						log__printf(NULL, MOSQ_LOG_NOTICE, "Warning: Invalid line in password file '%s', password too long.", file);
						mosquitto__free(unpwd->username);
						mosquitto__free(unpwd);
						continue;
					}

					unpwd->password = mosquitto__strdup(password);
					if(!unpwd->password){
						fclose(pwfile);
						mosquitto__free(unpwd->username);
						mosquitto__free(unpwd);
						mosquitto__free(buf);
						return MOSQ_ERR_NOMEM;
					}

					HASH_ADD_KEYPTR(hh, *root, unpwd->username, strlen(unpwd->username), unpwd);
				}else{
					log__printf(NULL, MOSQ_LOG_NOTICE, "Warning: Invalid line in password file '%s': %s", file, buf);
					mosquitto__free(unpwd->username);
					mosquitto__free(unpwd);
				}
			}
		}
	}
	fclose(pwfile);
	mosquitto__free(buf);

	return MOSQ_ERR_SUCCESS;
}


void unpwd__free_item(struct mosquitto__unpwd **unpwd, struct mosquitto__unpwd *item)
{
	mosquitto__free(item->username);
	mosquitto__free(item->password);
#ifdef WITH_TLS
	mosquitto__free(item->salt);
#endif
	HASH_DEL(*unpwd, item);
	mosquitto__free(item);
}


#ifdef WITH_TLS
static int unpwd__decode_passwords(struct mosquitto__unpwd **unpwd)
{
	struct mosquitto__unpwd *u, *tmp;
	char *token;
	unsigned char *salt;
	unsigned int salt_len;
	unsigned char *password;
	unsigned int password_len;
	int rc;
	enum mosquitto_pwhash_type hashtype;

	HASH_ITER(hh, *unpwd, u, tmp){
		/* Need to decode password into hashed data + salt. */
		if(u->password == NULL){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Missing password hash for user %s, removing entry.", u->username);
			unpwd__free_item(unpwd, u);
			continue;
		}

		token = strtok(u->password, "$");
		if(token == NULL){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid password hash for user %s, removing entry.", u->username);
			unpwd__free_item(unpwd, u);
			continue;
		}

		if(!strcmp(token, "6")){
			hashtype = pw_sha512;
		}else if(!strcmp(token, "7")){
			hashtype = pw_sha512_pbkdf2;
		}else{
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid password hash type for user %s, removing entry.", u->username);
			unpwd__free_item(unpwd, u);
			continue;
		}

		if(hashtype == pw_sha512_pbkdf2){
			token = strtok(NULL, "$");
			if(token == NULL){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid password hash for user %s, removing entry.", u->username);
				unpwd__free_item(unpwd, u);
				continue;
			}
			u->iterations = atoi(token);
			if(u->iterations < 1){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid hash iterations for user %s, removing entry.", u->username);
				unpwd__free_item(unpwd, u);
				continue;
			}
		}

		token = strtok(NULL, "$");
		if(token == NULL){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid password hash for user %s, removing entry.", u->username);
			unpwd__free_item(unpwd, u);
			continue;
		}
		rc = base64__decode(token, &salt, &salt_len);
		if(rc == MOSQ_ERR_SUCCESS && salt_len == 12){
			u->salt = salt;
			u->salt_len = salt_len;
			token = strtok(NULL, "$");
			if(token){
				rc = base64__decode(token, &password, &password_len);
				if(rc == MOSQ_ERR_SUCCESS && password_len == 64){
					mosquitto__free(u->password);
					u->password = (char *)password;
					u->password_len = password_len;
					u->hashtype = hashtype;
				}else{
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to decode password for user %s, removing entry.", u->username);
					unpwd__free_item(unpwd, u);
				}
			}else{
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid password hash for user %s, removing entry.", u->username);
				unpwd__free_item(unpwd, u);
			}
		}else{
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to decode password salt for user %s, removing entry.", u->username);
			unpwd__free_item(unpwd, u);
		}
	}

	return MOSQ_ERR_SUCCESS;
}
#endif


static int unpwd__file_parse(struct mosquitto__unpwd **unpwd, const char *password_file)
{
	int rc;
	if(!unpwd) return MOSQ_ERR_INVAL;

	if(!password_file) return MOSQ_ERR_SUCCESS;

	rc = pwfile__parse(password_file, unpwd);

#ifdef WITH_TLS
	if(rc) return rc;
	rc = unpwd__decode_passwords(unpwd);
#endif

	return rc;
}

static int psk__file_parse(struct mosquitto__unpwd **psk_id, const char *psk_file)
{
	int rc;
	struct mosquitto__unpwd *u, *tmp;

	if(!db.config || !psk_id) return MOSQ_ERR_INVAL;

	/* We haven't been asked to parse a psk file. */
	if(!psk_file) return MOSQ_ERR_SUCCESS;

	rc = pwfile__parse(psk_file, psk_id);
	if(rc) return rc;

	HASH_ITER(hh, (*psk_id), u, tmp){
		/* Check for hex only digits */
		if(!u->password){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty psk for identity \"%s\".", u->username);
			return MOSQ_ERR_INVAL;
		}
		if(strspn(u->password, "0123456789abcdefABCDEF") < strlen(u->password)){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: psk for identity \"%s\" contains non-hexadecimal characters.", u->username);
			return MOSQ_ERR_INVAL;
		}
	}
	return MOSQ_ERR_SUCCESS;
}


#ifdef WITH_TLS
static int mosquitto__memcmp_const(const void *a, const void *b, size_t len)
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
#endif


static int mosquitto_unpwd_check_default(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_basic_auth *ed = event_data;
	struct mosquitto__unpwd *u;
	struct mosquitto__unpwd *unpwd_ref;
#ifdef WITH_TLS
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hash_len;
	int rc;
#endif

	if(ed->client->username == NULL){
		return MOSQ_ERR_PLUGIN_DEFER;
	}

	if(db.config->per_listener_settings){
		if(ed->client->bridge) return MOSQ_ERR_SUCCESS;
		if(!ed->client->listener) return MOSQ_ERR_INVAL;
		unpwd_ref = ed->client->listener->security_options.unpwd;
	}else{
		unpwd_ref = db.config->security_options.unpwd;
	}

	HASH_FIND(hh, unpwd_ref, ed->client->username, strlen(ed->client->username), u);
	if(u){
		if(u->password){
			if(ed->client->password){
#ifdef WITH_TLS
				rc = pw__digest(ed->client->password, u->salt, u->salt_len, hash, &hash_len, u->hashtype, u->iterations);
				if(rc == MOSQ_ERR_SUCCESS){
					if(hash_len == u->password_len && !mosquitto__memcmp_const(u->password, hash, hash_len)){
						return MOSQ_ERR_SUCCESS;
					}else{
						return MOSQ_ERR_AUTH;
					}
				}else{
					return rc;
				}
#else
				if(!strcmp(u->password, ed->client->password)){
					return MOSQ_ERR_SUCCESS;
				}
#endif
			}else{
				return MOSQ_ERR_AUTH;
			}
		}else{
			return MOSQ_ERR_SUCCESS;
		}
	}

	return MOSQ_ERR_AUTH;
}

static int unpwd__cleanup(struct mosquitto__unpwd **root, bool reload)
{
	struct mosquitto__unpwd *u, *tmp;

	UNUSED(reload);

	if(!root) return MOSQ_ERR_INVAL;

	HASH_ITER(hh, *root, u, tmp){
		HASH_DEL(*root, u);
		mosquitto__free(u->password);
		mosquitto__free(u->username);
#ifdef WITH_TLS
		mosquitto__free(u->salt);
#endif
		mosquitto__free(u);
	}

	*root = NULL;

	return MOSQ_ERR_SUCCESS;
}


#ifdef WITH_TLS
static void security__disconnect_auth(struct mosquitto *context)
{
	if(context->protocol == mosq_p_mqtt5){
		send__disconnect(context, MQTT_RC_ADMINISTRATIVE_ACTION, NULL);
	}
	mosquitto__set_state(context, mosq_cs_disconnecting);
	do_disconnect(context, MOSQ_ERR_AUTH);
}
#endif

/* Apply security settings after a reload.
 * Includes:
 * - Disconnecting anonymous users if appropriate
 * - Disconnecting users with invalid passwords
 * - Reapplying ACLs
 */
int mosquitto_security_apply_default(void)
{
	struct mosquitto *context, *ctxt_tmp;
	struct mosquitto__acl_user *acl_user_tail;
	bool allow_anonymous;
	struct mosquitto__security_options *security_opts = NULL;
#ifdef WITH_TLS
	int i;
	X509 *client_cert = NULL;
	X509_NAME *name;
	X509_NAME_ENTRY *name_entry;
	ASN1_STRING *name_asn1 = NULL;
	struct mosquitto__listener *listener;
	BIO *subject_bio;
	char *data_start;
	size_t name_length;
	char *subject;
#endif

#ifdef WITH_TLS
	for(i=0; i<db.config->listener_count; i++){
		listener = &db.config->listeners[i];
		if(listener && listener->ssl_ctx && listener->certfile && listener->keyfile && listener->crlfile && listener->require_certificate){
			if(net__tls_server_ctx(listener)){
				return MOSQ_ERR_TLS;
			}

			if(net__tls_load_verify(listener)){
				return MOSQ_ERR_TLS;
			}
		}
	}
#endif

	HASH_ITER(hh_id, db.contexts_by_id, context, ctxt_tmp){
		/* Check for anonymous clients when allow_anonymous is false */
		if(db.config->per_listener_settings){
			if(context->listener){
				allow_anonymous = context->listener->security_options.allow_anonymous;
			}else{
				/* Client not currently connected, so defer judgement until it does connect */
				allow_anonymous = true;
			}
		}else{
			allow_anonymous = db.config->security_options.allow_anonymous;
		}

		if(!allow_anonymous && !context->username){
			mosquitto__set_state(context, mosq_cs_disconnecting);
			do_disconnect(context, MOSQ_ERR_AUTH);
			continue;
		}

		/* Check for connected clients that are no longer authorised */
#ifdef WITH_TLS
		if(context->listener && context->listener->ssl_ctx && (context->listener->use_identity_as_username || context->listener->use_subject_as_username)){
			/* Client must have either a valid certificate, or valid PSK used as a username. */
			if(!context->ssl){
				if(context->protocol == mosq_p_mqtt5){
					send__disconnect(context, MQTT_RC_ADMINISTRATIVE_ACTION, NULL);
				}
				mosquitto__set_state(context, mosq_cs_disconnecting);
				do_disconnect(context, MOSQ_ERR_AUTH);
				continue;
			}
#ifdef FINAL_WITH_TLS_PSK
			if(context->listener->psk_hint){
				/* Client should have provided an identity to get this far. */
				if(!context->username){
					security__disconnect_auth(context);
					continue;
				}
			}else
#endif /* FINAL_WITH_TLS_PSK */
			{
				/* Free existing credentials and then recover them. */
				mosquitto__free(context->username);
				context->username = NULL;
				mosquitto__free(context->password);
				context->password = NULL;

				client_cert = SSL_get_peer_certificate(context->ssl);
				if(!client_cert){
					security__disconnect_auth(context);
					continue;
				}
				name = X509_get_subject_name(client_cert);
				if(!name){
					X509_free(client_cert);
					client_cert = NULL;
					security__disconnect_auth(context);
					continue;
				}
				if (context->listener->use_identity_as_username) { /* use_identity_as_username */
					i = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
					if(i == -1){
						X509_free(client_cert);
						client_cert = NULL;
						security__disconnect_auth(context);
						continue;
					}
					name_entry = X509_NAME_get_entry(name, i);
					if(name_entry){
						name_asn1 = X509_NAME_ENTRY_get_data(name_entry);
						if (name_asn1 == NULL) {
							X509_free(client_cert);
							client_cert = NULL;
							security__disconnect_auth(context);
							continue;
						}
#if OPENSSL_VERSION_NUMBER < 0x10100000L
						context->username = mosquitto__strdup((char *) ASN1_STRING_data(name_asn1));
#else
						context->username = mosquitto__strdup((char *) ASN1_STRING_get0_data(name_asn1));
#endif
						if(!context->username){
							X509_free(client_cert);
							client_cert = NULL;
							security__disconnect_auth(context);
							continue;
						}
						/* Make sure there isn't an embedded NUL character in the CN */
						if ((size_t)ASN1_STRING_length(name_asn1) != strlen(context->username)) {
							X509_free(client_cert);
							client_cert = NULL;
							security__disconnect_auth(context);
							continue;
						}
					}
				} else { /* use_subject_as_username */
					subject_bio = BIO_new(BIO_s_mem());
					X509_NAME_print_ex(subject_bio, X509_get_subject_name(client_cert), 0, XN_FLAG_RFC2253);
					data_start = NULL;
					name_length = (size_t)BIO_get_mem_data(subject_bio, &data_start);
					subject = mosquitto__malloc(sizeof(char)*name_length+1);
					if(!subject){
						BIO_free(subject_bio);
						X509_free(client_cert);
						client_cert = NULL;
						security__disconnect_auth(context);
						continue;
					}
					memcpy(subject, data_start, name_length);
					subject[name_length] = '\0';
					BIO_free(subject_bio);
					context->username = subject;
				}
				if(!context->username){
					X509_free(client_cert);
					client_cert = NULL;
					security__disconnect_auth(context);
					continue;
				}
				X509_free(client_cert);
				client_cert = NULL;
			}
		}else
#endif
		{
			/* Username/password check only if the identity/subject check not used */
			if(mosquitto_unpwd_check(context) != MOSQ_ERR_SUCCESS){
				mosquitto__set_state(context, mosq_cs_disconnecting);
				do_disconnect(context, MOSQ_ERR_AUTH);
				continue;
			}
		}


		/* Check for ACLs and apply to user. */
		if(db.config->per_listener_settings){
			if(context->listener){
				security_opts = &context->listener->security_options;
			}else{
				if(context->state != mosq_cs_active){
					mosquitto__set_state(context, mosq_cs_disconnecting);
					do_disconnect(context, MOSQ_ERR_AUTH);
					continue;
				}
			}
		}else{
			security_opts = &db.config->security_options;
		}

		if(security_opts && security_opts->acl_list){
			acl_user_tail = security_opts->acl_list;
			while(acl_user_tail){
				if(acl_user_tail->username){
					if(context->username){
						if(!strcmp(acl_user_tail->username, context->username)){
							context->acl_list = acl_user_tail;
							break;
						}
					}
				}else{
					if(!context->username){
						context->acl_list = acl_user_tail;
						break;
					}
				}
				acl_user_tail = acl_user_tail->next;
			}
		}
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_psk_key_get_default(struct mosquitto *context, const char *hint, const char *identity, char *key, int max_key_len)
{
	struct mosquitto__unpwd *u, *tmp;
	struct mosquitto__unpwd *psk_id_ref = NULL;

	if(!hint || !identity || !key) return MOSQ_ERR_INVAL;

	if(db.config->per_listener_settings){
		if(!context->listener) return MOSQ_ERR_INVAL;
		psk_id_ref = context->listener->security_options.psk_id;
	}else{
		psk_id_ref = db.config->security_options.psk_id;
	}
	if(!psk_id_ref) return MOSQ_ERR_PLUGIN_DEFER;

	HASH_ITER(hh, psk_id_ref, u, tmp){
		if(!strcmp(u->username, identity)){
			strncpy(key, u->password, (size_t)max_key_len);
			return MOSQ_ERR_SUCCESS;
		}
	}

	return MOSQ_ERR_AUTH;
}

#ifdef WITH_TLS
int pw__digest(const char *password, const unsigned char *salt, unsigned int salt_len, unsigned char *hash, unsigned int *hash_len, enum mosquitto_pwhash_type hashtype, int iterations)
{
	const EVP_MD *digest;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX context;
#else
	EVP_MD_CTX *context;
#endif

	digest = EVP_get_digestbyname("sha512");
	if(!digest){
		/* FIXME fprintf(stderr, "Error: Unable to create openssl digest.\n"); */
		return 1;
	}

	if(hashtype == pw_sha512){
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		EVP_MD_CTX_init(&context);
		EVP_DigestInit_ex(&context, digest, NULL);
		EVP_DigestUpdate(&context, password, strlen(password));
		EVP_DigestUpdate(&context, salt, salt_len);
		/* hash is assumed to be EVP_MAX_MD_SIZE bytes long. */
		EVP_DigestFinal_ex(&context, hash, hash_len);
		EVP_MD_CTX_cleanup(&context);
#else
		context = EVP_MD_CTX_new();
		EVP_DigestInit_ex(context, digest, NULL);
		EVP_DigestUpdate(context, password, strlen(password));
		EVP_DigestUpdate(context, salt, salt_len);
		/* hash is assumed to be EVP_MAX_MD_SIZE bytes long. */
		EVP_DigestFinal_ex(context, hash, hash_len);
		EVP_MD_CTX_free(context);
#endif
	}else{
		*hash_len = EVP_MAX_MD_SIZE;
		PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
			salt, (int)salt_len, iterations,
			digest, (int)(*hash_len), hash);
	}

	return MOSQ_ERR_SUCCESS;
}

#endif
