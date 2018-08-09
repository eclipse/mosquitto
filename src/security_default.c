/*
Copyright (c) 2011-2018 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include <stdio.h>
#include <string.h>

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "util_mosq.h"

static int aclfile__parse(struct mosquitto_db *db, struct mosquitto__security_options *security_opts);
static int unpwd__file_parse(struct mosquitto__unpwd **unpwd, const char *password_file);
static int acl__cleanup(struct mosquitto_db *db, bool reload);
static int unpwd__cleanup(struct mosquitto__unpwd **unpwd, bool reload);
static int psk__file_parse(struct mosquitto_db *db, struct mosquitto__unpwd **psk_id, const char *psk_file);
#ifdef WITH_TLS
static int pw__digest(const char *password, const unsigned char *salt, unsigned int salt_len, unsigned char *hash, unsigned int *hash_len);
static int base64__decode(char *in, unsigned char **decoded, unsigned int *decoded_len);
static int mosquitto__memcmp_const(const void *ptr1, const void *b, size_t len);
#endif



int mosquitto_security_init_default(struct mosquitto_db *db, bool reload)
{
	int rc;
	int i;
	char *pwf;
	char *pskf;

	/* Load username/password data if required. */
	if(db->config->per_listener_settings){
		for(i=0; i<db->config->listener_count; i++){
			pwf = db->config->listeners[i].security_options.password_file;
			if(pwf){
				rc = unpwd__file_parse(&db->config->listeners[i].unpwd, pwf);
				if(rc){
					log__printf(NULL, MOSQ_LOG_ERR, "Error opening password file \"%s\".", pwf);
					return rc;
				}
			}
		}
	}else{
		if(db->config->security_options.password_file){
			pwf = db->config->security_options.password_file;
			if(pwf){
				rc = unpwd__file_parse(&db->unpwd, pwf);
				if(rc){
					log__printf(NULL, MOSQ_LOG_ERR, "Error opening password file \"%s\".", pwf);
					return rc;
				}
			}
		}
	}

	/* Load acl data if required. */
	if(db->config->per_listener_settings){
		for(i=0; i<db->config->listener_count; i++){
			if(db->config->listeners[i].security_options.acl_file){
				rc = aclfile__parse(db, &db->config->listeners[i].security_options);
				if(rc){
					log__printf(NULL, MOSQ_LOG_ERR, "Error opening acl file \"%s\".", db->config->listeners[i].security_options.acl_file);
					return rc;
				}
			}
		}
	}else{
		if(db->config->security_options.acl_file){
			rc = aclfile__parse(db, &db->config->security_options);
			if(rc){
				log__printf(NULL, MOSQ_LOG_ERR, "Error opening acl file \"%s\".", db->config->security_options.acl_file);
				return rc;
			}
		}
	}

	/* Load psk data if required. */
	if(db->config->per_listener_settings){
		for(i=0; i<db->config->listener_count; i++){
			pskf = db->config->listeners[i].security_options.psk_file;
			if(pskf){
				rc = psk__file_parse(db, &db->config->listeners[i].psk_id, pskf);
				if(rc){
					log__printf(NULL, MOSQ_LOG_ERR, "Error opening psk file \"%s\".", pskf);
					return rc;
				}
			}
		}
	}else{
		char *pskf = db->config->security_options.psk_file;
		if(pskf){
			rc = psk__file_parse(db, &db->psk_id, pskf);
			if(rc){
				log__printf(NULL, MOSQ_LOG_ERR, "Error opening psk file \"%s\".", pskf);
				return rc;
			}
		}
	}

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_security_cleanup_default(struct mosquitto_db *db, bool reload)
{
	int rc;
	int i;

	rc = acl__cleanup(db, reload);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	rc = unpwd__cleanup(&db->unpwd, reload);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	for(i=0; i<db->config->listener_count; i++){
		if(db->config->listeners[i].unpwd){
			rc = unpwd__cleanup(&db->config->listeners[i].unpwd, reload);
			if(rc != MOSQ_ERR_SUCCESS) return rc;
		}
	}

	rc = unpwd__cleanup(&db->psk_id, reload);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	for(i=0; i<db->config->listener_count; i++){
		if(db->config->listeners[i].psk_id){
			rc = unpwd__cleanup(&db->config->listeners[i].psk_id, reload);
			if(rc != MOSQ_ERR_SUCCESS) return rc;
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
		while(acl_tail->next){
			acl_tail = acl_tail->next;
		}
		acl_tail->next = acl;
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

	if(security_opts->acl_patterns){
		acl_tail = security_opts->acl_patterns;
		while(acl_tail->next){
			acl_tail = acl_tail->next;
		}
		acl_tail->next = acl;
	}else{
		security_opts->acl_patterns = acl;
	}

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_acl_check_default(struct mosquitto_db *db, struct mosquitto *context, const char *topic, int access)
{
	char *local_acl;
	struct mosquitto__acl *acl_root;
	bool result;
	int i;
	int len, tlen, clen, ulen;
	char *s;
	struct mosquitto__security_options *security_opts = NULL;

	if(!db || !context || !topic) return MOSQ_ERR_INVAL;

	if(db->config->per_listener_settings){
		if(!context->listener) return MOSQ_ERR_ACL_DENIED;
		security_opts = &context->listener->security_options;
	}else{
		security_opts = &db->config->security_options;
	}
	if(!security_opts->acl_list && !security_opts->acl_patterns){
			return MOSQ_ERR_PLUGIN_DEFER;
	}

	if(context->bridge) return MOSQ_ERR_SUCCESS;
	if(access == MOSQ_ACL_SUBSCRIBE) return MOSQ_ERR_SUCCESS; /* FIXME - implement ACL subscription strings. */
	if(!context->acl_list && !security_opts->acl_patterns) return MOSQ_ERR_ACL_DENIED;

	if(context->acl_list){
		acl_root = context->acl_list->acl;
	}else{
		acl_root = NULL;
	}

	/* Loop through all ACLs for this client. */
	while(acl_root){
		/* Loop through the topic looking for matches to this ACL. */

		/* If subscription starts with $, acl_root->topic must also start with $. */
		if(topic[0] == '$' && acl_root->topic[0] != '$'){
			acl_root = acl_root->next;
			continue;
		}
		mosquitto_topic_matches_sub(acl_root->topic, topic, &result);
		if(result){
			if(access & acl_root->access){
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
		if(context->username && strpbrk(context->username, "+#")){
			log__printf(NULL, MOSQ_LOG_NOTICE, "ACL denying access to client with dangerous username \"%s\"", context->username);
			return MOSQ_ERR_ACL_DENIED;
		}

		if(context->id && strpbrk(context->id, "+#")){
			log__printf(NULL, MOSQ_LOG_NOTICE, "ACL denying access to client with dangerous client id \"%s\"", context->id);
			return MOSQ_ERR_ACL_DENIED;
		}
	}

	/* Loop through all pattern ACLs. */
	if(!context->id) return MOSQ_ERR_ACL_DENIED;
	clen = strlen(context->id);

	while(acl_root){
		tlen = strlen(acl_root->topic);

		if(acl_root->ucount && !context->username){
			acl_root = acl_root->next;
			continue;
		}

		if(context->username){
			ulen = strlen(context->username);
			len = tlen + acl_root->ccount*(clen-2) + acl_root->ucount*(ulen-2);
		}else{
			ulen = 0;
			len = tlen + acl_root->ccount*(clen-2);
		}
		local_acl = mosquitto__malloc(len+1);
		if(!local_acl) return 1; // FIXME
		s = local_acl;
		for(i=0; i<tlen; i++){
			if(i<tlen-1 && acl_root->topic[i] == '%'){
				if(acl_root->topic[i+1] == 'c'){
					i++;
					strncpy(s, context->id, clen);
					s+=clen;
					continue;
				}else if(context->username && acl_root->topic[i+1] == 'u'){
					i++;
					strncpy(s, context->username, ulen);
					s+=ulen;
					continue;
				}
			}
			s[0] = acl_root->topic[i];
			s++;
		}
		local_acl[len] = '\0';

		mosquitto_topic_matches_sub(local_acl, topic, &result);
		mosquitto__free(local_acl);
		if(result){
			if(access & acl_root->access){
				/* And access is allowed. */
				return MOSQ_ERR_SUCCESS;
			}
		}

		acl_root = acl_root->next;
	}

	return MOSQ_ERR_ACL_DENIED;
}


static int aclfile__parse(struct mosquitto_db *db, struct mosquitto__security_options *security_opts)
{
	FILE *aclfptr;
	char buf[1024];
	char *token;
	char *user = NULL;
	char *topic;
	char *access_s;
	int access;
	int rc;
	int slen;
	int topic_pattern;
	char *saveptr = NULL;

	if(!db || !db->config) return MOSQ_ERR_INVAL;
	if(!security_opts) return MOSQ_ERR_INVAL;
	if(!security_opts->acl_file) return MOSQ_ERR_SUCCESS;

	aclfptr = mosquitto__fopen(security_opts->acl_file, "rt", false);
	if(!aclfptr){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open acl_file \"%s\".", security_opts->acl_file);
		return 1;
	}

	// topic [read|write] <topic> 
	// user <user>

	while(fgets(buf, 1024, aclfptr)){
		slen = strlen(buf);
		while(slen > 0 && (buf[slen-1] == 10 || buf[slen-1] == 13)){
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
					mosquitto__free(user);
					fclose(aclfptr);
					return MOSQ_ERR_INVAL;
				}
				token = strtok_r(NULL, "", &saveptr);
				if(token){
					topic = token;
					/* Ignore duplicate spaces */
					while(topic[0] == ' '){
						topic++;
					}
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
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid topic access type \"%s\" in acl_file \"%s\".", access_s, security_opts->acl_file);
						mosquitto__free(user);
						fclose(aclfptr);
						return MOSQ_ERR_INVAL;
					}
				}else{
					access = MOSQ_ACL_READ | MOSQ_ACL_WRITE;
				}
				if(topic_pattern == 0){
					rc = add__acl(security_opts, user, topic, access);
				}else{
					rc = add__acl_pattern(security_opts, topic, access);
				}
				if(rc){
					mosquitto__free(user);
					fclose(aclfptr);
					return rc;
				}
			}else if(!strcmp(token, "user")){
				token = strtok_r(NULL, "", &saveptr);
				if(token){
					/* Ignore duplicate spaces */
					while(token[0] == ' '){
						token++;
					}
					mosquitto__free(user);
					user = mosquitto__strdup(token);
					if(!user){
						fclose(aclfptr);
						return MOSQ_ERR_NOMEM;
					}
				}else{
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Missing username in acl_file \"%s\".", security_opts->acl_file);
					mosquitto__free(user);
					fclose(aclfptr);
					return 1;
				}
			}
		}
	}

	mosquitto__free(user);
	fclose(aclfptr);

	return MOSQ_ERR_SUCCESS;
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


static int acl__cleanup(struct mosquitto_db *db, bool reload)
{
	struct mosquitto *context, *ctxt_tmp;
	int i;

	if(!db) return MOSQ_ERR_INVAL;

	/* As we're freeing ACLs, we must clear context->acl_list to ensure no
	 * invalid memory accesses take place later.
	 * This *requires* the ACLs to be reapplied after acl__cleanup()
	 * is called if we are reloading the config. If this is not done, all 
	 * access will be denied to currently connected clients.
	 */
	HASH_ITER(hh_id, db->contexts_by_id, context, ctxt_tmp){
		context->acl_list = NULL;
	}

	if(db->config->per_listener_settings){
		for(i=0; i<db->config->listener_count; i++){
			acl__cleanup_single(&db->config->listeners[i].security_options);
		}
	}else{
		acl__cleanup_single(&db->config->security_options);
	}

	return MOSQ_ERR_SUCCESS;
}

static int pwfile__parse(const char *file, struct mosquitto__unpwd **root)
{
	FILE *pwfile;
	struct mosquitto__unpwd *unpwd;
	char buf[256];
	char *username, *password;
	int len;
	char *saveptr = NULL;

	pwfile = mosquitto__fopen(file, "rt", false);
	if(!pwfile){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open pwfile \"%s\".", file);
		return 1;
	}

	while(!feof(pwfile)){
		if(fgets(buf, 256, pwfile)){
			username = strtok_r(buf, ":", &saveptr);
			if(username){
				unpwd = mosquitto__calloc(1, sizeof(struct mosquitto__unpwd));
				if(!unpwd){
					fclose(pwfile);
					return MOSQ_ERR_NOMEM;
				}
				unpwd->username = mosquitto__strdup(username);
				if(!unpwd->username){
					mosquitto__free(unpwd);
					fclose(pwfile);
					return MOSQ_ERR_NOMEM;
				}
				len = strlen(unpwd->username);
				while(unpwd->username[len-1] == 10 || unpwd->username[len-1] == 13){
					unpwd->username[len-1] = '\0';
					len = strlen(unpwd->username);
				}
				password = strtok_r(NULL, ":", &saveptr);
				if(password){
					unpwd->password = mosquitto__strdup(password);
					if(!unpwd->password){
						fclose(pwfile);
						mosquitto__free(unpwd->username);
						mosquitto__free(unpwd);
						return MOSQ_ERR_NOMEM;
					}
					len = strlen(unpwd->password);
					while(len && (unpwd->password[len-1] == 10 || unpwd->password[len-1] == 13)){
						unpwd->password[len-1] = '\0';
						len = strlen(unpwd->password);
					}
				}
				HASH_ADD_KEYPTR(hh, *root, unpwd->username, strlen(unpwd->username), unpwd);
			}
		}
	}
	fclose(pwfile);

	return MOSQ_ERR_SUCCESS;
}

static int unpwd__file_parse(struct mosquitto__unpwd **unpwd, const char *password_file)
{
	int rc;
#ifdef WITH_TLS
	struct mosquitto__unpwd *u, *tmp;
	char *token;
	unsigned char *salt;
	unsigned int salt_len;
	unsigned char *password;
	unsigned int password_len;
#endif

	if(!unpwd) return MOSQ_ERR_INVAL;

	if(!password_file) return MOSQ_ERR_SUCCESS;

	rc = pwfile__parse(password_file, unpwd);
#ifdef WITH_TLS
	if(rc) return rc;

	HASH_ITER(hh, *unpwd, u, tmp){
		/* Need to decode password into hashed data + salt. */
		if(u->password){
			token = strtok(u->password, "$");
			if(token && !strcmp(token, "6")){
				token = strtok(NULL, "$");
				if(token){
					rc = base64__decode(token, &salt, &salt_len);
					if(rc){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to decode password salt for user %s.", u->username);
						return MOSQ_ERR_INVAL;
					}
					u->salt = salt;
					u->salt_len = salt_len;
					token = strtok(NULL, "$");
					if(token){
						rc = base64__decode(token, &password, &password_len);
						if(rc){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to decode password for user %s.", u->username);
							return MOSQ_ERR_INVAL;
						}
						mosquitto__free(u->password);
						u->password = (char *)password;
						u->password_len = password_len;
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid password hash for user %s.", u->username);
						return MOSQ_ERR_INVAL;
					}
				}else{
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid password hash for user %s.", u->username);
					return MOSQ_ERR_INVAL;
				}
			}else{
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid password hash for user %s.", u->username);
				return MOSQ_ERR_INVAL;
			}
		}
	}
#endif
	return rc;
}

static int psk__file_parse(struct mosquitto_db *db, struct mosquitto__unpwd **psk_id, const char *psk_file)
{
	int rc;
	struct mosquitto__unpwd *u, *tmp;

	if(!db || !db->config || !psk_id) return MOSQ_ERR_INVAL;

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
	int i;
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


int mosquitto_unpwd_check_default(struct mosquitto_db *db, struct mosquitto *context, const char *username, const char *password)
{
	struct mosquitto__unpwd *u, *tmp;
	struct mosquitto__unpwd *unpwd_ref;
#ifdef WITH_TLS
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hash_len;
	int rc;
#endif

	if(!db) return MOSQ_ERR_INVAL;

	if(db->config->per_listener_settings){
		if(!context->listener) return MOSQ_ERR_INVAL;
		if(!context->listener->unpwd) return MOSQ_ERR_PLUGIN_DEFER;
		unpwd_ref = context->listener->unpwd;
	}else{
		if(!db->unpwd) return MOSQ_ERR_PLUGIN_DEFER;
		unpwd_ref = db->unpwd;
	}
	if(!username) return MOSQ_ERR_INVAL; /* Check must be made only after checking unpwd_ref. */

	HASH_ITER(hh, unpwd_ref, u, tmp){
		if(!strcmp(u->username, username)){
			if(u->password){
				if(password){
#ifdef WITH_TLS
					rc = pw__digest(password, u->salt, u->salt_len, hash, &hash_len);
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
					if(!strcmp(u->password, password)){
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
	}

	return MOSQ_ERR_AUTH;
}

static int unpwd__cleanup(struct mosquitto__unpwd **root, bool reload)
{
	struct mosquitto__unpwd *u, *tmp;

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

/* Apply security settings after a reload.
 * Includes:
 * - Disconnecting anonymous users if appropriate
 * - Disconnecting users with invalid passwords
 * - Reapplying ACLs
 */
int mosquitto_security_apply_default(struct mosquitto_db *db)
{
	struct mosquitto *context, *ctxt_tmp;
	struct mosquitto__acl_user *acl_user_tail;
	bool allow_anonymous;
	struct mosquitto__security_options *security_opts = NULL;

	if(!db) return MOSQ_ERR_INVAL;

	
	HASH_ITER(hh_id, db->contexts_by_id, context, ctxt_tmp){
		/* Check for anonymous clients when allow_anonymous is false */
		if(db->config->per_listener_settings){
			allow_anonymous = context->listener->security_options.allow_anonymous;
		}else{
			allow_anonymous = db->config->security_options.allow_anonymous;
		}

		if(!allow_anonymous && !context->username){
			context->state = mosq_cs_disconnecting;
			do_disconnect(db, context);
			continue;
		}
		/* Check for connected clients that are no longer authorised */
		if(mosquitto_unpwd_check(db, context, context->username, context->password) != MOSQ_ERR_SUCCESS){
			context->state = mosq_cs_disconnecting;
			do_disconnect(db, context);
			continue;
		}
		/* Check for ACLs and apply to user. */
		if(db->config->per_listener_settings){
			if(context->listener){
				security_opts = &context->listener->security_options;
			}else{
				if(context->state != mosq_cs_connected){
					context->state = mosq_cs_disconnecting;
					do_disconnect(db, context);
					continue;
				}
			}
		}else{
			security_opts = &db->config->security_options;
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

int mosquitto_psk_key_get_default(struct mosquitto_db *db, struct mosquitto *context, const char *hint, const char *identity, char *key, int max_key_len)
{
	struct mosquitto__unpwd *u, *tmp;
	struct mosquitto__unpwd *psk_id_ref = NULL;

	if(!db || !hint || !identity || !key) return MOSQ_ERR_INVAL;

	if(db->config->per_listener_settings){
		if(!context->listener) return MOSQ_ERR_INVAL;
		if(!context->listener->psk_id) return MOSQ_ERR_PLUGIN_DEFER;
		psk_id_ref = context->listener->psk_id;
	}else{
		if(!db->psk_id) return MOSQ_ERR_PLUGIN_DEFER;
		psk_id_ref = db->psk_id;
	}
	if(!psk_id_ref) return MOSQ_ERR_PLUGIN_DEFER;

	HASH_ITER(hh, psk_id_ref, u, tmp){
		if(!strcmp(u->username, identity)){
			strncpy(key, u->password, max_key_len);
			return MOSQ_ERR_SUCCESS;
		}
	}

	return MOSQ_ERR_AUTH;
}

#ifdef WITH_TLS
int pw__digest(const char *password, const unsigned char *salt, unsigned int salt_len, unsigned char *hash, unsigned int *hash_len)
{
	const EVP_MD *digest;
#ifndef HAVE_OPENSSL_OPAQUE_STRUCTS
	EVP_MD_CTX context;

	digest = EVP_get_digestbyname("sha512");
	if(!digest){
		// FIXME fprintf(stderr, "Error: Unable to create openssl digest.\n");
		return 1;
	}

	EVP_MD_CTX_init(&context);
	EVP_DigestInit_ex(&context, digest, NULL);
	EVP_DigestUpdate(&context, password, strlen(password));
	EVP_DigestUpdate(&context, salt, salt_len);
	/* hash is assumed to be EVP_MAX_MD_SIZE bytes long. */
	EVP_DigestFinal_ex(&context, hash, hash_len);
	EVP_MD_CTX_cleanup(&context);
#else
	EVP_MD_CTX *context;

	digest = EVP_get_digestbyname("sha512");
	if(!digest){
		// FIXME fprintf(stderr, "Error: Unable to create openssl digest.\n");
		return 1;
	}

	context = EVP_MD_CTX_new();
	EVP_DigestInit_ex(context, digest, NULL);
	EVP_DigestUpdate(context, password, strlen(password));
	EVP_DigestUpdate(context, salt, salt_len);
	/* hash is assumed to be EVP_MAX_MD_SIZE bytes long. */
	EVP_DigestFinal_ex(context, hash, hash_len);
	EVP_MD_CTX_free(context);
#endif

	return MOSQ_ERR_SUCCESS;
}

int base64__decode(char *in, unsigned char **decoded, unsigned int *decoded_len)
{
	BIO *bmem, *b64;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(bmem, in, strlen(in));

	if(BIO_flush(bmem) != 1){
		BIO_free_all(b64);
		return 1;
	}
	*decoded = mosquitto__calloc(strlen(in), 1);
	*decoded_len =  BIO_read(b64, *decoded, strlen(in));
	BIO_free_all(b64);

	return 0;
}

#endif
