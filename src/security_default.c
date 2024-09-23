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

static int aclfile__parse(struct mosquitto__security_options *security_opts);
static int unpwd__file_parse(struct mosquitto__unpwd **unpwd, const char *password_file);
static int acl__cleanup(bool reload);
static int unpwd__cleanup(struct mosquitto__unpwd **unpwd, bool reload);
static int mosquitto_basic_auth_default(int event, void *event_data, void *userdata);
static int mosquitto_acl_check_default(int event, void *event_data, void *userdata);


int mosquitto_security_init_default(bool reload)
{
	int rc;
	char *pwf;

	UNUSED(reload);

	/* Configure plugin identifier */
	if(db.config->per_listener_settings){
		for(int i=0; i<db.config->listener_count; i++){
			db.config->listeners[i].security_options->pid = mosquitto_calloc(1, sizeof(mosquitto_plugin_id_t));
			if(db.config->listeners[i].security_options->pid == NULL){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				return MOSQ_ERR_NOMEM;
			}
			db.config->listeners[i].security_options->pid->plugin_name = mosquitto_strdup("builtin-security");
			db.config->listeners[i].security_options->pid->listener = &db.config->listeners[i];
			config__plugin_add_secopt(db.config->listeners[i].security_options->pid, db.config->listeners[i].security_options);
		}
	}else{
		db.config->security_options.pid = mosquitto_calloc(1, sizeof(mosquitto_plugin_id_t));
		if(db.config->security_options.pid == NULL){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
		db.config->security_options.pid->plugin_name = mosquitto_strdup("builtin-security");
		config__plugin_add_secopt(db.config->security_options.pid, &db.config->security_options);
	}

	/* Load username/password data if required. */
	if(db.config->per_listener_settings){
		for(int i=0; i<db.config->listener_count; i++){
			pwf = db.config->listeners[i].security_options->password_file;
			if(pwf){
				rc = unpwd__file_parse(&db.config->listeners[i].security_options->unpwd, pwf);
				if(rc){
					log__printf(NULL, MOSQ_LOG_ERR, "Error opening password file \"%s\".", pwf);
					return rc;
				}
				mosquitto_callback_register(db.config->listeners[i].security_options->pid,
						MOSQ_EVT_BASIC_AUTH, mosquitto_basic_auth_default, NULL, NULL);
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
					MOSQ_EVT_BASIC_AUTH, mosquitto_basic_auth_default, NULL, NULL);
		}
	}

	/* Load acl data if required. */
	if(db.config->per_listener_settings){
		for(int i=0; i<db.config->listener_count; i++){
			if(db.config->listeners[i].security_options->acl_file){
				rc = aclfile__parse(db.config->listeners[i].security_options);
				if(rc){
					log__printf(NULL, MOSQ_LOG_ERR, "Error opening acl file \"%s\".", db.config->listeners[i].security_options->acl_file);
					return rc;
				}
				if(db.config->listeners[i].security_options->plugin_count == 0){
					config__plugin_add_secopt(db.config->listeners[i].security_options->pid, db.config->listeners[i].security_options);
				}

				mosquitto_callback_register(db.config->listeners[i].security_options->pid,
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
			if(db.config->security_options.plugin_count == 0){
				config__plugin_add_secopt(db.config->security_options.pid, &db.config->security_options);
			}

			mosquitto_callback_register(db.config->security_options.pid,
					MOSQ_EVT_ACL_CHECK, mosquitto_acl_check_default, NULL, NULL);
		}
	}

	rc = psk_file__init();
	if(rc) return rc;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_security_cleanup_default(bool reload)
{
	int rc;

	rc = acl__cleanup(reload);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	rc = unpwd__cleanup(&db.config->security_options.unpwd, reload);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	for(int i=0; i<db.config->listener_count; i++){
		if(db.config->listeners[i].security_options->unpwd){
			rc = unpwd__cleanup(&db.config->listeners[i].security_options->unpwd, reload);
			if(rc != MOSQ_ERR_SUCCESS) return rc;
		}
	}

	rc = psk_file__cleanup();
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	if(db.config->per_listener_settings){
		for(int i=0; i<db.config->listener_count; i++){
			if(db.config->listeners[i].security_options->pid){
				mosquitto_callback_unregister(db.config->listeners[i].security_options->pid,
						MOSQ_EVT_BASIC_AUTH, mosquitto_basic_auth_default, NULL);
				mosquitto_callback_unregister(db.config->listeners[i].security_options->pid,
						MOSQ_EVT_ACL_CHECK, mosquitto_acl_check_default, NULL);

				mosquitto_FREE(db.config->listeners[i].security_options->pid->plugin_name);
				mosquitto_FREE(db.config->listeners[i].security_options->pid->config.security_options);
				mosquitto_FREE(db.config->listeners[i].security_options->pid);
			}
		}
	}else{
		if(db.config->security_options.pid){
			mosquitto_callback_unregister(db.config->security_options.pid,
					MOSQ_EVT_BASIC_AUTH, mosquitto_basic_auth_default, NULL);
			mosquitto_callback_unregister(db.config->security_options.pid,
					MOSQ_EVT_ACL_CHECK, mosquitto_acl_check_default, NULL);

			mosquitto_FREE(db.config->security_options.pid->plugin_name);
			mosquitto_FREE(db.config->security_options.pid->config.security_options);
			mosquitto_FREE(db.config->security_options.pid);
		}
	}
	return MOSQ_ERR_SUCCESS;
}


static int add__acl(struct mosquitto__security_options *security_opts, const char *user, const char *topic, int access)
{
	struct mosquitto__acl_user *acl_user=NULL, *user_tail;
	struct mosquitto__acl *acl, *acl_tail;
	char *local_topic;
	bool new_user = false;

	if(!security_opts || !topic) return MOSQ_ERR_INVAL;

	local_topic = mosquitto_strdup(topic);
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
		acl_user = mosquitto_malloc(sizeof(struct mosquitto__acl_user));
		if(!acl_user){
			mosquitto_FREE(local_topic);
			return MOSQ_ERR_NOMEM;
		}
		new_user = true;
		if(user){
			acl_user->username = mosquitto_strdup(user);
			if(!acl_user->username){
				mosquitto_FREE(local_topic);
				mosquitto_FREE(acl_user);
				return MOSQ_ERR_NOMEM;
			}
		}else{
			acl_user->username = NULL;
		}
		acl_user->next = NULL;
		acl_user->acl = NULL;
	}

	acl = mosquitto_malloc(sizeof(struct mosquitto__acl));
	if(!acl){
		mosquitto_FREE(local_topic);
		mosquitto_FREE(acl_user->username);
		mosquitto_FREE(acl_user);
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

static int add__acl_pattern(struct mosquitto__security_options *security_opts, const char *topic, int access)
{
	struct mosquitto__acl *acl, *acl_tail;
	char *local_topic;
	char *s;

	if(!security_opts| !topic) return MOSQ_ERR_INVAL;

	local_topic = mosquitto_strdup(topic);
	if(!local_topic){
		return MOSQ_ERR_NOMEM;
	}

	acl = mosquitto_malloc(sizeof(struct mosquitto__acl));
	if(!acl){
		mosquitto_FREE(local_topic);
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
	struct mosquitto__acl *acl_root;
	bool result;
	struct mosquitto__security_options *security_opts = NULL;

	UNUSED(event);
	UNUSED(userdata);

	if(ed->client->bridge) return MOSQ_ERR_SUCCESS;
	if(ed->access == MOSQ_ACL_SUBSCRIBE || ed->access == MOSQ_ACL_UNSUBSCRIBE) return MOSQ_ERR_SUCCESS; /* FIXME - implement ACL subscription strings. */

	if(db.config->per_listener_settings){
		if(!ed->client->listener) return MOSQ_ERR_ACL_DENIED;
		security_opts = ed->client->listener->security_options;
	}else{
		security_opts = &db.config->security_options;
	}
	if(!security_opts->acl_file && !security_opts->acl_list && !security_opts->acl_patterns){
		return MOSQ_ERR_PLUGIN_IGNORE;
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

	while(acl_root){
		if(acl_root->ucount && !ed->client->username){
			acl_root = acl_root->next;
			continue;
		}

		if(mosquitto_topic_matches_sub_with_pattern(acl_root->topic, ed->topic, ed->client->id, ed->client->username, &result)){
			return MOSQ_ERR_ACL_DENIED;
		}
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

	buf = mosquitto_malloc((size_t)buflen);
	if(buf == NULL){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}

	aclfptr = mosquitto_fopen(security_opts->acl_file, "rt", true);
	if(!aclfptr){
		mosquitto_FREE(buf);
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open acl_file \"%s\".", security_opts->acl_file);
		return MOSQ_ERR_UNKNOWN;
	}

	/* topic [read|write] <topic>
	 * user <user>
	 */

	while(mosquitto_fgets(&buf, &buflen, aclfptr)){
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
					topic = mosquitto_trimblanks(token);
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
					token = mosquitto_trimblanks(token);
					if(slen == 0){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Missing username in acl_file \"%s\".", security_opts->acl_file);
						rc = MOSQ_ERR_INVAL;
						break;
					}
					mosquitto_FREE(user);
					user = mosquitto_strdup(token);
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

	mosquitto_FREE(buf);
	mosquitto_FREE(user);
	fclose(aclfptr);

	return rc;
}

static void free__acl(struct mosquitto__acl *acl)
{
	if(!acl) return;

	if(acl->next){
		free__acl(acl->next);
	}
	mosquitto_FREE(acl->topic);
	mosquitto_FREE(acl);
}


static void acl__cleanup_single(struct mosquitto__security_options *security_opts)
{
	struct mosquitto__acl_user *user_tail;

	while(security_opts->acl_list){
		user_tail = security_opts->acl_list->next;

		free__acl(security_opts->acl_list->acl);
		mosquitto_FREE(security_opts->acl_list->username);
		mosquitto_FREE(security_opts->acl_list);

		security_opts->acl_list = user_tail;
	}

	if(security_opts->acl_patterns){
		free__acl(security_opts->acl_patterns);
		security_opts->acl_patterns = NULL;
	}
}


static int acl__cleanup(bool reload)
{
	struct mosquitto *context, *ctxt_tmp = NULL;

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
		for(int i=0; i<db.config->listener_count; i++){
			acl__cleanup_single(db.config->listeners[i].security_options);
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
		security_opts = context->listener->security_options;
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

				HASH_FIND(hh, *root, username, strlen(username), unpwd);
				if(unpwd){
					log__printf(NULL, MOSQ_LOG_NOTICE, "Error: Duplicate user '%s' in password file '%s', ignoring.", username, file);
					continue;
				}

				unpwd = mosquitto_calloc(1, sizeof(struct mosquitto__unpwd));
				if(!unpwd){
					fclose(pwfile);
					mosquitto_FREE(buf);
					return MOSQ_ERR_NOMEM;
				}

				unpwd->username = mosquitto_strdup(username);
				if(!unpwd->username){
					mosquitto_FREE(unpwd);
					mosquitto_FREE(buf);
					fclose(pwfile);
					return MOSQ_ERR_NOMEM;
				}
				password = strtok_r(NULL, ":", &saveptr);
				if(password){
					password = mosquitto_trimblanks(password);

					if(strlen(password) > 65535){
						log__printf(NULL, MOSQ_LOG_NOTICE, "Warning: Invalid line in password file '%s', password too long.", file);
						mosquitto_FREE(unpwd->username);
						mosquitto_FREE(unpwd);
						continue;
					}

					if(mosquitto_pw_new(&unpwd->pw, MOSQ_PW_DEFAULT)
							|| mosquitto_pw_decode(unpwd->pw, password)){

						log__printf(NULL, MOSQ_LOG_NOTICE, "Warning: Unable to decode line in password file '%s'.", file);
						mosquitto_pw_cleanup(unpwd->pw);
						mosquitto_FREE(unpwd->username);
						mosquitto_FREE(unpwd);
						continue;
					}

					HASH_ADD_KEYPTR(hh, *root, unpwd->username, strlen(unpwd->username), unpwd);
				}else{
					log__printf(NULL, MOSQ_LOG_NOTICE, "Warning: Invalid line in password file '%s': %s", file, buf);
					mosquitto_pw_cleanup(unpwd->pw);
					mosquitto_FREE(unpwd->username);
					mosquitto_FREE(unpwd);
				}
			}
		}
	}
	fclose(pwfile);
	mosquitto_FREE(buf);

	return MOSQ_ERR_SUCCESS;
}


void unpwd__free_item(struct mosquitto__unpwd **unpwd, struct mosquitto__unpwd *item)
{
	mosquitto_FREE(item->username);
	mosquitto_pw_cleanup(item->pw);
	HASH_DEL(*unpwd, item);
	mosquitto_FREE(item);
}


static int unpwd__file_parse(struct mosquitto__unpwd **unpwd, const char *password_file)
{
	int rc;
	if(!unpwd) return MOSQ_ERR_INVAL;

	if(!password_file) return MOSQ_ERR_SUCCESS;

	rc = pwfile__parse(password_file, unpwd);

	return rc;
}

static int mosquitto_basic_auth_default(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_basic_auth *ed = event_data;
	struct mosquitto__unpwd *u;
	struct mosquitto__unpwd *unpwd_ref;

	UNUSED(event);
	UNUSED(userdata);

	if(ed->client->username == NULL){
		return MOSQ_ERR_PLUGIN_IGNORE;
	}

	if(db.config->per_listener_settings){
		if(ed->client->bridge) return MOSQ_ERR_SUCCESS;
		if(!ed->client->listener) return MOSQ_ERR_INVAL;
		unpwd_ref = ed->client->listener->security_options->unpwd;
	}else{
		unpwd_ref = db.config->security_options.unpwd;
	}

	HASH_FIND(hh, unpwd_ref, ed->client->username, strlen(ed->client->username), u);
	if(u){
		if(u->pw){
			if(ed->client->password){
				return mosquitto_pw_verify(u->pw, ed->client->password);
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
	struct mosquitto__unpwd *u, *tmp = NULL;

	UNUSED(reload);

	if(!root) return MOSQ_ERR_INVAL;

	HASH_ITER(hh, *root, u, tmp){
		HASH_DEL(*root, u);
		mosquitto_pw_cleanup(u->pw);
		mosquitto_FREE(u->username);
		mosquitto_FREE(u);
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
	struct mosquitto *context, *ctxt_tmp = NULL;
	struct mosquitto__acl_user *acl_user_tail;
	bool allow_anonymous;
	struct mosquitto__security_options *security_opts = NULL;
#ifdef WITH_TLS
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
	for(int i=0; i<db.config->listener_count; i++){
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
		if(context->bridge){
			continue;
		}

		/* Check for anonymous clients when allow_anonymous is false */
		if(db.config->per_listener_settings){
			if(context->listener){
				allow_anonymous = context->listener->security_options->allow_anonymous;
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
				mosquitto_FREE(context->username);
				mosquitto_FREE(context->password);

				X509 *client_cert = SSL_get_peer_certificate(context->ssl);
				if(!client_cert){
					security__disconnect_auth(context);
					continue;
				}
				name = X509_get_subject_name(client_cert);
				if(!name){
					X509_free(client_cert);
					security__disconnect_auth(context);
					continue;
				}
				if (context->listener->use_identity_as_username) { /* use_identity_as_username */
					int i = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
					if(i == -1){
						X509_free(client_cert);
						security__disconnect_auth(context);
						continue;
					}
					name_entry = X509_NAME_get_entry(name, i);
					if(name_entry){
						name_asn1 = X509_NAME_ENTRY_get_data(name_entry);
						if (name_asn1 == NULL) {
							X509_free(client_cert);
							security__disconnect_auth(context);
							continue;
						}
						context->username = mosquitto_strdup((char *) ASN1_STRING_get0_data(name_asn1));
						if(!context->username){
							X509_free(client_cert);
							security__disconnect_auth(context);
							continue;
						}
						/* Make sure there isn't an embedded NUL character in the CN */
						if ((size_t)ASN1_STRING_length(name_asn1) != strlen(context->username)) {
							X509_free(client_cert);
							security__disconnect_auth(context);
							continue;
						}
					}
				} else { /* use_subject_as_username */
					subject_bio = BIO_new(BIO_s_mem());
					X509_NAME_print_ex(subject_bio, X509_get_subject_name(client_cert), 0, XN_FLAG_RFC2253);
					data_start = NULL;
					name_length = (size_t)BIO_get_mem_data(subject_bio, &data_start);
					subject = mosquitto_malloc(sizeof(char)*name_length+1);
					if(!subject){
						BIO_free(subject_bio);
						X509_free(client_cert);
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
					security__disconnect_auth(context);
					continue;
				}
				X509_free(client_cert);
			}
		}else
#endif
		{
			/* Username/password check only if the identity/subject check not used */
			if(mosquitto_basic_auth(context) != MOSQ_ERR_SUCCESS){
				mosquitto__set_state(context, mosq_cs_disconnecting);
				do_disconnect(context, MOSQ_ERR_AUTH);
				continue;
			}
		}


		/* Check for ACLs and apply to user. */
		if(db.config->per_listener_settings){
			if(context->listener){
				security_opts = context->listener->security_options;
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
