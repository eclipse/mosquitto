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
static int acl__cleanup(void);
static int mosquitto_acl_check_default(int event, void *event_data, void *userdata);


int acl_file__init(void)
{
	int rc;

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

	return MOSQ_ERR_SUCCESS;
}

int acl_file__cleanup(void)
{
	int rc;

	rc = acl__cleanup();
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	if(db.config->per_listener_settings){
		for(int i=0; i<db.config->listener_count; i++){
			if(db.config->listeners[i].security_options->pid){
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


static int acl__cleanup(void)
{
	struct mosquitto *context, *ctxt_tmp = NULL;

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

/* Apply security settings after a reload.
 * Includes:
 * - Disconnecting anonymous users if appropriate
 * - Disconnecting users with invalid passwords
 * - Reapplying ACLs
 */
int acl_file__apply(void)
{
	struct mosquitto *context, *ctxt_tmp = NULL;
	struct mosquitto__acl_user *acl_user_tail;
	struct mosquitto__security_options *security_opts = NULL;

	HASH_ITER(hh_id, db.contexts_by_id, context, ctxt_tmp){
		if(context->bridge){
			continue;
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
