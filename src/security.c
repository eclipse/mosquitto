/*
Copyright (c) 2011-2015 Roger Light <roger@atchoo.org>

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

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "memory_mosq.h"
#include "lib_load.h"

typedef int (*FUNC_auth_plugin_version)(void);
typedef int (*FUNC_auth_plugin_init)(void **, struct mosquitto_auth_opt *, int);
typedef int (*FUNC_auth_plugin_cleanup)(void *, struct mosquitto_auth_opt *, int);
typedef int (*FUNC_auth_plugin_security_init)(void *, struct mosquitto_auth_opt *, int, bool);
typedef int (*FUNC_auth_plugin_security_cleanup)(void *, struct mosquitto_auth_opt *, int, bool);
typedef int (*FUNC_auth_plugin_acl_check)(void *, const char *, const char *, const char *, int);
typedef int (*FUNC_auth_plugin_unpwd_check)(void *, const char *, const char *);
typedef int (*FUNC_auth_plugin_psk_key_get)(void *, const char *, const char *, char *, int);

void LIB_ERROR(void)
{
#ifdef WIN32
	char *buf;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING,
			NULL, GetLastError(), LANG_NEUTRAL, &buf, 0, NULL);
	log__printf(NULL, MOSQ_LOG_ERR, "Load error: %s", buf);
	LocalFree(buf);
#else
	log__printf(NULL, MOSQ_LOG_ERR, "Load error: %s", dlerror());
#endif
}

int mosquitto_security_module_init(struct mosquitto_db *db)
{
	void *lib;
	int (*plugin_version)(void) = NULL;
	int version;
	int rc;
	int i;

	if(db->config->auth_plugin_count == 0){
		db->auth_plugins = NULL;
		db->auth_plugin_count = 0;
	}else{
		db->auth_plugin_count = db->config->auth_plugin_count;
		db->auth_plugins = mosquitto__calloc(db->auth_plugin_count, sizeof(struct mosquitto__auth_plugin));
		if(!db->auth_plugins){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return 1;
		}
	}

	for(i=0; i<db->config->auth_plugin_count; i++){
		if(db->config->auth_plugins[i].path){
			lib = LIB_LOAD(db->config->auth_plugins[i].path);
			if(!lib){
				log__printf(NULL, MOSQ_LOG_ERR,
						"Error: Unable to load auth plugin \"%s\".", db->config->auth_plugins[i].path);
				LIB_ERROR();
				return 1;
			}

			db->auth_plugins[i].lib = NULL;
			if(!(plugin_version = (FUNC_auth_plugin_version)LIB_SYM(lib, "mosquitto_auth_plugin_version"))){
				log__printf(NULL, MOSQ_LOG_ERR,
						"Error: Unable to load auth plugin function mosquitto_auth_plugin_version().");
				LIB_ERROR();
				LIB_CLOSE(lib);
				return 1;
			}
			version = plugin_version();
			if(version != MOSQ_AUTH_PLUGIN_VERSION){
				log__printf(NULL, MOSQ_LOG_ERR,
						"Error: Incorrect auth plugin version (got %d, expected %d).",
						version, MOSQ_AUTH_PLUGIN_VERSION);
				LIB_ERROR();

				LIB_CLOSE(lib);
				return 1;
			}
			if(!(db->auth_plugins[i].plugin_init = (FUNC_auth_plugin_init)LIB_SYM(lib, "mosquitto_auth_plugin_init"))){
				log__printf(NULL, MOSQ_LOG_ERR,
						"Error: Unable to load auth plugin function mosquitto_auth_plugin_init().");
				LIB_ERROR();
				LIB_CLOSE(lib);
				return 1;
			}
			if(!(db->auth_plugins[i].plugin_cleanup = (FUNC_auth_plugin_cleanup)LIB_SYM(lib, "mosquitto_auth_plugin_cleanup"))){
				log__printf(NULL, MOSQ_LOG_ERR,
						"Error: Unable to load auth plugin function mosquitto_auth_plugin_cleanup().");
				LIB_ERROR();
				LIB_CLOSE(lib);
				return 1;
			}

			if(!(db->auth_plugins[i].security_init = (FUNC_auth_plugin_security_init)LIB_SYM(lib, "mosquitto_auth_security_init"))){
				log__printf(NULL, MOSQ_LOG_ERR,
						"Error: Unable to load auth plugin function mosquitto_auth_security_init().");
				LIB_ERROR();
				LIB_CLOSE(lib);
				return 1;
			}

			if(!(db->auth_plugins[i].security_cleanup = (FUNC_auth_plugin_security_cleanup)LIB_SYM(lib, "mosquitto_auth_security_cleanup"))){
				log__printf(NULL, MOSQ_LOG_ERR,
						"Error: Unable to load auth plugin function mosquitto_auth_security_cleanup().");
				LIB_ERROR();
				LIB_CLOSE(lib);
				return 1;
			}

			if(!(db->auth_plugins[i].acl_check = (FUNC_auth_plugin_acl_check)LIB_SYM(lib, "mosquitto_auth_acl_check"))){
				log__printf(NULL, MOSQ_LOG_ERR,
						"Error: Unable to load auth plugin function mosquitto_auth_acl_check().");
				LIB_ERROR();
				LIB_CLOSE(lib);
				return 1;
			}

			if(!(db->auth_plugins[i].unpwd_check = (FUNC_auth_plugin_unpwd_check)LIB_SYM(lib, "mosquitto_auth_unpwd_check"))){
				log__printf(NULL, MOSQ_LOG_ERR,
						"Error: Unable to load auth plugin function mosquitto_auth_unpwd_check().");
				LIB_ERROR();
				LIB_CLOSE(lib);
				return 1;
			}

			if(!(db->auth_plugins[i].psk_key_get = (FUNC_auth_plugin_psk_key_get)LIB_SYM(lib, "mosquitto_auth_psk_key_get"))){
				log__printf(NULL, MOSQ_LOG_ERR,
						"Error: Unable to load auth plugin function mosquitto_auth_psk_key_get().");
				LIB_ERROR();
				LIB_CLOSE(lib);
				return 1;
			}

			db->auth_plugins[i].lib = lib;
			db->auth_plugins[i].user_data = NULL;
			if(db->auth_plugins[i].plugin_init){
				rc = db->auth_plugins[i].plugin_init(&db->auth_plugins[i].user_data, db->config->auth_plugins[i].options, db->config->auth_plugins[i].option_count);
				if(rc){
					log__printf(NULL, MOSQ_LOG_ERR,
							"Error: Authentication plugin returned %d when initialising.", rc);
					return rc;
				}
			}
		}
	}

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_security_module_cleanup(struct mosquitto_db *db)
{
	int i;

	mosquitto_security_cleanup(db, false);

	for(i=0; i<db->config->auth_plugin_count; i++){
		if(db->auth_plugins[i].plugin_cleanup){
			db->auth_plugins[i].plugin_cleanup(db->auth_plugins[i].user_data, db->config->auth_plugins[i].options, db->config->auth_plugins[i].option_count);
		}

		if(db->auth_plugins[i].lib){
			LIB_CLOSE(db->auth_plugins[i].lib);
		}
		db->auth_plugins[i].lib = NULL;
		db->auth_plugins[i].plugin_init = NULL;
		db->auth_plugins[i].plugin_cleanup = NULL;
		db->auth_plugins[i].security_init = NULL;
		db->auth_plugins[i].security_cleanup = NULL;
		db->auth_plugins[i].acl_check = NULL;
		db->auth_plugins[i].unpwd_check = NULL;
		db->auth_plugins[i].psk_key_get = NULL;
	}
	mosquitto__free(db->auth_plugins);
	db->auth_plugins = NULL;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_security_init(struct mosquitto_db *db, bool reload)
{
	int i;
	int rc;

	for(i=0; i<db->config->auth_plugin_count; i++){
		rc = db->auth_plugins[i].security_init(db->auth_plugins[i].user_data, db->config->auth_plugins[i].options, db->config->auth_plugins[i].option_count, reload);
		if(rc != MOSQ_ERR_SUCCESS){
			return rc;
		}
	}
	return mosquitto_security_init_default(db, reload);
}

/* Apply security settings after a reload.
 * Includes:
 * - Disconnecting anonymous users if appropriate
 * - Disconnecting users with invalid passwords
 * - Reapplying ACLs
 */
int mosquitto_security_apply(struct mosquitto_db *db)
{
	return mosquitto_security_apply_default(db);
}

int mosquitto_security_cleanup(struct mosquitto_db *db, bool reload)
{
	int i;
	int rc;

	for(i=0; i<db->config->auth_plugin_count; i++){
		rc = db->auth_plugins[i].security_cleanup(db->auth_plugins[i].user_data, db->config->auth_plugins[i].options, db->config->auth_plugins[i].option_count, reload);
		if(rc != MOSQ_ERR_SUCCESS){
			return rc;
		}
	}
	return mosquitto_security_cleanup_default(db, reload);
}

int mosquitto_acl_check(struct mosquitto_db *db, struct mosquitto *context, const char *topic, int access)
{
	char *username;
	int rc;
	int i;

	if(!context->id){
		return MOSQ_ERR_ACL_DENIED;
	}

#ifdef WITH_BRIDGE
	if(context->bridge){
		username = context->bridge->local_username;
	}else
#endif
	{
		username = context->username;
	}

	rc = mosquitto_acl_check_default(db, context, topic, access);
	if(rc != MOSQ_ERR_PLUGIN_DEFER){
		return rc;
	}
	/* Default check has accepted or errored and then returned, or deferred.
	 * If no plugins exist we should accept at this point so set rc to success.
	 */
	rc = MOSQ_ERR_SUCCESS;
	for(i=0; i<db->auth_plugin_count; i++){
		rc = db->auth_plugins[i].acl_check(db->auth_plugins[i].user_data, context->id, username, topic, access);
		if(rc != MOSQ_ERR_PLUGIN_DEFER){
			return rc;
		}
	}
	/* If all plugins deferred, this is a denial. If rc == MOSQ_ERR_SUCCESS
	 * here, then no plugins were configured. */
	if(rc == MOSQ_ERR_PLUGIN_DEFER){
		rc = MOSQ_ERR_ACL_DENIED;
	}
	return rc;
}

int mosquitto_unpwd_check(struct mosquitto_db *db, const char *username, const char *password)
{
	int rc;
	int i;

	rc = mosquitto_unpwd_check_default(db, username, password);
	if(rc != MOSQ_ERR_PLUGIN_DEFER){
		return rc;
	}
	/* Default check has accepted or errored and then returned, or deferred.
	 * If no plugins exist we should accept at this point so set rc to success.
	 */
	rc = MOSQ_ERR_SUCCESS;
	for(i=0; i<db->auth_plugin_count; i++){
		rc = db->auth_plugins[i].unpwd_check(db->auth_plugins[i].user_data, username, password);
		if(rc != MOSQ_ERR_PLUGIN_DEFER){
			return rc;
		}
	}
	/* If all plugins deferred, this is a denial. If rc == MOSQ_ERR_SUCCESS
	 * here, then no plugins were configured. */
	if(rc == MOSQ_ERR_PLUGIN_DEFER){
		rc = MOSQ_ERR_AUTH;
	}
	return rc;
}

int mosquitto_psk_key_get(struct mosquitto_db *db, const char *hint, const char *identity, char *key, int max_key_len)
{
	int rc;
	int i;

	for(i=0; i<db->auth_plugin_count; i++){
		rc = db->auth_plugins[i].psk_key_get(db->auth_plugins[i].user_data, hint, identity, key, max_key_len);
		if(rc != MOSQ_ERR_PLUGIN_DEFER){
			return rc;
		}
	}
	return mosquitto_psk_key_get_default(db, hint, identity, key, max_key_len);
}

