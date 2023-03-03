#include <string.h>
#include <stdbool.h>
#include "mosquitto_plugin_v2.h"

/*
 * Following constant come from mosquitto.h
 *
 * They are copied here to fix value of those constant at the time of MOSQ_AUTH_PLUGIN_VERSION == 2
 */
enum mosq_err_t {
	MOSQ_ERR_SUCCESS = 0,
	MOSQ_ERR_AUTH = 11,
	MOSQ_ERR_ACL_DENIED = 12
};

int mosquitto_auth_plugin_version(void)
{
	return 2;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
	(void)user_data;
	(void)auth_opts;
	(void)auth_opt_count;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
	(void)user_data;
	(void)auth_opts;
	(void)auth_opt_count;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
	(void)user_data;
	(void)auth_opts;
	(void)auth_opt_count;
	(void)reload;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
	(void)user_data;
	(void)auth_opts;
	(void)auth_opt_count;
	(void)reload;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void *user_data, const char *clientid, const char *username, const char *topic, int access)
{
	(void)user_data;
	(void)clientid;
	(void)topic;

	if(access != MOSQ_ACL_READ && access != MOSQ_ACL_WRITE){
		return MOSQ_ERR_ACL_DENIED;
	}else if(username && !strcmp(username, "readonly") && access == MOSQ_ACL_READ){
		return MOSQ_ERR_SUCCESS;
	}else if(username && !strcmp(username, "readwrite")){
		if((!strcmp(topic, "readonly") && access == MOSQ_ACL_READ)
				|| !strcmp(topic, "writeable")){

			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_ACL_DENIED;
		}

	}else{
		return MOSQ_ERR_ACL_DENIED;
	}
}

int mosquitto_auth_unpwd_check(void *user_data, const char *username, const char *password)
{
	(void)user_data;

	if(username && !strcmp(username, "test-username") && password && !strcmp(password, "cnwTICONIURW")){
		return MOSQ_ERR_SUCCESS;
	}else if(username && (!strcmp(username, "readonly") || !strcmp(username, "readwrite"))){
		return MOSQ_ERR_SUCCESS;
	}else if(username && !strcmp(username, "test-username@v2")){
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_AUTH;
	}
}

int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len)
{
	(void)user_data;
	(void)hint;
	(void)identity;
	(void)key;
	(void)max_key_len;

	return MOSQ_ERR_AUTH;
}

