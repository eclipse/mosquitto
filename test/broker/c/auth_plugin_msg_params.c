#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

int mosquitto_auth_plugin_version(void)
{
	return 4;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	(void)user_data;
	(void)auth_opts;
	(void)auth_opt_count;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	(void)user_data;
	(void)auth_opts;
	(void)auth_opt_count;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count, bool reload)
{
	(void)user_data;
	(void)auth_opts;
	(void)auth_opt_count;
	(void)reload;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count, bool reload)
{
	(void)user_data;
	(void)auth_opts;
	(void)auth_opt_count;
	(void)reload;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void *user_data, int access, struct mosquitto *client, const struct mosquitto_acl_msg *msg)
{
	(void)user_data;
	(void)client;

	if(access == MOSQ_ACL_SUBSCRIBE){
		return MOSQ_ERR_SUCCESS;
	}

	if(!msg->topic || strcmp(msg->topic, "param/topic")){
		abort();
		return MOSQ_ERR_ACL_DENIED;
	}

	if(!msg->payload || strncmp(msg->payload, "payload contents", strlen("payload contents"))){
		abort();
		return MOSQ_ERR_ACL_DENIED;
	}

	if(msg->payloadlen != strlen("payload contents")){
		abort();
		return MOSQ_ERR_ACL_DENIED;
	}

	if(msg->qos != 1){
		abort();
		return MOSQ_ERR_ACL_DENIED;
	}

	if(!msg->retain){
		abort();
		return MOSQ_ERR_ACL_DENIED;
	}

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_unpwd_check(void *user_data, struct mosquitto *client, const char *username, const char *password)
{
	(void)user_data;
	(void)client;
	(void)username;
	(void)password;

	return MOSQ_ERR_PLUGIN_DEFER;
}

int mosquitto_auth_psk_key_get(void *user_data, struct mosquitto *client, const char *hint, const char *identity, char *key, int max_key_len)
{
	(void)user_data;
	(void)client;
	(void)hint;
	(void)identity;
	(void)key;
	(void)max_key_len;

	return MOSQ_ERR_AUTH;
}

