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
	(void)access;
	(void)client;
	(void)msg;

	return MOSQ_ERR_PLUGIN_DEFER;
}

int mosquitto_auth_unpwd_check(void *user_data, struct mosquitto *client, const char *username, const char *password)
{
	const char *tmp;

	(void)user_data;
	(void)username;
	(void)password;

	tmp = mosquitto_client_address(client);
	if(!tmp || strcmp(tmp, "127.0.0.1")){
		return MOSQ_ERR_AUTH;
	}

	if(!mosquitto_client_clean_session(client)){
		fprintf(stderr, "mosquitto_auth_unpwd_check clean_session error: %d\n", mosquitto_client_clean_session(client));
		return MOSQ_ERR_AUTH;
	}

	tmp = mosquitto_client_id(client);
	if(!tmp || strcmp(tmp, "client-params-test")){
		fprintf(stderr, "mosquitto_auth_unpwd_check client_id error: %s\n", tmp);
		return MOSQ_ERR_AUTH;
	}

	if(mosquitto_client_keepalive(client) != 42){
		fprintf(stderr, "mosquitto_auth_unpwd_check keepalive error: %d\n", mosquitto_client_keepalive(client));
		return MOSQ_ERR_AUTH;
	}

	if(!mosquitto_client_certificate(client)){
		// FIXME
		//return MOSQ_ERR_AUTH;
	}

	if(mosquitto_client_protocol(client) != mp_mqtt){
		fprintf(stderr, "mosquitto_auth_unpwd_check protocol error: %d\n", mosquitto_client_protocol(client));
		return MOSQ_ERR_AUTH;
	}

	if(mosquitto_client_sub_count(client)){
		fprintf(stderr, "mosquitto_auth_unpwd_check sub_count error: %d\n", mosquitto_client_sub_count(client));
		return MOSQ_ERR_AUTH;
	}

	tmp = mosquitto_client_username(client);
	if(!tmp || strcmp(tmp, "client-username")){
		fprintf(stderr, "mosquitto_auth_unpwd_check username error: %s\n", tmp);
		return MOSQ_ERR_AUTH;
	}

	return MOSQ_ERR_SUCCESS;
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

