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


int mosquitto_auth_start(void *user_data, struct mosquitto *client, const char *method, bool reauth, const void *data, uint16_t data_len, void **data_out, uint16_t *data_out_len)
{
	int i;

	(void)user_data;
	(void)client;
	(void)reauth;

	if(!strcmp(method, "mirror")){
		if(data_len > 0){
			*data_out = malloc(data_len);
			if(!(*data_out)){
				return MOSQ_ERR_NOMEM;
			}
			for(i=0; i<data_len; i++){
				((uint8_t *)(*data_out))[i] = ((uint8_t *)data)[data_len-i-1];
			}
			*data_out_len = data_len;

			return MOSQ_ERR_AUTH_CONTINUE;
		}else{
			return MOSQ_ERR_INVAL;
		}
	}
	return MOSQ_ERR_NOT_SUPPORTED;
}


int mosquitto_auth_continue(void *user_data, struct mosquitto *client, const char *method, const void *data, uint16_t data_len, void **data_out, uint16_t *data_out_len)
{
	size_t len;

	(void)user_data;
	(void)client;
	(void)data_out;
	(void)data_out_len;

	if(!strcmp(method, "mirror")){
		if(data_len > 0){
			len = strlen("supercalifragilisticexpialidocious")>data_len?data_len:strlen("supercalifragilisticexpialidocious");
			if(!memcmp(data, "supercalifragilisticexpialidocious", len)){
				return MOSQ_ERR_SUCCESS;
			}else{
				return MOSQ_ERR_AUTH;
			}
		}else{
			return MOSQ_ERR_INVAL;
		}
	}
	return MOSQ_ERR_NOT_SUPPORTED;
}
