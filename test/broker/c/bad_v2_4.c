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
