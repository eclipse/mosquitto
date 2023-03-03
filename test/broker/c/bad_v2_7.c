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
