#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

int mosquitto_auth_acl_check_v5(int event, void *event_data, void *user_data);
int mosquitto_auth_unpwd_check_v5(int event, void *event_data, void *user_data);

static mosquitto_plugin_id_t *plg_id;

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	(void)user_data;
	(void)auth_opts;
	(void)auth_opt_count;

	plg_id = identifier;

	mosquitto_plugin_set_info(identifier, "test-plugin", NULL);

	mosquitto_callback_register(plg_id, MOSQ_EVT_ACL_CHECK, mosquitto_auth_acl_check_v5, NULL, NULL);
	mosquitto_callback_register(plg_id, MOSQ_EVT_BASIC_AUTH, mosquitto_auth_unpwd_check_v5, NULL, NULL);
	mosquitto_callback_register(plg_id, MOSQ_EVT_CONTROL, mosquitto_auth_unpwd_check_v5, "$CONTROL/test/v1", NULL);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	(void)user_data;
	(void)auth_opts;
	(void)auth_opt_count;

	mosquitto_callback_unregister(plg_id, MOSQ_EVT_ACL_CHECK, mosquitto_auth_acl_check_v5, NULL);
	mosquitto_callback_unregister(plg_id, MOSQ_EVT_BASIC_AUTH, mosquitto_auth_unpwd_check_v5, NULL);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check_v5(int event, void *event_data, void *user_data)
{
	(void)event;
	(void)event_data;
	(void)user_data;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_unpwd_check_v5(int event, void *event_data, void *user_data)
{
	(void)event;
	(void)event_data;
	(void)user_data;

	return MOSQ_ERR_SUCCESS;
}
