#include <stdio.h>
#include <string.h>
#include <mqtt_protocol.h>
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
	static int count = 0;
	mosquitto_property *props = NULL;

	(void)user_data;
	(void)client;
	(void)msg;

	if(access == MOSQ_ACL_WRITE){
		if(count == 0){
			/* "missing-client" isn't connected, so we can check memory usage properly. */
			mosquitto_broker_publish_copy("missing-client", "topic/2", strlen("test-message-2"), "test-message-2", 2, true, NULL);
			mosquitto_broker_publish_copy("test-client", "topic/0", strlen("test-message-0"), "test-message-0", 0, true, NULL);
			mosquitto_broker_publish_copy("missing-client", "topic/2", strlen("test-message-2"), "test-message-2", 2, true, NULL);
			mosquitto_broker_publish_copy("test-client", "topic/1", strlen("test-message-1"), "test-message-1", 1, true, NULL);
			mosquitto_broker_publish_copy("missing-client", "topic/2", strlen("test-message-2"), "test-message-2", 2, true, NULL);
			mosquitto_broker_publish_copy("test-client", "topic/2", strlen("test-message-2"), "test-message-2", 2, true, NULL);
			count = 1;
		}else{
			mosquitto_property_add_byte(&props, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 1);
			mosquitto_broker_publish_copy("test-client", "topic/0", strlen("test-message-0"), "test-message-0", 0, true, props);
			props = NULL;
			mosquitto_property_add_byte(&props, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 1);
			mosquitto_broker_publish_copy("test-client", "topic/1", strlen("test-message-1"), "test-message-1", 1, true, props);
			props = NULL;
			mosquitto_property_add_byte(&props, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 1);
			mosquitto_broker_publish_copy("test-client", "topic/2", strlen("test-message-2"), "test-message-2", 2, true, props);
		}
	}

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_unpwd_check(void *user_data, struct mosquitto *client, const char *username, const char *password)
{
	(void)user_data;
	(void)client;
	(void)username;
	(void)password;

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

