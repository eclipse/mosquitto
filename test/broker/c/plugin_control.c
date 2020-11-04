#include <stdio.h>
#include <string.h>
#include <mqtt_protocol.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

static mosquitto_plugin_id_t *plg_id = NULL;

int control_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_control *ed = event_data;

	mosquitto_broker_publish_copy(NULL, ed->topic, ed->payloadlen, ed->payload, 0, 0, NULL);

	return 0;
}


int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)
{
	return MOSQ_PLUGIN_VERSION;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	int i;
	char buf[100];

	plg_id = identifier;

	for(i=0; i<100; i++){
		snprintf(buf, sizeof(buf), "$CONTROL/user-management/v%d", i);
		mosquitto_callback_register(plg_id, MOSQ_EVT_CONTROL, control_callback, "$CONTROL/user-management/v1", NULL);
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	int i;
	char buf[100];

	for(i=0; i<100; i++){
		snprintf(buf, sizeof(buf), "$CONTROL/user-management/v%d", i);
		mosquitto_callback_unregister(plg_id, MOSQ_EVT_CONTROL, control_callback, "$CONTROL/user-management/v1");
	}
	return MOSQ_ERR_SUCCESS;
}
