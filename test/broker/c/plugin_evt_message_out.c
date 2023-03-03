#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

static mosquitto_plugin_id_t *plg_id;

int callback_message_out(int event, void *event_data, void *user_data)
{
	struct mosquitto_evt_message *ed = event_data;

	(void)user_data;

	if(event != MOSQ_EVT_MESSAGE_OUT){
		abort();
	}
	if(!strcmp(ed->topic, "deny")){
		return MOSQ_ERR_ACL_DENIED;
	}
	ed->topic = mosquitto_strdup("new-topic");
	ed->payload = mosquitto_strdup("new-message");
	ed->payloadlen = strlen(ed->payload);
	ed->properties = NULL;
	if(mosquitto_property_add_string_pair(&ed->properties, MQTT_PROP_USER_PROPERTY, "key", "value")) abort();

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
	(void)user_data;
	(void)opts;
	(void)opt_count;

	plg_id = identifier;

	mosquitto_callback_register(plg_id, MOSQ_EVT_MESSAGE_OUT, callback_message_out, NULL, NULL);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
	(void)user_data;
	(void)opts;
	(void)opt_count;

	mosquitto_callback_unregister(plg_id, MOSQ_EVT_MESSAGE_OUT, callback_message_out, NULL);

	return MOSQ_ERR_SUCCESS;
}
