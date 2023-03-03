#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

static mosquitto_plugin_id_t *plg_id;

int callback_unsubscribe(int event, void *event_data, void *user_data)
{
	struct mosquitto_evt_unsubscribe *ed = event_data;

	(void)user_data;

	if(event != MOSQ_EVT_UNSUBSCRIBE){
		abort();
	}
	ed->data.topic_filter = mosquitto_strdup("missing-topic");

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
	(void)user_data;
	(void)opts;
	(void)opt_count;

	plg_id = identifier;

	mosquitto_callback_register(plg_id, MOSQ_EVT_UNSUBSCRIBE, callback_unsubscribe, NULL, NULL);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
	(void)user_data;
	(void)opts;
	(void)opt_count;

	mosquitto_callback_unregister(plg_id, MOSQ_EVT_UNSUBSCRIBE, callback_unsubscribe, NULL);

	return MOSQ_ERR_SUCCESS;
}
