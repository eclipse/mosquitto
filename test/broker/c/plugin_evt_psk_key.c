#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mqtt_protocol.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

static mosquitto_plugin_id_t *plg_id = NULL;

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

static int psk_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_psk_key *ed = event_data;

	(void)userdata;

	if(!strcmp(ed->hint, "myhint") && !strcmp(ed->identity, "subidentity")){
		snprintf(ed->key, ed->max_key_len, "159445");
	}else if(!strcmp(ed->hint, "myhint") && !strcmp(ed->identity, "pubidentity")){
		snprintf(ed->key, ed->max_key_len, "297A49");
	}else{
		return MOSQ_ERR_INVAL;
	}

	return 0;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	(void)user_data;
	(void)auth_opts;
	(void)auth_opt_count;

	plg_id = identifier;

	mosquitto_callback_register(plg_id, MOSQ_EVT_PSK_KEY, psk_callback, NULL, NULL);
	return MOSQ_ERR_SUCCESS;
}
