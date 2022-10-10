/* Example plugin that prints out the client id and IP address of any clients
 * that publish to a particular topic, defined in "my_topic". */
#include "config.h"

#include <stdio.h>
#include <string.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

#define PLUGIN_NAME "print-ip-on-publish"
#define PLUGIN_VERSION "1.0"

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

static mosquitto_plugin_id_t *mosq_pid = NULL;

static char my_topic[] = "troublesome/topic";

static int message_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_message *ed = event_data;

	UNUSED(event);
	UNUSED(userdata);

	if(!strcmp(ed->topic, my_topic)){
		printf("PUBLISH FROM %s on IP %s\n", mosquitto_client_id(ed->client), mosquitto_client_address(ed->client));
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	mosq_pid = identifier;
	mosquitto_plugin_set_info(identifier, PLUGIN_NAME, PLUGIN_VERSION);
	return mosquitto_callback_register(mosq_pid, MOSQ_EVT_MESSAGE, message_callback, NULL, NULL);
}
