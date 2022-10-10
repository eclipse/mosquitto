/*
 * This is an *example* plugin which prints information of a message after it is
 * received by the broker and before it is sent on to other clients. 
 *
 * Compile with:
 *   gcc -I<path to mosquitto-repo/include> -fPIC -shared printf_example.c -o printf_example.so
 *
 * Use in config with:
 *
 *   plugin /path/to/printf_example.so
 *
 * Note that this only works on Mosquitto 2.0 or later.
 */
#include <stdio.h>
#include <string.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

#define PLUGIN_NAME "client-properties"
#define PLUGIN_VERSION "1.0"

#define UNUSED(A) (void)(A)

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

static mosquitto_plugin_id_t *mosq_pid = NULL;

static int callback_message(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_message *ed = event_data;

	UNUSED(event);
	UNUSED(userdata);

	printf("printf-example - client address: %s\n", mosquitto_client_address(ed->client));
	printf("printf-example - client id: %s\n", mosquitto_client_id(ed->client));
	printf("printf-example - client username: %s\n", mosquitto_client_username(ed->client));
	printf("printf-example - payload: '%.*s'\n", ed->payloadlen, (char *)ed->payload);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	mosq_pid = identifier;
	mosquitto_plugin_set_info(identifier, PLUGIN_NAME, PLUGIN_VERSION);
	return mosquitto_callback_register(mosq_pid, MOSQ_EVT_MESSAGE, callback_message, NULL, NULL);
}
