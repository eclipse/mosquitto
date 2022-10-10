#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mqtt_protocol.h>
#include <mosquitto.h>

static int run = -1;

static void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)obj;

	if(rc){
		exit(1);
	}else{
		mosquitto_disconnect(mosq);
	}
}

static void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)mosq;
	(void)obj;

	run = rc;
}

int main(int argc, char *argv[])
{
	int rc;
	struct mosquitto *mosq;
	int port;
	mosquitto_property *proplist = NULL;

	if(argc < 2){
		return 1;
	}
	port = atoi(argv[1]);

	mosquitto_lib_init();

	mosq = mosquitto_new("01-con-discon-will", true, NULL);
	if(mosq == NULL){
		return 1;
	}
	mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

	rc = mosquitto_property_add_byte(&proplist, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 1);
	if(rc != MOSQ_ERR_SUCCESS){
		abort();
	}
	/* Set twice, so it has to clear the old settings */
	mosquitto_will_set_v5(mosq, "will/topic", strlen("will-payload"), "will-payload", 1, true, proplist);
	proplist = NULL;
	rc = mosquitto_property_add_byte(&proplist, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 1);
	if(rc != MOSQ_ERR_SUCCESS){
		abort();
	}
	mosquitto_will_set_v5(mosq, "will/topic", strlen("will-payload"), "will-payload", 1, true, proplist);
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_disconnect_callback_set(mosq, on_disconnect);

	rc = mosquitto_connect(mosq, "localhost", port, 60);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	while(run == -1){
		mosquitto_loop(mosq, -1, 1);
	}

	mosquitto_destroy(mosq);

	mosquitto_lib_cleanup();
	return run;
}
