#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>
#include <mqtt_protocol.h>

static int run = -1;
static int sent_mid = -1;

void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	int rc2;
	mosquitto_property *proplist = NULL;

	if(rc){
		exit(1);
	}else{
		rc2 = mosquitto_property_add_string(&proplist, MQTT_PROP_CONTENT_TYPE, "application/json");
		mosquitto_publish_v5(mosq, &sent_mid, "prop/qos0", strlen("message"), "message", 0, false, proplist);
		mosquitto_property_free_all(&proplist);
	}
}

void on_publish(struct mosquitto *mosq, void *obj, int mid)
{
	if(mid == sent_mid){
		mosquitto_disconnect(mosq);
		run = 0;
	}else{
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	int rc;
	int tmp;
	struct mosquitto *mosq;

	int port = atoi(argv[1]);

	mosquitto_lib_init();

	mosq = mosquitto_new("prop-test", true, NULL);
	if(mosq == NULL){
		return 1;
	}
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_publish_callback_set(mosq, on_publish);
	tmp = MQTT_PROTOCOL_V5;
	mosquitto_opts_set(mosq, MOSQ_OPT_PROTOCOL_VERSION, &tmp);

	rc = mosquitto_connect(mosq, "localhost", port, 60);

	while(run == -1){
		rc = mosquitto_loop(mosq, -1, 1);
	}

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	return run;
}
