#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>

static int run = -1;

void on_connect(struct mosquitto *mosq, void *obj, int rc, int flags, const mosquitto_property *properties)
{
	int i;

	if(rc){
		exit(1);
	}

	for(i=0; i<6; i++){
		mosquitto_publish_v5(mosq, NULL, "topic", 5, "12345", 1, false, NULL);
	}
}

void on_publish(struct mosquitto *mosq, void *obj, int mid, int reason_code, const mosquitto_property *properties)
{
	if(mid == 6){
		mosquitto_disconnect(mosq);
		run = 0;
	}
}

int main(int argc, char *argv[])
{
	int rc;
	struct mosquitto *mosq;
	mosquitto_property *props = NULL;

	int port = atoi(argv[1]);

	mosquitto_lib_init();

	mosq = mosquitto_new("publish-qos1-test", true, &run);
	mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

	mosquitto_connect_v5_callback_set(mosq, on_connect);
	mosquitto_publish_v5_callback_set(mosq, on_publish);

	rc = mosquitto_connect_bind_v5(mosq, "localhost", port, 60, NULL, NULL);

	while(run == -1){
		mosquitto_loop(mosq, 300, 1);
	}

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	return run;
}
