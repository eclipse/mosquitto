#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>

static int run = -1;
static int sent_mid = -1;

void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	if(rc){
		exit(1);
	}else{
		mosquitto_publish(mosq, &sent_mid, "pub/qos0/test", strlen("message"), "message", 0, false);
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
	struct mosquitto *mosq;

	int port = atoi(argv[1]);

	mosquitto_lib_init();

	mosq = mosquitto_new("publish-qos0-test", true, NULL);
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_publish_callback_set(mosq, on_publish);

	rc = mosquitto_connect(mosq, "localhost", port, 60);

	while(run == -1){
		rc = mosquitto_loop(mosq, -1, 1);
	}

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	return run;
}
