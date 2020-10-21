#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <mosquitto.h>

static int run = -1;

void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	if(rc){
		exit(1);
	}else{
		mosquitto_unsubscribe(mosq, NULL, "unsubscribe/test");
	}
}

void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
	run = rc;
}

void on_unsubscribe(struct mosquitto *mosq, void *obj, int mid)
{
	mosquitto_disconnect(mosq);
}

int main(int argc, char *argv[])
{
	int rc;
	struct mosquitto *mosq;

	int port = atoi(argv[1]);

	mosquitto_lib_init();

	mosq = mosquitto_new("unsubscribe-test", true, NULL);
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_disconnect_callback_set(mosq, on_disconnect);
	mosquitto_unsubscribe_callback_set(mosq, on_unsubscribe);

	rc = mosquitto_connect(mosq, "localhost", port, 60);

	while(run == -1){
		mosquitto_loop(mosq, -1, 1);
	}

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	return run;
}
