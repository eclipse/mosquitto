#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <mosquitto.h>

static int run = -1;

void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	if(rc){
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	int rc;
	struct mosquitto *mosq;

	int port = atoi(argv[1]);

	mosquitto_lib_init();

	mosq = mosquitto_new("01-keepalive-pingreq", true, NULL);
	if(mosq == NULL){
		return 1;
	}
	mosquitto_connect_callback_set(mosq, on_connect);

	rc = mosquitto_connect(mosq, "localhost", port, 5);
	if(rc != 0) return rc;

	while(run == -1){
		rc = mosquitto_loop(mosq, -1, 1);
		if(rc != 0) break;
	}

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	return run;
}
