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
		mosquitto_publish_bufs(mosq, &sent_mid, "pub/qos0/no-payload/test", NULL, 0, 0, false);
		//Caution, this throws error: mosquitto_publish_bufs(mosq, &sent_mid, "pub/qos0/no-payload/test", NULL, 1, 0, false);
        /* Note: This also publishes a packet with no-payload
        const struct buf dummy[] = {
            {NULL, 0},
            {NULL, 0}
        };
		mosquitto_publish_bufs(mosq, &sent_mid, "pub/qos0/no-payload/test", dummy, 2, 0, false);
        */
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

	mosq = mosquitto_new("publish_bufs-qos0-test-np", true, NULL);
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_publish_callback_set(mosq, on_publish);

	rc = mosquitto_connect(mosq, "localhost", port, 60);

	while(run == -1){
		mosquitto_loop(mosq, -1, 1);
	}

	mosquitto_lib_cleanup();
	return run;
}
