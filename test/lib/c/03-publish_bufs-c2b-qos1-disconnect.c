#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>

static int run = -1;
static int first_connection = 1;

void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	if(rc){
		exit(1);
	}else{
		if(first_connection == 1){
            const struct buf buffers[] = {
                {"message1", (uint32_t) strlen("message1")},
                {"msg2", (uint32_t) strlen("msg2")}
            };
			mosquitto_publish_bufs(mosq, NULL, "pub/qos1/test", buffers, 2, 1, false);
			first_connection = 0;
		}
	}
}

void on_publish(struct mosquitto *mosq, void *obj, int mid)
{
	mosquitto_disconnect(mosq);
}

void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
	if(rc){
		mosquitto_reconnect(mosq);
	}else{
		run = 0;
	}
}

int main(int argc, char *argv[])
{
	int rc;
	struct mosquitto *mosq;

	int port = atoi(argv[1]);

	mosquitto_lib_init();

	mosq = mosquitto_new("publish_bufs-qos1-test", true, NULL);
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_disconnect_callback_set(mosq, on_disconnect);
	mosquitto_publish_callback_set(mosq, on_publish);
	mosquitto_message_retry_set(mosq, 3);

	rc = mosquitto_connect(mosq, "localhost", port, 60);

	while(run == -1){
		mosquitto_loop(mosq, 300, 1);
	}

	mosquitto_lib_cleanup();
	return run;
}
