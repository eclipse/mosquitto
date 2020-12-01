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
		rc = mosquitto_subscribe(mosq, NULL, "0123456789012345678901234567890", 0);
		if(rc != MOSQ_ERR_OVERSIZE_PACKET){
			printf("Fail on subscribe\n");
			exit(1);
		}

		rc = mosquitto_unsubscribe(mosq, NULL, "0123456789012345678901234567890");
		if(rc != MOSQ_ERR_OVERSIZE_PACKET){
			printf("Fail on unsubscribe\n");
			exit(1);
		}

		rc = mosquitto_publish(mosq, &sent_mid, "pub/test", strlen("0123456789012345678"), "0123456789012345678", 0, false);
		if(rc != MOSQ_ERR_OVERSIZE_PACKET){
			printf("Fail on publish 1\n");
			exit(1);
		}
		rc = mosquitto_publish(mosq, &sent_mid, "pub/test", strlen("012345678901234567"), "012345678901234567", 0, false);
		if(rc != MOSQ_ERR_SUCCESS){
			printf("Fail on publish 2\n");
			exit(1);
		}
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
	if(mosq == NULL){
		return 1;
	}
	mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);
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
