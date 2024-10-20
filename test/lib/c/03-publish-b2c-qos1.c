#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>

volatile bool done = false;

static void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)mosq;
	(void)obj;

	if(rc){
		exit(1);
	}
}

static void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg)
{
	(void)mosq;
	(void)obj;

	if(msg->mid != 123){
		printf("Invalid mid (%d)\n", msg->mid);
		exit(1);
	}
	if(msg->qos != 1){
		printf("Invalid qos (%d)\n", msg->qos);
		exit(1);
	}
	if(strcmp(msg->topic, "pub/qos1/receive")){
		printf("Invalid topic (%s)\n", msg->topic);
		exit(1);
	}
	if(strcmp(msg->payload, "message")){
		printf("Invalid payload (%s)\n", (char *)msg->payload);
		exit(1);
	}
	if(msg->payloadlen != 7){
		printf("Invalid payloadlen (%d)\n", msg->payloadlen);
		exit(1);
	}
	if(msg->retain != false){
		printf("Invalid retain (%d)\n", msg->retain);
		exit(1);
	}

	done = true;
}

int main(int argc, char *argv[])
{
	int rc;
	struct mosquitto *mosq;
	int port;

	if(argc < 2){
		return 1;
	}
	port = atoi(argv[1]);

	mosquitto_lib_init();

	mosq = mosquitto_new("publish-qos1-test", true, NULL);
	if(mosq == NULL){
		return 1;
	}
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_message_callback_set(mosq, on_message);

	rc = mosquitto_connect(mosq, "localhost", port, 60);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	while(!done){
		mosquitto_loop(mosq, 300, 1);
	}
	mosquitto_destroy(mosq);

	mosquitto_lib_cleanup();

	return 0;
}
