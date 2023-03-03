#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>

static int run = -1;

static void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)obj;

	if(rc){
		exit(1);
	}else{
		rc = mosquitto_publish(mosq, NULL, "maximum/qos/qos2", strlen("message"), "message", 2, false);
		if(rc != MOSQ_ERR_QOS_NOT_SUPPORTED) run = 1;
		rc = mosquitto_publish(mosq, NULL, "maximum/qos/qos1", strlen("message"), "message", 1, false);
		if(rc != MOSQ_ERR_QOS_NOT_SUPPORTED) run = 1;
		rc = mosquitto_publish(mosq, NULL, "maximum/qos/qos0", strlen("message"), "message", 0, false);
		if(rc != MOSQ_ERR_SUCCESS) run = 1;
	}
}

static void on_publish(struct mosquitto *mosq, void *obj, int mid)
{
	(void)obj;

	if(mid == 1){
		mosquitto_disconnect(mosq);
	}
}

static void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)mosq;
	(void)obj;
	(void)rc;

	run = 0;
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

	mosq = mosquitto_new("publish-qos2-test", true, NULL);
	if(mosq == NULL){
		return 1;
	}
	mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_disconnect_callback_set(mosq, on_disconnect);
	mosquitto_publish_callback_set(mosq, on_publish);

	rc = mosquitto_connect(mosq, "localhost", port, 60);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	while(run == -1){
		mosquitto_loop(mosq, 50, 1);
	}

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	return run;
}
