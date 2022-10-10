#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>
#include <mqtt_protocol.h>

#define QOS 0

static int run = -1;

static void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)obj;

	if(rc){
		exit(1);
	}else{
		mosquitto_subscribe(mosq, NULL, "response/topic", QOS);
	}
}

static void on_subscribe(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
	mosquitto_property *props = NULL;
	int rc;

	(void)obj;
	(void)mid;

	if(qos_count != 1 || granted_qos[0] != QOS){
		abort();
	}

	mosquitto_property_add_string(&props, MQTT_PROP_RESPONSE_TOPIC, "response/topic");
	mosquitto_property_add_binary(&props, MQTT_PROP_CORRELATION_DATA, "corridor", 8);
	rc = mosquitto_publish_v5(mosq, NULL, "request/topic", 6, "action", QOS, 0, props);
	if(rc != MOSQ_ERR_SUCCESS){
		abort();
	}
	mosquitto_property_free_all(&props);
}

static void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg)
{
	(void)mosq;
	(void)obj;

	if(!strcmp(msg->payload, "a response")){
		run = 0;
	}else{
		run = 1;
	}
}

int main(int argc, char *argv[])
{
	int rc;
	struct mosquitto *mosq;
	int ver = PROTOCOL_VERSION_v5;
	int port;

	if(argc < 2){
		return 1;
	}
	port = atoi(argv[1]);

	mosquitto_lib_init();

	mosq = mosquitto_new("request-test", true, NULL);
	if(mosq == NULL){
		return 1;
	}
	mosquitto_opts_set(mosq, MOSQ_OPT_PROTOCOL_VERSION, &ver);
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_subscribe_callback_set(mosq, on_subscribe);
	mosquitto_message_callback_set(mosq, on_message);

	rc = mosquitto_connect(mosq, "localhost", port, 60);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	while(run == -1){
		rc = mosquitto_loop(mosq, -1, 1);
	}
	mosquitto_destroy(mosq);

	mosquitto_lib_cleanup();
	return run;
}
