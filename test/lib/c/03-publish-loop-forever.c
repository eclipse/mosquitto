#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>

static int run = -1;

static void on_connect_v5(struct mosquitto *mosq, void *obj, int rc, int flags, const mosquitto_property *properties)
{
	(void)mosq;
	(void)obj;

	if(rc){
		exit(1);
	}else{
		mosquitto_subscribe_v5(mosq, NULL, "loop/test", 0, 0, NULL);
	}
}

static void on_disconnect_v5(struct mosquitto *mosq, void *obj, int rc, const mosquitto_property *properties)
{
	(void)mosq;
	(void)obj;
	(void)properties;

	run = rc;
}

static void on_subscribe_v5(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos, const mosquitto_property *props)
{
	mosquitto_publish_v5(mosq, NULL, "loop/test", strlen("message"), "message", 0, false, NULL);
}

static void on_message_v5(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg, const mosquitto_property *properties)
{
	(void)mosq;
	(void)obj;

	mosquitto_disconnect(mosq);
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

	mosq = mosquitto_new("loop-test", true, NULL);
	if(mosq == NULL){
		return 1;
	}
	mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

	mosquitto_connect_v5_callback_set(mosq, on_connect_v5);
	mosquitto_disconnect_v5_callback_set(mosq, on_disconnect_v5);
	mosquitto_subscribe_v5_callback_set(mosq, on_subscribe_v5);
	mosquitto_message_v5_callback_set(mosq, on_message_v5);

	rc = mosquitto_connect_bind_v5(mosq, "localhost", port, 60, NULL, NULL);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	mosquitto_loop_forever(mosq, -1, 1);
	mosquitto_destroy(mosq);

	mosquitto_lib_cleanup();
	return 1;
}
