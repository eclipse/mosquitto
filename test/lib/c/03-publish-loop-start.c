#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <mosquitto.h>
#ifdef WIN32
#  include <windows.h>
#endif

static int run = -1;


static void on_connect_v5(struct mosquitto *mosq, void *obj, int rc, int flags, const mosquitto_property *properties)
{
	(void)obj;
	(void)flags;
	(void)properties;

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
	(void)obj;
	(void)mid;
	(void)qos_count;
	(void)granted_qos;
	(void)props;

	mosquitto_publish_v5(mosq, NULL, "loop/test", strlen("message"), "message", 0, false, NULL);
}


static void on_message_v5(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg, const mosquitto_property *properties)
{
	(void)obj;
	(void)msg;
	(void)properties;

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
	if(rc != MOSQ_ERR_SUCCESS){
		return rc;
	}

	mosquitto_loop_start(mosq);
	while(run == -1){
#ifdef WIN32
		Sleep(50);
#else
		struct timespec tv = { 0, 50000000 };
		nanosleep(&tv, NULL);
#endif
	}

	mosquitto_destroy(mosq);

	mosquitto_lib_cleanup();
	return 1;
}
