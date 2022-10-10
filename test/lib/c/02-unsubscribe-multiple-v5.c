#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <mosquitto.h>

#define QOS 2

static int run = -1;

static void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)obj;

	if(rc){
		exit(1);
	}else{
		mosquitto_subscribe(mosq, NULL, "unsubscribe/test", QOS);
	}
}

static void on_subscribe(struct mosquitto *mosq, void *obj, int mid, int sub_count, const int *subs)
{
	char *const unsubs[] = {"unsubscribe/test", "no-sub"};

	(void)obj;
	(void)mid;

	if(sub_count != 1 || subs[0] != QOS){
		abort();
	}

	mosquitto_unsubscribe_multiple(mosq, NULL, 2, unsubs, NULL);
}

static void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)mosq;
	(void)obj;

	run = rc;
}

static void on_unsubscribe(struct mosquitto *mosq, void *obj, int mid)
{
	(void)obj;
	(void)mid;

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

	mosq = mosquitto_new("unsubscribe-test", true, NULL);
	if(mosq == NULL){
		return 1;
	}
	mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_disconnect_callback_set(mosq, on_disconnect);
	mosquitto_subscribe_callback_set(mosq, on_subscribe);
	mosquitto_unsubscribe_callback_set(mosq, on_unsubscribe);

	rc = mosquitto_connect(mosq, "localhost", port, 60);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	while(run == -1){
		mosquitto_loop(mosq, -1, 1);
	}
	mosquitto_destroy(mosq);

	mosquitto_lib_cleanup();
	return run;
}
