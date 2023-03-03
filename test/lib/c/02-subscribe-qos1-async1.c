#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <mosquitto.h>

/* mosquitto_connect_async() test, with mosquitto_loop_start() called before mosquitto_connect_async(). */

#define QOS 1

static int run = -1;
static bool should_run = true;

static void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)obj;

	if(rc){
		exit(1);
	}else{
		mosquitto_subscribe(mosq, NULL, "qos1/test", QOS);
	}
}

static void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)mosq;
	(void)obj;

	run = rc;
}

static void on_subscribe(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
	(void)mosq;
	(void)obj;
	(void)mid;

	if(qos_count != 1 || granted_qos[0] != QOS){
		abort();
	}
	should_run = false;
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

	mosq = mosquitto_new("subscribe-qos1-test", true, NULL);
	if(mosq == NULL){
		return 1;
	}
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_disconnect_callback_set(mosq, on_disconnect);
	mosquitto_subscribe_callback_set(mosq, on_subscribe);

	rc = mosquitto_loop_start(mosq);
	if(rc){
		printf("loop_start failed: %s\n", mosquitto_strerror(rc));
		return rc;
	}

	rc = mosquitto_connect_async(mosq, "localhost", port, 60);
	if(rc){
		printf("connect_async failed: %s\n", mosquitto_strerror(rc));
		return rc;
	}

	/* 50 millis to be system polite */
	struct timespec tv = { 0, 50e6 };
	while(should_run){
		nanosleep(&tv, NULL);
	}

	mosquitto_disconnect(mosq);
	mosquitto_loop_stop(mosq, false);
	mosquitto_destroy(mosq);

	mosquitto_lib_cleanup();
	return run;
}
