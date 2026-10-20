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
		/* Wildcard subscribe must be rejected client-side: CONNACK said = 0 */
		rc = mosquitto_subscribe(mosq, NULL, "wildcard/+/rejected", 0);
		if(rc != MOSQ_ERR_WILDCARD_SUBS_NOT_SUPPORTED){
			run = 1;
			return;
		}
		rc = mosquitto_subscribe(mosq, NULL, "wildcard/#", 0);
		if(rc != MOSQ_ERR_WILDCARD_SUBS_NOT_SUPPORTED){
			run = 1;
			return;
		}
		/* Plain topic must succeed */
		rc = mosquitto_subscribe(mosq, NULL, "plain/topic", 0);
		if(rc != MOSQ_ERR_SUCCESS){
			run = 1;
		}
	}
}


static void on_subscribe(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
	(void)obj;
	(void)mid;
	(void)qos_count;
	(void)granted_qos;

	mosquitto_disconnect(mosq);
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

	mosq = mosquitto_new("subscribe-wildcard-unavailable-test", true, NULL);
	if(mosq == NULL){
		return 1;
	}
	mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_subscribe_callback_set(mosq, on_subscribe);
	mosquitto_disconnect_callback_set(mosq, on_disconnect);

	rc = mosquitto_connect(mosq, "localhost", port, 60);
	if(rc != MOSQ_ERR_SUCCESS){
		return rc;
	}

	while(run == -1){
		mosquitto_loop(mosq, 50, 1);
	}

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	return run;
}
