#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <mosquitto.h>

static int run = -1;

static void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	int rc2;
	mosquitto_property *proplist = NULL;
	(void)obj;

	if(rc){
		exit(1);
	}else{
		rc2 = mosquitto_property_add_string_pair(&proplist, MQTT_PROP_USER_PROPERTY, "key", "value");
		if(rc2 != MOSQ_ERR_SUCCESS){
			abort();
		}
		mosquitto_unsubscribe_v5(mosq, NULL, "unsubscribe/test", proplist);
	}
}

static void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)mosq;
	(void)obj;

	run = rc;
}

static void on_unsubscribe(struct mosquitto *mosq, void *obj, int mid, const mosquitto_property *props)
{
	(void)obj;
	(void)mid;
	(void)props;

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
	mosquitto_unsubscribe_v5_callback_set(mosq, on_unsubscribe);

	rc = mosquitto_connect(mosq, "localhost", port, 60);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	while(run == -1){
		mosquitto_loop(mosq, -1, 1);
	}
	mosquitto_destroy(mosq);

	mosquitto_lib_cleanup();
	return run;
}
