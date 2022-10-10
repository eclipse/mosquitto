#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>

static int run = -1;
static int sent_mid;

static void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)obj;

	if(rc){
		exit(1);
	}else{
		mosquitto_publish(mosq, &sent_mid, "psk/test", strlen("message"), "message", 0, false);
	}
}

static void on_publish(struct mosquitto *mosq, void *obj, int mid)
{
	(void)obj;

	if(mid == sent_mid){
		mosquitto_disconnect(mosq);
		run = 0;
	}else{
		exit(1);
	}
}

static void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)mosq;
	(void)obj;

	run = rc;
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

	mosq = mosquitto_new("08-tls-psk-pub", true, NULL);
	mosquitto_tls_opts_set(mosq, 1, "tlsv1", NULL);
	rc = mosquitto_tls_psk_set(mosq, "deadbeef", "psk-id", NULL);
	if(rc){
		mosquitto_destroy(mosq);
		return rc;
	}
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_disconnect_callback_set(mosq, on_disconnect);
	mosquitto_publish_callback_set(mosq, on_publish);

	rc = mosquitto_connect(mosq, "localhost", port, 60);
	if(rc){
		mosquitto_destroy(mosq);
		return rc;
	}

	while(run == -1){
		mosquitto_loop(mosq, -1, 1);
	}

	mosquitto_destroy(mosq);

	mosquitto_lib_cleanup();
	return run;
}
