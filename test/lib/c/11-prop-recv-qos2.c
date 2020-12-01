#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>
#include <mqtt_protocol.h>

static int run = -1;
static int sent_mid = -1;

void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	int rc2;
	mosquitto_property *proplist = NULL;

	if(rc){
		exit(1);
	}
}


void on_message_v5(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg, const mosquitto_property *properties)
{
	int rc;
	char *str;

	if(properties){
		if(mosquitto_property_read_string(properties, MQTT_PROP_CONTENT_TYPE, &str, false)){
			rc = strcmp(str, "plain/text");
			free(str);

			if(rc == 0){
				if(mosquitto_property_read_string(properties, MQTT_PROP_RESPONSE_TOPIC, &str, false)){
					rc = strcmp(str, "msg/123");
					free(str);

					if(rc == 0){
						if(msg->qos == 2){
							mosquitto_publish(mosq, NULL, "ok", 2, "ok", 0, 0);
							return;
						}
					}
				}
			}
		}
	}

	/* No matching message, so quit with an error */
	exit(1);
}


void on_publish(struct mosquitto *mosq, void *obj, int mid)
{
	run = 0;
}

int main(int argc, char *argv[])
{
	int rc;
	int tmp;
	struct mosquitto *mosq;

	int port = atoi(argv[1]);

	mosquitto_lib_init();

	mosq = mosquitto_new("prop-test", true, NULL);
	if(mosq == NULL){
		return 1;
	}
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_message_v5_callback_set(mosq, on_message_v5);
	mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

	rc = mosquitto_connect(mosq, "localhost", port, 60);

	while(run == -1){
		rc = mosquitto_loop(mosq, -1, 1);
	}

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	return run;
}
