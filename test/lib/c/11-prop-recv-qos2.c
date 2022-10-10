#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>
#include <mqtt_protocol.h>

static int run = -1;

static void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)mosq;
	(void)obj;

	if(rc){
		exit(1);
	}
}


static void on_message_v5(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg, const mosquitto_property *properties)
{
	int rc;
	char *str;

	(void)obj;

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

	mosq = mosquitto_new("prop-test", true, NULL);
	if(mosq == NULL){
		return 1;
	}
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_message_v5_callback_set(mosq, on_message_v5);
	mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

	rc = mosquitto_connect(mosq, "localhost", port, 60);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	while(run == -1){
		rc = mosquitto_loop(mosq, -1, 1);
		if(rc != MOSQ_ERR_SUCCESS) return rc;
	}

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	return run;
}
