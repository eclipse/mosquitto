#include <stdlib.h>
#include <stdio.h>
#include "mosquitto.h"

int on_message(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *msg)
{
	printf("%s %s (%d)\n", msg->topic, (const char *)msg->payload, msg->payloadlen);
	return 0;
}


int main(int argc, char *argv[])
{
	int rc;

	mosquitto_lib_init();

	rc = mosquitto_subscribe_callback(
			on_message, NULL,
			"irc/#", 0,
			"test.mosquitto.org", 1883,
			NULL, 60, true,
			NULL, NULL,
			NULL, NULL);

	if(rc){
		printf("Error: %s\n", mosquitto_strerror(rc));
	}

	mosquitto_lib_cleanup();

	return rc;
}

