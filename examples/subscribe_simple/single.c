#include <stdlib.h>
#include <stdio.h>
#include "mosquitto.h"

int main(int argc, char *argv[])
{
	int rc;
	struct mosquitto_message *msg;

	mosquitto_lib_init();

	rc = mosquitto_subscribe_simple(
			&msg, 1, true,
			"irc/#", 0,
			"test.mosquitto.org", 1883,
			NULL, 60, true,
			NULL, NULL,
			NULL, NULL);

	if(rc){
		printf("Error: %s\n", mosquitto_strerror(rc));
		mosquitto_lib_cleanup();
		return rc;
	}

	printf("%s %s\n", msg->topic, (char *)msg->payload);
	mosquitto_message_free(&msg);

	mosquitto_lib_cleanup();

	return 0;
}

