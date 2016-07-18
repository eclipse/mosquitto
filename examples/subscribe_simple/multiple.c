#include <stdlib.h>
#include <stdio.h>
#include "mosquitto.h"

#define COUNT 3

int main(int argc, char *argv[])
{
	int rc;
	int i;
	struct mosquitto_message *msg;

	mosquitto_lib_init();

	rc = mosquitto_subscribe_simple(
			&msg, COUNT, true,
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

	for(i=0; i<COUNT; i++){
		printf("%s %s\n", msg[i].topic, (char *)msg[i].payload);
		mosquitto_message_free_contents(&msg[i]);
	}
	free(msg);

	mosquitto_lib_cleanup();

	return 0;
}

