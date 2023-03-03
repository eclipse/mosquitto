#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <mosquitto.h>

#define QOS 2

int main(int argc, char *argv[])
{
	int port;
	struct mosquitto_message *messages;

	if(argc < 2){
		return 1;
	}
	port = atoi(argv[1]);

	mosquitto_lib_init();

	mosquitto_subscribe_simple(&messages, 1,
			true, "qos2/test", QOS, "localhost", port,
			"subscribe-qos2-test", 60, true, NULL, NULL, NULL, NULL);

	mosquitto_message_free(&messages);

	mosquitto_lib_cleanup();
	return 0;
}
