#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mosquitto.h>

#define QOS 2

int cb(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *msg)
{
	assert(msg);
	assert(!strcmp(msg->topic, "qos2/test"));
	return 1;
}

int main(int argc, char *argv[])
{
	int port;

	if(argc < 2){
		return 1;
	}
	port = atoi(argv[1]);

	mosquitto_lib_init();

	mosquitto_subscribe_callback(
			cb, NULL, "qos2/test", QOS, "localhost", port,
			"subscribe-qos2-test", 60, true, NULL, NULL, NULL, NULL);

	mosquitto_lib_cleanup();
	return 0;
}
