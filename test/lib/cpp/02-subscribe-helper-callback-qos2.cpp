#include <cassert>
#include <cstdlib>
#include <cstring>
#include <mosquittopp.h>

#define QOS 2
static int mydata = 1;

int cb(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *msg)
{
	assert(mosq);
	assert(userdata == &mydata);
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

	mosqpp::lib_init();

	mosqpp::subscribe_callback(
			cb, &mydata, "qos2/test", QOS, "localhost", port,
			"subscribe-qos2-test", 60, true, NULL, NULL, NULL, NULL);

	mosqpp::lib_cleanup();
	return 0;
}
