#include <cstdlib>
#include <mosquittopp.h>

#define QOS 2

int main(int argc, char *argv[])
{
	int port;
	struct mosquitto_message *messages;

	if(argc < 2){
		return 1;
	}
	port = atoi(argv[1]);

	mosqpp::lib_init();

	mosqpp::subscribe_simple(&messages, 1,
			true, "qos2/test", QOS, "localhost", port,
			"subscribe-qos2-test", 60, true, NULL, NULL, NULL, NULL);

	/* FIXME - this should be in the wrapper */
	mosquitto_message_free(&messages);

	mosqpp::lib_cleanup();
	return 0;
}
