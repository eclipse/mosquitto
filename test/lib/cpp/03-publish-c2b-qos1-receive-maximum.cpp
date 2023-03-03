#include <cassert>
#include <cstdlib>
#include <cstring>

#include <mosquittopp.h>

static int run = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect(int rc);
		void on_publish_v5(int mid, int reason_code, const mosquitto_property *properties);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}

void mosquittopp_test::on_connect(int rc)
{
	if(rc){
		exit(1);
	}
	for(int i=0; i<6; i++){
		publish_v5(NULL, "topic", 5, "12345", 1, false, NULL);
	}
}

void mosquittopp_test::on_publish_v5(int mid, int reason_code, const mosquitto_property *properties)
{
	assert(reason_code == 0);
	assert(properties == NULL);
	if(mid == 6){
		disconnect();
		run = 0;
	}
}

int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;

	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("publish-qos1-test");
	mosq->int_option(MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

	mosq->connect_v5("localhost", port, 60, NULL, NULL);

	while(run == -1){
		mosq->loop(300, 1);
	}

	delete mosq;
	mosqpp::lib_cleanup();

	return run;
}

