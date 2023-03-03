#include <cassert>
#include <cstdio>
#include <cstring>
#include <mosquittopp.h>

static int run = -1;
static int sent_mid = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect(int rc);
		void on_publish(int rc);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}

void mosquittopp_test::on_connect(int rc)
{
	if(rc){
		exit(1);
	}else{
		mosquitto_property *proplist = NULL;
		int rc2 = mosquitto_property_add_byte(&proplist, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 1);
		if(rc2 != MOSQ_ERR_SUCCESS){
			abort();
		}
		publish_v5(&sent_mid, "prop/qos0", strlen("message"), "message", 0, false, proplist);
		mosquitto_property_free_all(&proplist);
	}

}

void mosquittopp_test::on_publish(int mid)
{
	if(mid == sent_mid){
		disconnect();
		run = 0;
	}else{
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;

	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("prop-test");
	mosq->int_option(MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop();
	}
	delete mosq;

	mosqpp::lib_cleanup();

	return run;
}
