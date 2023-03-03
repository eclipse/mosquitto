#include <cstring>
#include <cassert>
#include <mosquittopp.h>

static int run = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect(int rc);
		void on_disconnect(int rc);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}

void mosquittopp_test::on_connect(int rc)
{
	if(rc){
		exit(1);
	}else{
		disconnect();
	}
}

void mosquittopp_test::on_disconnect(int rc)
{
	run = rc;
}

int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;
	mosquitto_property *proplist = NULL;
	int rc;

	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("01-con-discon-will");
	mosq->int_option(MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

	rc = mosquitto_property_add_byte(&proplist, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 1);
	if(rc != MOSQ_ERR_SUCCESS){
		abort();
	}
	/* Set twice, so it has to clear the old settings */
	mosq->will_set_v5("will/topic", strlen("will-payload"), "will-payload", 1, true, proplist);
	proplist = NULL;
	rc = mosquitto_property_add_byte(&proplist, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 1);
	if(rc != MOSQ_ERR_SUCCESS){
		abort();
	}
	mosq->will_set_v5("will/topic", strlen("will-payload"), "will-payload", 1, true, proplist);

	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop();
	}
	delete mosq;

	mosqpp::lib_cleanup();

	return run;
}
