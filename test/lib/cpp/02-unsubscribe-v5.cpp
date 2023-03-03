#include <cassert>
#include <mosquittopp.h>

static int run = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect(int rc);
		void on_disconnect(int rc);
		void on_unsubscribe_v5(int mid, const mosquitto_property *props);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}

void mosquittopp_test::on_connect(int rc)
{
	int rc2;
	mosquitto_property *proplist = NULL;

	if(rc){
		exit(1);
	}else{
		rc2 = mosquitto_property_add_string_pair(&proplist, MQTT_PROP_USER_PROPERTY, "key", "value");
		if(rc2 != MOSQ_ERR_SUCCESS){
			abort();
		}
		unsubscribe_v5(NULL, "unsubscribe/test", proplist);
	}
}

void mosquittopp_test::on_disconnect(int rc)
{
	run = rc;
}

void mosquittopp_test::on_unsubscribe_v5(int mid, const mosquitto_property *props)
{
	assert(mid == 1);
	assert(props == NULL);

	disconnect_v5(0, NULL);
}

int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;

	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("unsubscribe-test");
	mosq->int_option(MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop();
	}
	delete mosq;

	mosqpp::lib_cleanup();

	return run;
}
