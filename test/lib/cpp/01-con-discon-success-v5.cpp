#include <cassert>
#include <mosquittopp.h>

static int run = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect_v5(int rc, int flags, const mosquitto_property *props);
		void on_disconnect_v5(int rc, const mosquitto_property *props);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}

void mosquittopp_test::on_connect_v5(int rc, int flags, const mosquitto_property *props)
{
	assert(flags == 0);
	assert(props);
	assert(mosqpp::property_check_all(CMD_CONNACK, props) == MOSQ_ERR_SUCCESS);

	if(rc){
		exit(1);
	}else{
		disconnect();
	}
}

void mosquittopp_test::on_disconnect_v5(int rc, const mosquitto_property *props)
{
	assert(props == NULL);
	run = rc;
}


int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;
	mosquitto_property *props = NULL;
	int rc;

	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("01-con-discon-success-v5");
	mosq->int_option(MOSQ_OPT_PROTOCOL_VERSION, 5);

	mosquitto_property_add_int32(&props, MQTT_PROP_MAXIMUM_PACKET_SIZE, 1000);
	rc = mosq->connect_v5("localhost", port, 60, NULL, props);
	mosquitto_property_free_all(&props);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	while(run == -1){
		mosq->loop();
	}
	delete mosq;

	mosqpp::lib_cleanup();

	return run;
}
