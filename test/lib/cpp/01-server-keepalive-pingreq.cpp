#include <cassert>
#include <mosquitto/libmosquittopp.h>

static int run = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect(int rc);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}

void mosquittopp_test::on_connect(int rc)
{
	if(rc){
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	mosquittopp_test *mosq;

	assert(argc == 2);
	int port = atoi(argv[1]);
	int rc;

	mosqpp::lib_init();

	mosq = new mosquittopp_test("01-server-keepalive-pingreq");
	mosq->int_option(MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

	mosq->connect("localhost", port, 60);

	while(run == -1){
		rc = mosq->loop();
		if(rc) break;
	}

	delete mosq;
	mosqpp::lib_cleanup();

	return run;
}
