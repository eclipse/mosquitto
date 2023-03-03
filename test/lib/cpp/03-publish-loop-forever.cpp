#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <mosquittopp.h>

static int run = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect_v5(int rc, int flags, const mosquitto_property *properties);
		void on_disconnect_v5(int rc, const mosquitto_property *properties);
		void on_subscribe_v5(int mid, int qos_count, const int *granted_qos, const mosquitto_property *props);
		void on_message_v5(const struct mosquitto_message *msg, const mosquitto_property *properties);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}

void mosquittopp_test::on_connect_v5(int rc, int flags, const mosquitto_property *properties)
{
	(void)flags;
	(void)properties;

	if(rc){
		exit(1);
	}else{
		subscribe_v5(NULL, "loop/test", 0, 0, NULL);
	}
}

void mosquittopp_test::on_disconnect_v5(int rc, const mosquitto_property *properties)
{
	(void)properties;

	run = rc;
}

void mosquittopp_test::on_subscribe_v5(int mid, int qos_count, const int *granted_qos, const mosquitto_property *props)
{
	(void)mid;
	(void)qos_count;
	(void)granted_qos;
	(void)props;

	publish_v5(NULL, "loop/test", strlen("message"), "message", 0, false, NULL);
}

void mosquittopp_test::on_message_v5(const struct mosquitto_message *msg, const mosquitto_property *properties)
{
	(void)msg;
	(void)properties;
	disconnect();
}

int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;

	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("loop-test");
	mosq->int_option(MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

	mosq->connect_v5("localhost", port, 60, NULL, NULL);

	mosq->loop_forever();

	delete mosq;
	mosqpp::lib_cleanup();

	return 1;
}

