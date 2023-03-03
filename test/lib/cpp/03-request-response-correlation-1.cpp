#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <mosquittopp.h>

#define QOS 0

static int run = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect(int rc);
		void on_message(const struct mosquitto_message *msg);
		void on_subscribe(int mid, int qos_count, const int *granted_qos);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}

void mosquittopp_test::on_connect(int rc)
{
	if(rc){
		exit(1);
	}else{
		subscribe(NULL, "response/topic", QOS);
	}
}

void mosquittopp_test::on_subscribe(int mid, int qos_count, const int *granted_qos)
{
	mosquitto_property *props = NULL;
	int rc;

	(void)mid;

	if(qos_count != 1 || granted_qos[0] != QOS){
		abort();
	}

	if(mosquitto_property_add_string(&props, MQTT_PROP_RESPONSE_TOPIC, "response/topic")
			|| mosquitto_property_add_binary(&props, MQTT_PROP_CORRELATION_DATA, "corridor", 8)){
		abort();
	}
	rc = publish_v5(NULL, "request/topic", 6, "action", QOS, 0, props);
	if(rc != MOSQ_ERR_SUCCESS){
		abort();
	}
	mosquitto_property_free_all(&props);
}

void mosquittopp_test::on_message(const struct mosquitto_message *msg)
{
	if(!strcmp((char *)msg->payload, "a response")){
		run = 0;
	}else{
		run = 1;
	}
}

int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;

	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("request-test");
	mosq->int_option(MOSQ_OPT_PROTOCOL_VERSION, 5);

	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop();
	}

	delete mosq;
	mosqpp::lib_cleanup();

	return 1;
}

