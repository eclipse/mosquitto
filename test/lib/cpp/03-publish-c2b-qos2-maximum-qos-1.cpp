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
		void on_disconnect(int rc);
		void on_publish(int mid);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}

void mosquittopp_test::on_connect(int rc)
{
	if(rc){
		exit(1);
	}else{
		rc = publish(NULL, "maximum/qos/qos2", strlen("message"), "message", 2, false);
		if(rc != MOSQ_ERR_QOS_NOT_SUPPORTED) run = 1;
		rc = publish(NULL, "maximum/qos/qos1", strlen("message"), "message", 1, false);
		if(rc != MOSQ_ERR_SUCCESS) run = 1;
		rc = publish(NULL, "maximum/qos/qos0", strlen("message"), "message", 0, false);
		if(rc != MOSQ_ERR_SUCCESS) run = 1;
	}
}

void mosquittopp_test::on_disconnect(int rc)
{
	run = rc;
}

void mosquittopp_test::on_publish(int mid)
{
	if(mid == 2){
		disconnect();
	}
}

int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;

	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("publish-qos2-test");
	mosq->int_option(MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop(50, 1);
	}

	delete mosq;
	mosqpp::lib_cleanup();

	return run;
}

