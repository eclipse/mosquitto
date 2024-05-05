#include <cassert>
#include <cstring>

#include <mosquitto/libmosquittopp.h>

static int run = -1;
static int sent_mid = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect(int rc);
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
		publish(&sent_mid, "retain/qos0/test", strlen("retained message"), "retained message", 0, true);
	}
}

void mosquittopp_test::on_publish(int mid)
{
	assert(mid == sent_mid);
	run = 0;
}

int main(int argc, char *argv[])
{
	mosquittopp_test *mosq;

	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("retain-qos0-test");

	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop();
	}

	delete mosq;
	mosqpp::lib_cleanup();

	return run;
}
