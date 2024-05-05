#include <cassert>
#include <mosquitto/libmosquittopp.h>

static int run = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect(int rc);
		void on_disconnect(int rc);
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
		subscribe(NULL, "qos0/test", 0);
	}
}

void mosquittopp_test::on_disconnect(int rc)
{
	run = rc;
}

void mosquittopp_test::on_subscribe(int mid, int qos_count, const int *granted_qos)
{
	assert(mid == 1);
	assert(qos_count == 1);
	assert(granted_qos[0] == 0);
	disconnect();
}

int main(int argc, char *argv[])
{
	mosquittopp_test *mosq;

	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("subscribe-qos0-test");

	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop();
	}

	delete mosq;
	mosqpp::lib_cleanup();

	return run;
}
