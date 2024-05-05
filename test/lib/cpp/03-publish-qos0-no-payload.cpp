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
		publish(&sent_mid, "pub/qos0/no-payload/test", 0, NULL, 0, false);
	}
}

void mosquittopp_test::on_publish(int mid)
{
	if(sent_mid == mid){
		disconnect();
	}else{
		exit(1);
	}
}

void mosquittopp_test::on_disconnect(int rc)
{
	run = rc;
}

int main(int argc, char *argv[])
{
	mosquittopp_test *mosq;

	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("publish-qos0-test-np");

	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop();
	}

	delete mosq;
	mosqpp::lib_cleanup();

	return run;
}
