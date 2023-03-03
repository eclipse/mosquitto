#include <cassert>
#include <cstring>

#include <mosquittopp.h>

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
		publish(&sent_mid, "pub/qos0/test", strlen("message"), "message", 0, false);
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

int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;
	int rc;

	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("publish-qos0-test");

	mosq->connect("localhost", port, 60);

	rc = mosq->loop_forever();

	delete mosq;
	mosqpp::lib_cleanup();

	return rc;
}
