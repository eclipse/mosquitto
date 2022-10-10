#include <cstring>

#include <mosquittopp.h>

static int run = -1;

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
		publish(NULL, "retain/qos0/test", strlen("retained message"), "retained message", 0, true);
	}
}

void mosquittopp_test::on_publish(int mid)
{
	run = 0;
}

int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;

	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("retain-qos0-test");

	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop();
	}
	delete mosq;

	delete mosq;
	mosqpp::lib_cleanup();

	return run;
}
