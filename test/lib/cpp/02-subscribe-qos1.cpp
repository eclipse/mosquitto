#include <mosquittopp.h>

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
		subscribe(NULL, "qos1/test", 1);
	}
}

void mosquittopp_test::on_disconnect(int rc)
{
	run = rc;
}

void mosquittopp_test::on_subscribe(int mid, int qos_count, const int *granted_qos)
{
	disconnect();
}


int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;

	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("subscribe-qos1-test");

	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop();
	}

	delete mosq;
	mosqpp::lib_cleanup();

	return run;
}
