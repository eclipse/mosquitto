#include <cstdio>
#include <cstdlib>
#include <cstring>

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

	if(argc != 2){
		return 1;
	}
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("publish-qos2-test");

	mosq->connect("localhost", port, 2);

	while(run == -1){
		int rc = mosq->loop(300, 1);
		if(rc){
			exit(0);
		}
	}
	delete mosq;
	mosqpp::lib_cleanup();

	return run;
}
