#include <cassert>
#include <cstring>
#include <mosquitto/libmosquittopp.h>

static int run = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect(int rc);
		void on_disconnect(int rc);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}

void mosquittopp_test::on_connect(int rc)
{
	if(rc){
		exit(1);
	}else{
		disconnect();
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

	mosq = new mosquittopp_test("01-will-set");
	mosq->will_set("topic/on/unexpected/disconnect", strlen("will message"), "will message", 1, true);

	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop();
	}

	delete mosq;
	mosqpp::lib_cleanup();

	return run;
}
