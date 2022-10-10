#include <cstring>
#include <mosquittopp.h>

static int run = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id, bool clean_session);

		void on_connect(int rc);
		void on_disconnect(int rc);
};

mosquittopp_test::mosquittopp_test(const char *id, bool clean_session) : mosqpp::mosquittopp(id, clean_session)
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
	struct mosquittopp_test *mosq;

	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("01-no-clean-session", false);

	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop();
	}
	delete mosq;

	delete mosq;
	mosqpp::lib_cleanup();

	return run;
}
