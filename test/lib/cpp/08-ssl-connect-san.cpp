#include <cassert>
#include "path_helper.h"
#include <mosquittopp.h>
#include "path_helper.h"

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
	struct mosquittopp_test *mosq;
	int rc;
	char cafile[4096];
	assert(argc == 3);
	int port = atoi(argv[1]);
	char *host = argv[2];

	mosqpp::lib_init();

	mosq = new mosquittopp_test("08-ssl-connect-san");

    cat_sourcedir_with_relpath(cafile, "/../../ssl/test-root-ca.crt");
	mosq->tls_set(cafile);
	rc = mosq->connect(host, port, 60);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	while(run == -1){
		mosq->loop();
	}
	delete mosq;

	mosqpp::lib_cleanup();

	return run;
}
