#include <cassert>
#include <errno.h>
#include <mosquittopp.h>
#include "path_helper.h"

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
	(void)rc;
	exit(1);
}

int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;
	int rc;

	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("08-ssl-fake-cacert");

	char cafile[4096];
	cat_sourcedir_with_relpath(cafile, "/../../ssl/test-fake-root-ca.crt");
	char capath[4096];
	cat_sourcedir_with_relpath(capath, "/../../ssl/certs");
	char certfile[4096];
	cat_sourcedir_with_relpath(certfile, "/../../ssl/client.crt");
	char keyfile[4096];
	cat_sourcedir_with_relpath(keyfile, "/../../ssl/client.key");

	mosq->tls_set(cafile, NULL, certfile, keyfile);
	mosq->connect("localhost", port, 60);

	rc = mosq->loop_forever();
	delete mosq;
	mosqpp::lib_cleanup();
	if(rc == MOSQ_ERR_ERRNO && errno == EPROTO){
		return 0;
	}else{
		return 1;
	}
}
