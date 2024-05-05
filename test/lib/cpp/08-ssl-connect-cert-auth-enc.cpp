#include <cassert>
#include <cstring>
#include <mosquitto/libmosquittopp.h>
#include "path_helper.h"

static int run = -1;

static int password_callback(char* buf, int size, int rwflag, void* userdata)
{
	(void)rwflag;
	(void)userdata;

	strncpy(buf, "password", (size_t )size);
	buf[size-1] = '\0';

	return (int)strlen(buf);
}

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

	mosq = new mosquittopp_test("08-ssl-connect-crt-auth-enc");

	char cafile[4096];
	cat_sourcedir_with_relpath(cafile, "/../../ssl/test-root-ca.crt");
	char capath[4096];
	cat_sourcedir_with_relpath(capath, "/../../ssl/certs");
	char certfile[4096];
	cat_sourcedir_with_relpath(certfile, "/../../ssl/client.crt");
	char keyfile[4096];
	cat_sourcedir_with_relpath(keyfile, "/../../ssl/client.key");

	mosq->tls_set(cafile, NULL, certfile, keyfile, password_callback);
	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop();
	}

	delete mosq;
	mosqpp::lib_cleanup();

	return run;
}
