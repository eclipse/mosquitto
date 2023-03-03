#include <cassert>
#include <signal.h>
#include <mosquittopp.h>
#include <openssl/ssl.h>
#include "path_helper.h"

static int run = -1;

void handle_sigint(int signal)
{
	(void)signal;
	run = 0;
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
	struct mosquittopp_test *mosq;
	SSL_CTX *ssl_ctx;
	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
			| OPENSSL_INIT_ADD_ALL_DIGESTS \
			| OPENSSL_INIT_LOAD_CONFIG, NULL);
	ssl_ctx = SSL_CTX_new(TLS_client_method());

	mosq = new mosquittopp_test("08-ssl-connect-crt-auth");

	char cafile[4096];
	cat_sourcedir_with_relpath(cafile, "/../../ssl/test-root-ca.crt");
	char capath[4096];
	cat_sourcedir_with_relpath(capath, "/../../ssl/certs");
	char certfile[4096];
	cat_sourcedir_with_relpath(certfile, "/../../ssl/client.crt");
	char keyfile[4096];
	cat_sourcedir_with_relpath(keyfile, "/../../ssl/client.key");

	mosq->tls_set(cafile, NULL, certfile, keyfile);

	mosq->int_option(MOSQ_OPT_SSL_CTX_WITH_DEFAULTS, 1);
	mosq->void_option(MOSQ_OPT_SSL_CTX, ssl_ctx);

	mosq->connect("localhost", port, 60);

	signal(SIGINT, handle_sigint);
	while(run == -1){
		mosq->loop();
	}
	SSL_CTX_free(ssl_ctx);

	delete mosq;
	mosqpp::lib_cleanup();

	return run;
}
