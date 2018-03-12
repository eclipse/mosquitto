#include <mosquittopp.h>

static int run = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}

int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;
	int rc = 0;

	mosqpp::lib_init();

	mosq = new mosquittopp_test("08-ssl-bad-cacert");

	mosq->tls_opts_set(1, "tlsv1", NULL);
	if(mosq->tls_set_uri("file://../ssl/test-root-ca.crt",
			     "../ssl/certs",
		     	     "file://../ssl/client.crt",
			     "pk:something",
			     NULL,
			     "../ssl/libpkcs11.so",
			     "../ssl/libsofthsm2.so") != MOSQ_ERR_INVAL){
		rc = 1;
		goto cleanup;
	}

	if(mosq->tls_set_uri("file://../ssl/test-root-ca.crt",
			     "../ssl/certs",
		     	     "file://../ssl/client.crt",
			     "pkcs11:something",
			     NULL,
			     NULL,
			     "../ssl/libsofthsm2.so") != MOSQ_ERR_INVAL){
		rc = 1;
		goto cleanup;
	}

	if(mosq->tls_set_uri("file://../ssl/test-root-ca.crt",
			     "../ssl/certs",
		     	     "file://../ssl/client.crt",
			     "pkcs11:something",
			     NULL,
			     "../ssl/libpkcs11.so",
			     NULL) != MOSQ_ERR_INVAL){
		rc = 1;
		goto cleanup;
	}
cleanup:	
	mosqpp::lib_cleanup();

	return rc;
}
