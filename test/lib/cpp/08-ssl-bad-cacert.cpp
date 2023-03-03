#include <cassert>
#include <mosquittopp.h>
#include "path_helper.h"

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
	int rc = 1;

	assert(argc == 2);
	(void)argv;

	mosqpp::lib_init();

	mosq = new mosquittopp_test("08-ssl-bad-cacert");

	if(mosq->tls_set("this/file/doesnt/exist") == MOSQ_ERR_INVAL){
		rc = 0;
	}
	delete mosq;
	mosqpp::lib_cleanup();

	return rc;
}
