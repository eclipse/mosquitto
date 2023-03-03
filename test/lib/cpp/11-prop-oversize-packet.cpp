#include <cassert>
#include <cstdio>
#include <cstring>
#include <mosquittopp.h>

static int run = -1;
static int sent_mid = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect(int rc);
		void on_publish(int rc);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}

void mosquittopp_test::on_connect(int rc)
{
	if(rc){
		exit(1);
	}else{
		rc = subscribe(NULL, "0123456789012345678901234567890", 0);
		if(rc != MOSQ_ERR_OVERSIZE_PACKET){
			printf("Fail on subscribe\n");
			exit(1);
		}

		rc = unsubscribe(NULL, "0123456789012345678901234567890");
		if(rc != MOSQ_ERR_OVERSIZE_PACKET){
			printf("Fail on unsubscribe\n");
			exit(1);
		}

		rc = publish(&sent_mid, "pub/test", strlen("0123456789012345678"), "0123456789012345678", 0, false);
		if(rc != MOSQ_ERR_OVERSIZE_PACKET){
			printf("Fail on publish 1\n");
			exit(1);
		}
		rc = publish(&sent_mid, "pub/test", strlen("012345678901234567"), "012345678901234567", 0, false);
		if(rc != MOSQ_ERR_SUCCESS){
			printf("Fail on publish 2\n");
			exit(1);
		}
	}

}

void mosquittopp_test::on_publish(int mid)
{
	if(mid == sent_mid){
		disconnect();
		run = 0;
	}else{
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;

	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("publish-qos0-test");
	mosq->int_option(MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop();
	}
	delete mosq;

	mosqpp::lib_cleanup();

	return run;
}
