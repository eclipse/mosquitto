#include <cstring>

#include <mosquittopp.h>

static int run = -1;
static int sent_mid = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect(int rc);
		void on_publish(int mid);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}

void mosquittopp_test::on_connect(int rc)
{
	if(rc){
		exit(1);
	}else{
        const struct buf buffers[] = {
            {"message1", (uint32_t) strlen("message1")},
            {"msg2", (uint32_t) strlen("msg2")},
            {"last_message", (uint32_t) strlen("last_message")},
        };
		publish_bufs(&sent_mid, "pub/qos0/test", buffers, 3, 0, false);
	}
}

void mosquittopp_test::on_publish(int mid)
{
	if(sent_mid == mid){
		disconnect();
	}else{
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;

	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("publish_bufs-qos0-test");

	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop();
	}

	delete mosq;
	mosqpp::lib_cleanup();

	return run;
}
