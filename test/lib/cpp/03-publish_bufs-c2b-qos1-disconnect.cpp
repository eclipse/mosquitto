#include <cstdlib>
#include <cstring>

#include <mosquittopp.h>

static int run = -1;
static int first_connection = 1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect(int rc);
		void on_disconnect(int rc);
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
		if(first_connection == 1){
            const struct buf buffers[] = {
                {"message1", (uint32_t) strlen("message1")},
                {"msg2", (uint32_t) strlen("msg2")}
            };
			publish_bufs(NULL, "pub/qos1/test", buffers, 2, 1, false);
			first_connection = 0;
		}
	}
}

void mosquittopp_test::on_disconnect(int rc)
{
	if(rc){
		reconnect();
	}else{
		run = 0;
	}
}

void mosquittopp_test::on_publish(int mid)
{
	disconnect();
}

int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;

	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("publish_bufs-qos1-test");
	mosq->message_retry_set(3);

	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop();
	}

	delete mosq;
	mosqpp::lib_cleanup();

	return run;
}

