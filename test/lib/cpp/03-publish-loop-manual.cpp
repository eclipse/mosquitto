#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <mosquittopp.h>

static int run = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect_v5(int rc, int flags, const mosquitto_property *properties);
		void on_disconnect_v5(int rc, const mosquitto_property *properties);
		void on_subscribe_v5(int mid, int qos_count, const int *granted_qos, const mosquitto_property *props);
		void on_message_v5(const struct mosquitto_message *msg, const mosquitto_property *properties);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}

void mosquittopp_test::on_connect_v5(int rc, int flags, const mosquitto_property *properties)
{
	(void)flags;
	(void)properties;

	if(rc){
		exit(1);
	}else{
		subscribe_v5(NULL, "loop/test", 0, 0, NULL);
	}
}

void mosquittopp_test::on_disconnect_v5(int rc, const mosquitto_property *properties)
{
	(void)properties;

	run = rc;
}

void mosquittopp_test::on_subscribe_v5(int mid, int qos_count, const int *granted_qos, const mosquitto_property *props)
{
	(void)mid;
	(void)qos_count;
	(void)granted_qos;
	(void)props;

	publish_v5(NULL, "loop/test", strlen("message"), "message", 0, false, NULL);
}

void mosquittopp_test::on_message_v5(const struct mosquitto_message *msg, const mosquitto_property *properties)
{
	(void)msg;
	(void)properties;
	mosqpp::validate_utf8(msg->topic, (int)strlen(msg->topic));
	disconnect();
}

void do_loop(mosquittopp_test *mosq)
{
	int sock;
	struct timeval tv;
	fd_set readfds, writefds;

	sock = mosq->socket();
	if(sock < 0) exit(1);

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);

	FD_SET(sock, &readfds);

	while(run == -1){
		tv.tv_sec = 0;
		tv.tv_usec = 100000;

		FD_SET(sock, &readfds);
		if(mosq->want_write()){
			FD_SET(sock, &writefds);
		}else{
			FD_CLR(sock, &writefds);
		}

		int fdcount = select(sock+1, &readfds, &writefds, NULL, &tv);
		if(fdcount < 0) exit(1);

		if(FD_ISSET(sock, &readfds)){
			mosq->loop_read();
		}
		if(FD_ISSET(sock, &writefds)){
			mosq->loop_write();
		}
		mosq->loop_misc();
	}
}

int main(int argc, char *argv[])
{
	mosquittopp_test *mosq;

	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("loop-test");
	mosq->int_option(MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

	mosq->connect_v5("localhost", port, 60, NULL, NULL);

	do_loop(mosq);

	delete mosq;
	mosqpp::lib_cleanup();

	return 1;
}

