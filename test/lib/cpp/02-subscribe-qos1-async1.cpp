#include <cassert>
#include <cstdio>
#include <cstring>
#ifdef WIN32
#  include <windows.h>
#endif

#include <mosquitto/libmosquittopp.h>

/* mosquitto_connect_async() test, with mosquitto_loop_start() called before mosquitto_connect_async(). */

#define QOS 1

static int run = -1;
static bool should_run = true;

class mosquittopp_test : public mosqpp::mosquittopp
{
public:
	mosquittopp_test(const char *id);

	void on_connect(int rc);
	void on_disconnect(int rc);
	void on_subscribe(int mid, int qos_count, const int *granted_qos);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}


void mosquittopp_test::on_connect(int rc)
{
	if(rc){
		exit(1);
	}else{
		subscribe(NULL, "qos1/test", QOS);
	}
}


void mosquittopp_test::on_disconnect(int rc)
{
	run = rc;
}


void mosquittopp_test::on_subscribe(int mid, int qos_count, const int *granted_qos)
{
	assert(mid == 1);
	assert(qos_count == 1);
	assert(granted_qos[0] == QOS);
	should_run = false;
}


int main(int argc, char *argv[])
{
	mosquittopp_test *mosq;
	int rc;

	if(argc != 2){
		return 1;
	}
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("subscribe-qos1-test");

	rc = mosq->loop_start();
	if(rc){
		printf("loop_start failed: %s\n", mosquitto_strerror(rc));
		return rc;
	}

	rc = mosq->connect_async("localhost", port, 60);
	if(rc){
		printf("connect_async failed: %s\n", mosquitto_strerror(rc));
		return rc;
	}

	/* 50 millis to be system polite */
	while(should_run){
#ifdef WIN32
		Sleep(50);
#else
		struct timespec tv = { 0, 50000000 };
		nanosleep(&tv, NULL);
#endif
	}

	mosq->disconnect();
	mosq->loop_stop();
	delete mosq;
	mosqpp::lib_cleanup();

	return run;
}
