#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <mosquittopp.h>

#define QOS 0

static int run = -1;
static int sent_mid = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect(int rc);
		void on_message_v5(const struct mosquitto_message *msg, const mosquitto_property *props);
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
		subscribe(NULL, "request/topic", QOS);
	}
}

void mosquittopp_test::on_publish(int mid)
{
	assert(mid == sent_mid);
	run = 0;
}

void mosquittopp_test::on_message_v5(const struct mosquitto_message *msg, const mosquitto_property *props)
{
	const mosquitto_property *p_resp, *p_corr = NULL;
	char *resp_topic = NULL;
	int rc;

	if(!strcmp(msg->topic, "request/topic")){
		p_resp = mosquitto_property_read_string(props, MQTT_PROP_RESPONSE_TOPIC, &resp_topic, false);
		if(p_resp){
			p_corr = mosquitto_property_read_binary(props, MQTT_PROP_CORRELATION_DATA, NULL, NULL, false);
			rc = publish_v5(&sent_mid, resp_topic, strlen("a response"), "a response", 0, false, p_corr);
			if(rc != MOSQ_ERR_SUCCESS){
				abort();
			}
			free(resp_topic);
		}
	}
}

int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;

	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("response-test");
	mosq->int_option(MOSQ_OPT_PROTOCOL_VERSION, 5);

	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop();
	}

	delete mosq;
	mosqpp::lib_cleanup();

	return 1;
}

