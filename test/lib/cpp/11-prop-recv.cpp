#include <cassert>
#include <cstdio>
#include <cstring>
#include <mosquittopp.h>

static int run = -1;
static int qos = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect(int rc);
		void on_message_v5(const struct mosquitto_message *msg, const mosquitto_property *properties);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}

void mosquittopp_test::on_connect(int rc)
{
	if(rc){
		exit(1);
	}
}

void mosquittopp_test::on_message_v5(const struct mosquitto_message *msg, const mosquitto_property *properties)
{
	int rc;
	char *str;

	if(properties){
		if(mosquitto_property_read_string(properties, MQTT_PROP_CONTENT_TYPE, &str, false)){
			rc = strcmp(str, "plain/text");
			free(str);

			if(rc == 0){
				if(mosquitto_property_read_string(properties, MQTT_PROP_RESPONSE_TOPIC, &str, false)){
					rc = strcmp(str, "msg/123");
					free(str);

					if(rc == 0){
						if(msg->qos == qos){
							publish(NULL, "ok", 2, "ok", 0, 0);
							return;
						}
					}
				}
			}
		}
	}

	/* No matching message, so quit with an error */
	exit(1);
}

int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;
	int rc;

	assert(argc == 3);
	int port = atoi(argv[1]);
	qos = atoi(argv[2]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("prop-test");
	mosq->int_option(MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

	mosq->connect("localhost", port, 60);

	while(run == -1){
		rc = mosq->loop();
		if(rc != MOSQ_ERR_SUCCESS) return rc;
	}
	delete mosq;

	mosqpp::lib_cleanup();

	return run;
}
