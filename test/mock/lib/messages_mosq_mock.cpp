#include "libmosquitto_mock.hpp"


int mosquitto_message_copy(struct mosquitto_message *dst,
		const struct mosquitto_message *src)
{
	return LibMosquittoMock::get_mock().mosquitto_message_copy(dst, src);
}


void mosquitto_message_free(struct mosquitto_message **message)
{
	LibMosquittoMock::get_mock().mosquitto_message_free(message);
}


void mosquitto_message_free_contents(struct mosquitto_message *message)
{
	LibMosquittoMock::get_mock().mosquitto_message_free_contents(message);
}


void mosquitto_message_retry_set(struct mosquitto *mosq, unsigned int message_retry)
{
	LibMosquittoMock::get_mock().mosquitto_message_retry_set(mosq, message_retry);
}


int mosquitto_max_inflight_messages_set(struct mosquitto *mosq, unsigned int max_inflight_messages)
{
	return LibMosquittoMock::get_mock().mosquitto_max_inflight_messages_set(mosq, max_inflight_messages);
}
