#include "config.h"
#include "mosquitto.h"
#include "mosquitto_internal.h"

#include <time.h>

time_t mosquitto_time(void)
{
	return 123;
}

int net__socket_close(struct mosquitto *mosq)
{
	UNUSED(mosq);

	return MOSQ_ERR_SUCCESS;
}

int net__socketpair(mosq_sock_t *pairR, mosq_sock_t *pairW)
{
	UNUSED(pairR);
	UNUSED(pairW);
	return MOSQ_ERR_ERRNO;
}

int net__init(void)
{
	return MOSQ_ERR_SUCCESS;
}

bool net__is_connected(struct mosquitto *mosq)
{
	UNUSED(mosq);
	return false;
}

void net__cleanup(void) {}

void message__cleanup(struct mosquitto_message_all **message)
{
	UNUSED(message);
}

void message__cleanup_all(struct mosquitto *mosq)
{
	UNUSED(mosq);
}

void packet__cleanup(struct mosquitto__packet *packet)
{
	UNUSED(packet);
}

void packet__cleanup_all(struct mosquitto *mosq)
{
	UNUSED(mosq);
}

void packet__cleanup_all_no_locks(struct mosquitto *mosq)
{
	UNUSED(mosq);
}

int will__clear(struct mosquitto *mosq)
{
	UNUSED(mosq);
	return MOSQ_ERR_SUCCESS;
}

void mosquitto_property_free_all(mosquitto_property **property)
{
	UNUSED(property);
}
