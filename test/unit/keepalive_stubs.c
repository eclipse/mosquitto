#include <time.h>

#define WITH_BROKER

#include <logging_mosq.h>
#include <memory_mosq.h>
#include <mosquitto_broker_internal.h>
#include <net_mosq.h>
#include <send_mosq.h>
#include <time_mosq.h>

int log__printf(struct mosquitto *mosq, unsigned int priority, const char *fmt, ...)
{
	UNUSED(mosq);
	UNUSED(priority);
	UNUSED(fmt);

	return 0;
}

bool net__is_connected(struct mosquitto *mosq)
{
	UNUSED(mosq);
	return true;
}

void loop__update_next_event(time_t new_ms)
{
	UNUSED(new_ms);
}
