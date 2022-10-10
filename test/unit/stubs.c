#include "config.h"

#include <time.h>
#include <sys/types.h>
#include "callbacks.h"
#include "logging_mosq.h"
#include "net_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "time_mosq.h"

struct mosquitto_db{

};

struct mosquitto_base_msg{

};

int log__printf(struct mosquitto *mosq, unsigned int priority, const char *fmt, ...)
{
	UNUSED(mosq);
	UNUSED(priority);
	UNUSED(fmt);

	return 0;
}

time_t mosquitto_time(void)
{
	return 123;
}

bool net__is_connected(struct mosquitto *mosq)
{
	UNUSED(mosq);
	return false;
}

int net__socket_close(struct mosquitto *mosq)
{
	UNUSED(mosq);

	return MOSQ_ERR_SUCCESS;
}

int send__pingreq(struct mosquitto *mosq)
{
	UNUSED(mosq);

	return MOSQ_ERR_SUCCESS;
}

void callback__on_disconnect(struct mosquitto *mosq, int rc, const mosquitto_property *props)
{
	UNUSED(mosq);
	UNUSED(rc);
	UNUSED(props);
}

void callback__on_publish(struct mosquitto *mosq, int mid, int reason_code, const mosquitto_property *properties)
{
	UNUSED(mosq);
	UNUSED(mid);
	UNUSED(reason_code);
	UNUSED(properties);
}

void do_client_disconnect(struct mosquitto *mosq, int reason_code, const mosquitto_property *properties)
{
	UNUSED(mosq);
	UNUSED(reason_code);
	UNUSED(properties);
}

int handle__packet(struct mosquitto *context)
{
	UNUSED(context);
	return MOSQ_ERR_SUCCESS;
}

ssize_t net__read(struct mosquitto *mosq, void *buf, size_t count)
{
	UNUSED(mosq);
	UNUSED(buf);
	UNUSED(count);
	return 1;
}

ssize_t net__write(struct mosquitto *mosq, const void *buf, size_t count)
{
	UNUSED(mosq);
	UNUSED(buf);
	UNUSED(count);
	return 1;
}

void plugin_persist__handle_retain_set(struct mosquitto_base_msg *msg)
{
	UNUSED(msg);
}

void plugin_persist__handle_retain_remove(struct mosquitto_base_msg *msg)
{
	UNUSED(msg);
}

void plugin_persist__process_retain_events(bool force)
{
	UNUSED(force);
}

void plugin_persist__queue_retain_event(struct mosquitto_base_msg *msg, int event)
{
	UNUSED(msg);
	UNUSED(event);
}
