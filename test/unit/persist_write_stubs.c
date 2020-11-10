#include <time.h>

#define WITH_BROKER

#include <logging_mosq.h>
#include <memory_mosq.h>
#include <mosquitto_broker_internal.h>
#include <net_mosq.h>
#include <send_mosq.h>
#include <time_mosq.h>

extern uint64_t last_retained;
extern char *last_sub;
extern int last_qos;

struct mosquitto *context__init(mosq_sock_t sock)
{
	return mosquitto__calloc(1, sizeof(struct mosquitto));
}

int log__printf(struct mosquitto *mosq, unsigned int priority, const char *fmt, ...)
{
	return 0;
}

time_t mosquitto_time(void)
{
	return 123;
}

int net__socket_close(struct mosquitto *mosq)
{
	return MOSQ_ERR_SUCCESS;
}

int send__pingreq(struct mosquitto *mosq)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_acl_check(struct mosquitto *context, const char *topic, uint32_t payloadlen, void* payload, uint8_t qos, bool retain, int access)
{
	return MOSQ_ERR_SUCCESS;
}

int acl__find_acls(struct mosquitto *context)
{
	return MOSQ_ERR_SUCCESS;
}


int send__publish(struct mosquitto *mosq, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, uint8_t qos, bool retain, bool dup, const mosquitto_property *cmsg_props, const mosquitto_property *store_props, uint32_t expiry_interval)
{
	return MOSQ_ERR_SUCCESS;
}

int send__pubcomp(struct mosquitto *mosq, uint16_t mid, const mosquitto_property *properties)
{
	return MOSQ_ERR_SUCCESS;
}

int send__pubrec(struct mosquitto *mosq, uint16_t mid, uint8_t reason_code, const mosquitto_property *properties)
{
	return MOSQ_ERR_SUCCESS;
}

int send__pubrel(struct mosquitto *mosq, uint16_t mid, const mosquitto_property *properties)
{
	return MOSQ_ERR_SUCCESS;
}
