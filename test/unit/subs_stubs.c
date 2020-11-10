#include <time.h>

#define WITH_BROKER

#include <logging_mosq.h>
#include <memory_mosq.h>
#include <mosquitto_broker_internal.h>
#include <net_mosq.h>
#include <send_mosq.h>
#include <time_mosq.h>

#if 0
extern uint64_t last_retained;
extern char *last_sub;
extern int last_qos;

struct mosquitto *context__init(mosq_sock_t sock)
{
	return mosquitto__calloc(1, sizeof(struct mosquitto));
}


int db__message_insert(struct mosquitto *context, uint16_t mid, enum mosquitto_msg_direction dir, uint8_t qos, bool retain, struct mosquitto_msg_store *stored, mosquitto_property *properties)
{
	return MOSQ_ERR_SUCCESS;
}

void db__msg_store_ref_dec(struct mosquitto_msg_store **store)
{
}

void db__msg_store_ref_inc(struct mosquitto_msg_store *store)
{
	store->ref_count++;
}
#endif

int log__printf(struct mosquitto *mosq, unsigned int priority, const char *fmt, ...)
{
	return 0;
}

time_t mosquitto_time(void)
{
	return 123;
}

#if 0
int net__socket_close(struct mosquitto *mosq)
{
	return MOSQ_ERR_SUCCESS;
}

int send__pingreq(struct mosquitto *mosq)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_acl_check(struct mosquitto *context, const char *topic, uint32_tn payloadlen, void* payload, uint8_t qos, bool retain, int access)
{
	return MOSQ_ERR_SUCCESS;
}

int acl__find_acls(struct mosquitto *context)
{
	return MOSQ_ERR_SUCCESS;
}
#endif


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

int mosquitto_acl_check(struct mosquitto *context, const char *topic, uint32_t payloadlen, void* payload, uint8_t qos, bool retain, int access)
{
	return MOSQ_ERR_SUCCESS;
}

uint16_t mosquitto__mid_generate(struct mosquitto *mosq)
{
	static uint16_t mid = 1;

	return ++mid;
}

int mosquitto_property_add_varint(mosquitto_property **proplist, int identifier, uint32_t value)
{
	return MOSQ_ERR_SUCCESS;
}

int persist__backup(bool shutdown)
{
	return MOSQ_ERR_SUCCESS;
}

int persist__restore(void)
{
	return MOSQ_ERR_SUCCESS;
}

void mosquitto_property_free_all(mosquitto_property **properties)
{
}

int retain__init(void)
{
	return MOSQ_ERR_SUCCESS;
}

void retain__clean(struct mosquitto__retainhier **retainhier)
{
}

int retain__queue(struct mosquitto *context, const char *sub, uint8_t sub_qos, uint32_t subscription_identifier)
{
	return MOSQ_ERR_SUCCESS;
}

int retain__store(const char *topic, struct mosquitto_msg_store *stored, char **split_topics)
{
	return MOSQ_ERR_SUCCESS;
}


void util__decrement_receive_quota(struct mosquitto *mosq)
{
	if(mosq->msgs_in.inflight_quota > 0){
		mosq->msgs_in.inflight_quota--;
	}
}

void util__decrement_send_quota(struct mosquitto *mosq)
{
	if(mosq->msgs_out.inflight_quota > 0){
		mosq->msgs_out.inflight_quota--;
	}
}


void util__increment_receive_quota(struct mosquitto *mosq)
{
	mosq->msgs_in.inflight_quota++;
}

void util__increment_send_quota(struct mosquitto *mosq)
{
	mosq->msgs_out.inflight_quota++;
}
