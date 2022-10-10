#include <time.h>

#define WITH_BROKER
#define WITH_PERSISTENCE

#include <logging_mosq.h>
#include <memory_mosq.h>
#include <mosquitto_broker_internal.h>
#include <net_mosq.h>
#include <send_mosq.h>
#include <time_mosq.h>
#include <util_mosq.h>
#include <logging_mosq.h>
#include <persist.h>

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

int send__publish(struct mosquitto *mosq, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, uint8_t qos, bool retain, bool dup, uint32_t subscription_identifier, const mosquitto_property *store_props, uint32_t expiry_interval)
{
	UNUSED(mosq);
	UNUSED(mid);
	UNUSED(topic);
	UNUSED(payloadlen);
	UNUSED(payload);
	UNUSED(qos);
	UNUSED(retain);
	UNUSED(dup);
	UNUSED(subscription_identifier);
	UNUSED(store_props);
	UNUSED(expiry_interval);

	return MOSQ_ERR_SUCCESS;
}

int send__pubcomp(struct mosquitto *mosq, uint16_t mid, const mosquitto_property *properties)
{
	UNUSED(mosq);
	UNUSED(mid);
	UNUSED(properties);

	return MOSQ_ERR_SUCCESS;
}

int send__pubrec(struct mosquitto *mosq, uint16_t mid, uint8_t reason_code, const mosquitto_property *properties)
{
	UNUSED(mosq);
	UNUSED(mid);
	UNUSED(reason_code);
	UNUSED(properties);

	return MOSQ_ERR_SUCCESS;
}

int send__pubrel(struct mosquitto *mosq, uint16_t mid, const mosquitto_property *properties)
{
	UNUSED(mosq);
	UNUSED(mid);
	UNUSED(properties);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_acl_check(struct mosquitto *context, const char *topic, uint32_t payloadlen, void* payload, uint8_t qos, bool retain, int access)
{
	UNUSED(context);
	UNUSED(topic);
	UNUSED(payloadlen);
	UNUSED(payload);
	UNUSED(qos);
	UNUSED(retain);
	UNUSED(access);

	return MOSQ_ERR_SUCCESS;
}

uint16_t mosquitto__mid_generate(struct mosquitto *mosq)
{
	static uint16_t mid = 1;

	UNUSED(mosq);

	return ++mid;
}

int mosquitto_property_add_varint(mosquitto_property **proplist, int identifier, uint32_t value)
{
	UNUSED(proplist);
	UNUSED(identifier);
	UNUSED(value);

	return MOSQ_ERR_SUCCESS;
}

int persist__backup(bool shutdown)
{
	UNUSED(shutdown);

	return MOSQ_ERR_SUCCESS;
}

int persist__restore(void)
{
	return MOSQ_ERR_SUCCESS;
}

void mosquitto_property_free_all(mosquitto_property **properties)
{
	UNUSED(properties);
}

int retain__init(void)
{
	return MOSQ_ERR_SUCCESS;
}

void retain__clean(struct mosquitto__retainhier **retainhier)
{
	UNUSED(retainhier);
}

int retain__queue(struct mosquitto *context, const char *sub, uint8_t sub_qos, uint32_t subscription_identifier)
{
	UNUSED(context);
	UNUSED(sub);
	UNUSED(sub_qos);
	UNUSED(subscription_identifier);

	return MOSQ_ERR_SUCCESS;
}

int retain__store(const char *topic, struct mosquitto_base_msg *stored, char **split_topics, bool persist)
{
	UNUSED(topic);
	UNUSED(stored);
	UNUSED(split_topics);
	UNUSED(persist);

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

int util__random_bytes(void *bytes, int count)
{
	UNUSED(bytes);
	UNUSED(count);

	return MOSQ_ERR_SUCCESS;
}

void plugin_persist__handle_client_msg_add(struct mosquitto *context, const struct mosquitto_client_msg *cmsg)
{
	UNUSED(context);
	UNUSED(cmsg);
}
void plugin_persist__handle_client_msg_delete(struct mosquitto *context, const struct mosquitto_client_msg *cmsg)
{
	UNUSED(context);
	UNUSED(cmsg);
}
void plugin_persist__handle_client_msg_update(struct mosquitto *context, const struct mosquitto_client_msg *cmsg)
{
	UNUSED(context);
	UNUSED(cmsg);
}
void plugin_persist__handle_client_msg_clear(struct mosquitto *context, uint8_t direction)
{
	UNUSED(context);
	UNUSED(direction);
}
void plugin_persist__handle_base_msg_add(struct mosquitto_base_msg *msg)
{
	UNUSED(msg);
}
void plugin_persist__handle_base_msg_delete(struct mosquitto_base_msg *msg)
{
	UNUSED(msg);
}
void plugin_persist__handle_retain_msg_add(struct mosquitto_base_msg *msg)
{
	UNUSED(msg);
}
void plugin_persist__handle_retain_msg_delete(struct mosquitto_base_msg *msg)
{
	UNUSED(msg);
}
void plugin_persist__handle_subscription_delete(struct mosquitto *context, const char *sub)
{
	UNUSED(context);
	UNUSED(sub);
}
int session_expiry__add_from_persistence(struct mosquitto *context, time_t expiry_time)
{
	UNUSED(context);
	UNUSED(expiry_time);
	return 0;
}
