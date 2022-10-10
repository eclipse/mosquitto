#include <time.h>

#define WITH_BROKER

#include <logging_mosq.h>
#include <memory_mosq.h>
#include <mosquitto_broker_internal.h>
#include <net_mosq.h>
#include <send_mosq.h>
#include <time_mosq.h>
#include <callbacks.h>

extern uint64_t last_retained;
extern char *last_sub;
extern int last_qos;

struct mosquitto *context__init(void)
{
	return mosquitto__calloc(1, sizeof(struct mosquitto));
}

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

int acl__find_acls(struct mosquitto *context)
{
	UNUSED(context);

	return MOSQ_ERR_SUCCESS;
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

void context__add_to_by_id(struct mosquitto *context)
{
	if(context->in_by_id == false){
		context->in_by_id = true;
		HASH_ADD_KEYPTR(hh_id, db.contexts_by_id, context->id, strlen(context->id), context);
	}
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
void plugin_persist__handle_retain_msg_set(struct mosquitto_base_msg *msg)
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

void plugin_persist__process_retain_events(bool force)
{
	UNUSED(force);
}

void plugin_persist__queue_retain_event(struct mosquitto_base_msg *msg, int event)
{
	UNUSED(msg);
	UNUSED(event);
}

int session_expiry__add_from_persistence(struct mosquitto *context, time_t expiry_time)
{
	UNUSED(context);
	UNUSED(expiry_time);
	return 0;
}

void mosquitto_log_printf(int level, const char *fmt, ...)
{
	UNUSED(level);
	UNUSED(fmt);
}
