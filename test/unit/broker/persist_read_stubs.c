#include <time.h>

#include <logging_mosq.h>
#include <mosquitto_broker_internal.h>
#include <net_mosq.h>
#include <send_mosq.h>
#include <callbacks.h>
#ifndef WITH_SYS_TREE
#  define WITH_SYS_TREE
#endif
#include <sys_tree.h>

extern char *last_sub;
extern int last_qos;
extern uint32_t last_identifier;

struct mosquitto *context__init(void)
{
	struct mosquitto *m;

	m = mosquitto_calloc(1, sizeof(struct mosquitto));
	if(m){
		m->msgs_in.inflight_maximum = 20;
		m->msgs_out.inflight_maximum = 20;
		m->msgs_in.inflight_quota = 20;
		m->msgs_out.inflight_quota = 20;
	}
	return m;
}


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
	return false;
}


int net__socket_close(struct mosquitto *mosq)
{
	UNUSED(mosq);

	return MOSQ_ERR_SUCCESS;
}


int net__socket_shutdown(struct mosquitto *mosq)
{
	UNUSED(mosq);

	return MOSQ_ERR_SUCCESS;
}


int send__pingreq(struct mosquitto *mosq)
{
	UNUSED(mosq);

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_acl_check(struct mosquitto *context, const char *topic, uint32_t payloadlen, void *payload, uint8_t qos, bool retain, mosquitto_property *properties, int access)
{
	UNUSED(context);
	UNUSED(topic);
	UNUSED(payloadlen);
	UNUSED(payload);
	UNUSED(qos);
	UNUSED(retain);
	UNUSED(properties);
	UNUSED(access);

	return MOSQ_ERR_SUCCESS;
}


int acl__find_acls(struct mosquitto *context)
{
	UNUSED(context);

	return MOSQ_ERR_SUCCESS;
}


int sub__add(struct mosquitto *context, const struct mosquitto_subscription *sub)
{
	UNUSED(context);

	last_sub = strdup(sub->topic_filter);
	last_qos = sub->options & 0x03;
	last_identifier = sub->identifier;

	return MOSQ_ERR_SUCCESS;
}


void callback__on_disconnect(struct mosquitto *mosq, int rc, const mosquitto_property *props)
{
	UNUSED(mosq);
	UNUSED(rc);
	UNUSED(props);
}


void context__add_to_by_id(struct mosquitto *context)
{
	if(context->in_by_id == false){
		context->in_by_id = true;
		HASH_ADD_KEYPTR(hh_id, db.contexts_by_id, context->id, strlen(context->id), context);
	}
}


void context__send_will(struct mosquitto *context)
{
	UNUSED(context);
}


void plugin_persist__handle_retain_msg_set(struct mosquitto__base_msg *msg)
{
	UNUSED(msg);
}


void plugin_persist__handle_retain_msg_delete(struct mosquitto__base_msg *msg)
{
	UNUSED(msg);
}


void plugin_persist__handle_base_msg_add(struct mosquitto__base_msg *msg)
{
	UNUSED(msg);
}


void plugin_persist__process_retain_events(bool force)
{
	UNUSED(force);
}


void plugin_persist__queue_retain_event(struct mosquitto__base_msg *msg, int event)
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
struct mosquitto__subhier *sub__add_hier_entry(struct mosquitto__subhier *parent, struct mosquitto__subhier **sibling, const char *topic, uint16_t len)
{
	UNUSED(parent);
	UNUSED(sibling);
	UNUSED(topic);
	UNUSED(len);

	return NULL;
}


void plugin_persist__handle_client_msg_add(struct mosquitto *context, const struct mosquitto__client_msg *cmsg)
{
	UNUSED(context);
	UNUSED(cmsg);
}


void plugin_persist__handle_client_msg_delete(struct mosquitto *context, const struct mosquitto__client_msg *cmsg)
{
	UNUSED(context);
	UNUSED(cmsg);
}


void plugin_persist__handle_client_msg_update(struct mosquitto *context, const struct mosquitto__client_msg *cmsg)
{
	UNUSED(context);
	UNUSED(cmsg);
}


void plugin_persist__handle_client_msg_clear(struct mosquitto *context, uint8_t direction)
{
	UNUSED(context);
	UNUSED(direction);
}


void plugin_persist__handle_base_msg_delete(struct mosquitto__base_msg *msg)
{
	UNUSED(msg);
}


void plugin_persist__handle_subscription_delete(struct mosquitto *context, char *sub)
{
	UNUSED(context);
	UNUSED(sub);
}


int sub__messages_queue(const char *source_id, uint8_t qos, struct mosquitto__base_msg **base_msg)
{
	UNUSED(source_id);
	UNUSED(qos);
	*base_msg = NULL;
	return 0;
}
#ifdef WITH_SYS_TREE


void metrics__int_inc(enum mosq_metric_type m, int64_t value)
{
	UNUSED(m); UNUSED(value);
}


void metrics__int_dec(enum mosq_metric_type m, int64_t value)
{
	UNUSED(m); UNUSED(value);
}
#endif


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


int sub__init(void)
{
	return MOSQ_ERR_SUCCESS;
}
