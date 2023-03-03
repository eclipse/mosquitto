#include <time.h>

#include <logging_mosq.h>
#include <memory_mosq.h>
#include <mosquitto_broker_internal.h>
#include <net_mosq.h>
#include <send_mosq.h>
#include <time_mosq.h>
#include <callbacks.h>

extern char *last_sub;
extern int last_qos;
extern uint32_t last_identifier;

struct mosquitto *context__init(void)
{
	struct mosquitto *m;

	m = mosquitto__calloc(1, sizeof(struct mosquitto));
	if(m){
		m->msgs_in.inflight_maximum = 20;
		m->msgs_out.inflight_maximum = 20;
		m->msgs_in.inflight_quota = 20;
		m->msgs_out.inflight_quota = 20;
	}
	return m;
}

void db__msg_store_free(struct mosquitto__base_msg *store)
{
	int i;

	mosquitto__free(store->data.source_id);
	mosquitto__free(store->data.source_username);
	if(store->dest_ids){
		for(i=0; i<store->dest_id_count; i++){
			mosquitto__free(store->dest_ids[i]);
		}
		mosquitto__free(store->dest_ids);
	}
	mosquitto__free(store->data.topic);
	mosquitto_property_free_all(&store->data.properties);
	mosquitto__free(store->data.payload);
	mosquitto__free(store);
}

int db__message_store(const struct mosquitto *source, struct mosquitto__base_msg *stored, uint32_t message_expiry_interval, enum mosquitto_msg_origin origin)
{
    int rc = MOSQ_ERR_SUCCESS;

	UNUSED(origin);

    if(source && source->id){
        stored->data.source_id = mosquitto__strdup(source->id);
    }else{
        stored->data.source_id = mosquitto__strdup("");
    }
    if(!stored->data.source_id){
        rc = MOSQ_ERR_NOMEM;
        goto error;
    }

    if(source && source->username){
        stored->data.source_username = mosquitto__strdup(source->username);
        if(!stored->data.source_username){
            rc = MOSQ_ERR_NOMEM;
            goto error;
        }
    }
    if(source){
        stored->source_listener = source->listener;
    }
    if(message_expiry_interval > 0){
        stored->data.expiry_time = time(NULL) + message_expiry_interval;
    }else{
        stored->data.expiry_time = 0;
    }

    stored->dest_ids = NULL;
    stored->dest_id_count = 0;
    db.msg_store_count++;
    db.msg_store_bytes += stored->data.payloadlen;

    if(!stored->data.store_id){
        stored->data.store_id = ++db.last_db_id;
    }

	HASH_ADD(hh, db.msg_store, data.store_id, sizeof(stored->data.store_id), stored);

    return MOSQ_ERR_SUCCESS;
error:
	db__msg_store_free(stored);
    return rc;
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


int sub__add(struct mosquitto *context, const struct mosquitto_subscription *sub)
{
	UNUSED(context);

	last_sub = strdup(sub->topic_filter);
	last_qos = sub->options & 0x03;
	last_identifier = sub->identifier;

	return MOSQ_ERR_SUCCESS;
}

int db__message_insert_incoming(struct mosquitto *context, uint64_t cmsg_id, struct mosquitto__base_msg *msg, bool persist)
{
	UNUSED(context);
	UNUSED(cmsg_id);
	UNUSED(msg);
	UNUSED(persist);

	return MOSQ_ERR_SUCCESS;
}

int db__message_insert_outgoing(struct mosquitto *context, uint64_t cmsg_id, uint16_t mid, uint8_t qos, bool retain, struct mosquitto__base_msg *stored, uint32_t subscription_identifier, bool update, bool persist)
{
	UNUSED(context);
	UNUSED(cmsg_id);
	UNUSED(mid);
	UNUSED(qos);
	UNUSED(retain);
	UNUSED(stored);
	UNUSED(subscription_identifier);
	UNUSED(update);
	UNUSED(persist);

	return MOSQ_ERR_SUCCESS;
}

void db__msg_store_ref_dec(struct mosquitto__base_msg **store)
{
	UNUSED(store);
}

void db__msg_store_ref_inc(struct mosquitto__base_msg *store)
{
	store->ref_count++;
}

void callback__on_disconnect(struct mosquitto *mosq, int rc, const mosquitto_property *props)
{
	UNUSED(mosq);
	UNUSED(rc);
	UNUSED(props);
}

void db__msg_add_to_inflight_stats(struct mosquitto_msg_data *msg_data, struct mosquitto__client_msg *msg)
{
	UNUSED(msg_data);
	UNUSED(msg);
}

void db__msg_add_to_queued_stats(struct mosquitto_msg_data *msg_data, struct mosquitto__client_msg *msg)
{
	UNUSED(msg_data);
	UNUSED(msg);
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
