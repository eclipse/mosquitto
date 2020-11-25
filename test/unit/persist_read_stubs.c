#include <time.h>

#define WITH_BROKER

#include <logging_mosq.h>
#include <memory_mosq.h>
#include <mosquitto_broker_internal.h>
#include <net_mosq.h>
#include <send_mosq.h>
#include <time_mosq.h>

extern char *last_sub;
extern int last_qos;
extern uint32_t last_identifier;
extern struct mosquitto_db db;

struct mosquitto *context__init(mosq_sock_t sock)
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

void db__msg_store_free(struct mosquitto_msg_store *store)
{
	int i;

	mosquitto__free(store->source_id);
	mosquitto__free(store->source_username);
	if(store->dest_ids){
		for(i=0; i<store->dest_id_count; i++){
			mosquitto__free(store->dest_ids[i]);
		}
		mosquitto__free(store->dest_ids);
	}
	mosquitto__free(store->topic);
	mosquitto_property_free_all(&store->properties);
	mosquitto__free(store->payload);
	mosquitto__free(store);
}

int db__message_store(const struct mosquitto *source, struct mosquitto_msg_store *stored, uint32_t message_expiry_interval, dbid_t store_id, enum mosquitto_msg_origin origin)
{
    int rc = MOSQ_ERR_SUCCESS;

    if(source && source->id){
        stored->source_id = mosquitto__strdup(source->id);
    }else{
        stored->source_id = mosquitto__strdup("");
    }
    if(!stored->source_id){
        rc = MOSQ_ERR_NOMEM;
        goto error;
    }

    if(source && source->username){
        stored->source_username = mosquitto__strdup(source->username);
        if(!stored->source_username){
            rc = MOSQ_ERR_NOMEM;
            goto error;
        }
    }
    if(source){
        stored->source_listener = source->listener;
    }
    stored->mid = 0;
    if(message_expiry_interval > 0){
        stored->message_expiry_time = time(NULL) + message_expiry_interval;
    }else{
        stored->message_expiry_time = 0;
    }

    stored->dest_ids = NULL;
    stored->dest_id_count = 0;
    db.msg_store_count++;
    db.msg_store_bytes += stored->payloadlen;

    if(!store_id){
        stored->db_id = ++db.last_db_id;
    }else{
        stored->db_id = store_id;
    }

	db.msg_store = stored;

    return MOSQ_ERR_SUCCESS;
error:
	db__msg_store_free(stored);
    return rc;
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


int sub__add(struct mosquitto *context, const char *sub, uint8_t qos, uint32_t identifier, int options, struct mosquitto__subhier **root)
{
	last_sub = strdup(sub);
	last_qos = qos;
	last_identifier = identifier;

	return MOSQ_ERR_SUCCESS;
}

int db__message_insert(struct mosquitto *context, uint16_t mid, enum mosquitto_msg_direction dir, uint8_t qos, bool retain, struct mosquitto_msg_store *stored, mosquitto_property *properties, bool update)
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

