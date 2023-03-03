#include <stdlib.h>
#include <string.h>

#include "misc_mosq.h"
#include "mosquitto_broker_internal.h"
#include "mosquitto_internal.h"
#include "util_mosq.h"

#ifndef UNUSED
#  define UNUSED(A) (void)(A)
#endif

struct mosquitto *context__init(void) { return NULL; }

void context__add_to_by_id(struct mosquitto *context) { UNUSED(context); }

int db__message_store(const struct mosquitto *source, struct mosquitto__base_msg *base_msg, uint32_t message_expiry_interval, enum mosquitto_msg_origin origin) { UNUSED(source); UNUSED(base_msg); UNUSED(message_expiry_interval); UNUSED(origin); return 0; }

void db__msg_store_ref_inc(struct mosquitto__base_msg *base_msg) { UNUSED(base_msg); }

int log__printf(struct mosquitto *mosq, unsigned int level, const char *fmt, ...) { UNUSED(mosq); UNUSED(level); UNUSED(fmt); return 0; }

FILE *mosquitto__fopen(const char *path, const char *mode, bool restrict_read) { UNUSED(path); UNUSED(mode); UNUSED(restrict_read); return NULL; }

int retain__store(const char *topic, struct mosquitto__base_msg *base_msg, char **split_topics, bool persist) { UNUSED(topic); UNUSED(base_msg); UNUSED(split_topics); UNUSED(persist); return 0; }

int sub__add(struct mosquitto *context, const struct mosquitto_subscription *sub) { UNUSED(context); UNUSED(sub); return 0; }

void db__msg_add_to_inflight_stats(struct mosquitto_msg_data *msg_data, struct mosquitto__client_msg *msg) { UNUSED(msg_data); UNUSED(msg); }

void db__msg_add_to_queued_stats(struct mosquitto_msg_data *msg_data, struct mosquitto__client_msg *msg) { UNUSED(msg_data); UNUSED(msg); }

int session_expiry__add_from_persistence(struct mosquitto *context, time_t expiry_time) { UNUSED(context); UNUSED(expiry_time); return 0; }
