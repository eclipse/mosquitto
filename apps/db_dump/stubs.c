#include <stdlib.h>
#include <string.h>

#include "mosquitto_broker_internal.h"
#include "mosquitto_internal.h"

struct mosquitto *context__init(mosq_sock_t sock)
{
	return NULL;
}

int db__message_store(const struct mosquitto *source, struct mosquitto_msg_store *stored, uint32_t message_expiry_interval, dbid_t store_id, enum mosquitto_msg_origin origin)
{
    return 0;
}

void db__msg_store_ref_inc(struct mosquitto_msg_store *store)
{
}

int handle__packet(struct mosquitto *context)
{
	return 0;
}

int log__printf(struct mosquitto *mosq, unsigned int level, const char *fmt, ...)
{
	return 0;
}

FILE *mosquitto__fopen(const char *path, const char *mode, bool restrict_read)
{
	return NULL;
}

enum mosquitto_client_state mosquitto__get_state(struct mosquitto *mosq)
{
	return mosq_cs_new;
}

ssize_t net__read(struct mosquitto *mosq, void *buf, size_t count)
{
	return 0;
}

ssize_t net__write(struct mosquitto *mosq, void *buf, size_t count)
{
	return 0;
}

int retain__store(const char *topic, struct mosquitto_msg_store *stored, char **split_topics)
{
	return 0;
}

int sub__add(struct mosquitto *context, const char *sub, uint8_t qos, uint32_t identifier, int options, struct mosquitto__subhier **root)
{
	return 0;
}

int sub__messages_queue(const char *source_id, const char *topic, uint8_t qos, int retain, struct mosquitto_msg_store **stored)
{
	return 0;
}

int keepalive__update(struct mosquitto *context)
{
	return 0;
}
