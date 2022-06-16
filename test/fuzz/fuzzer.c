#include "config.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "logging_mosq.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "packet_mosq.h"
#include "property_mosq.h"

int log__printf(struct mosquitto *mosq, unsigned int priority, const char *fmt, ...)
{
	UNUSED(mosq);
	UNUSED(priority);
	UNUSED(fmt);

	return 0;
}

extern int LLVMFuzzerTestOneInput(const char *data, size_t size) {
	int rc;
	struct mosquitto__packet packet;
	mosquitto_property *properties;
	
	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = (uint8_t *)data;						//input data
	packet.remaining_length = size;							//input size

	rc = property__read_all(CMD_PUBREL, &packet, &properties);
	rc = property__read_all(CMD_CONNACK, &packet, &properties);
	rc = property__read_all(CMD_PUBLISH, &packet, &properties);
	rc = property__read_all(CMD_PUBACK, &packet, &properties);
	rc = property__read_all(CMD_PUBREC, &packet, &properties);
	rc = property__read_all(CMD_PUBREL, &packet, &properties);
	rc = property__read_all(CMD_PUBCOMP, &packet, &properties);
	rc = property__read_all(CMD_SUBSCRIBE, &packet, &properties);
	rc = property__read_all(CMD_SUBACK, &packet, &properties);
	rc = property__read_all(CMD_UNSUBSCRIBE, &packet, &properties);
	rc = property__read_all(CMD_UNSUBACK, &packet, &properties);
	rc = property__read_all(CMD_DISCONNECT, &packet, &properties);
	rc = property__read_all(CMD_AUTH, &packet, &properties);
	rc = property__read_all(CMD_WILL, &packet, &properties);
	return rc;
}

