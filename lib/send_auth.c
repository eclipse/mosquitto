#include "config.h"

#include <stdio.h>
#include <string.h>

#include "logging_mosq.h"
#include "memory_mosq.h"
#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "mqtt_protocol.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "send_mosq.h"


#ifndef WITH_BROKER

int send__auth(struct mosquitto *context, uint8_t reason_code, uint8_t *authdata, uint16_t authlen)
{
	struct mosquitto__packet *packet = NULL;
	int rc;
	mosquitto_property *properties = NULL;

    if (context->protocol != mosq_p_mqtt5) return MOSQ_ERR_PROTOCOL;

    rc = mosquitto_property_add_string(&properties, MQTT_PROP_AUTHENTICATION_METHOD, context->auth_method);
	if (rc) return rc;

	if (authdata != NULL && authlen > 0){
		rc = mosquitto_property_add_binary(&properties, MQTT_PROP_AUTHENTICATION_DATA, authdata, authlen);
		if (rc){
			mosquitto_property_free_all(&properties);
			return rc;
		}
	}

	packet = calloc(1, sizeof(struct mosquitto__packet));
	if(!packet){
		mosquitto_property_free_all(&properties);
		return MOSQ_ERR_NOMEM;
	} 

	// packet->command = CMD_AUTH;
	// packet->remaining_length = 1 + property__get_remaining_length(properties);
	rc = packet__alloc(&packet, CMD_AUTH, 1 + property__get_remaining_length(properties));
	if(rc){
		mosquitto_property_free_all(&properties);
		free(packet);
		return rc;
	}

	packet__write_byte(packet, reason_code);
	property__write_all(packet, properties, true);

	mosquitto_property_free_all(&properties);
	return packet__queue(context, packet);
}

#endif // WITH_BROKER