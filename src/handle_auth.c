/*
Copyright (c) 2018-2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR EDL-1.0

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include <stdio.h>
#include <string.h>

#include "mosquitto_broker_internal.h"
#include "mqtt_protocol.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "send_mosq.h"
#include "util_mosq.h"
#include "will_mosq.h"


int handle__auth(struct mosquitto *context)
{
	int rc = 0;
	uint8_t reason_code = 0;
	mosquitto_property *properties = NULL;
	char *auth_method = NULL;
	void *auth_data = NULL;
	uint16_t auth_data_len = 0;
	void *auth_data_out = NULL;
	uint16_t auth_data_out_len = 0;

	if(!context) return MOSQ_ERR_INVAL;

	if(context->protocol != mosq_p_mqtt5 || context->auth_method == NULL){
		return MOSQ_ERR_PROTOCOL;
	}

	if(context->in_packet.remaining_length > 0){
		if(packet__read_byte(&context->in_packet, &reason_code)) return MOSQ_ERR_MALFORMED_PACKET;
		if(reason_code != MQTT_RC_CONTINUE_AUTHENTICATION
				&& reason_code != MQTT_RC_REAUTHENTICATE){

			send__disconnect(context, MQTT_RC_PROTOCOL_ERROR, NULL);
			return MOSQ_ERR_PROTOCOL;
		}

		if((reason_code == MQTT_RC_REAUTHENTICATE && context->state != mosq_cs_active)
				|| (reason_code == MQTT_RC_CONTINUE_AUTHENTICATION
					&& context->state != mosq_cs_authenticating && context->state != mosq_cs_reauthenticating)){

			send__disconnect(context, MQTT_RC_PROTOCOL_ERROR, NULL);
			return MOSQ_ERR_PROTOCOL;
		}

		rc = property__read_all(CMD_AUTH, &context->in_packet, &properties);
		if(rc){
			send__disconnect(context, MQTT_RC_UNSPECIFIED, NULL);
			return rc;
		}


		if(mosquitto_property_read_string(properties, MQTT_PROP_AUTHENTICATION_METHOD, &auth_method, false) == NULL){
			mosquitto_property_free_all(&properties);
			send__disconnect(context, MQTT_RC_UNSPECIFIED, NULL);
			return MOSQ_ERR_PROTOCOL;
		}

		if(!auth_method || strcmp(auth_method, context->auth_method)){
			/* No method, or non-matching method */
			mosquitto__free(auth_method);
			mosquitto_property_free_all(&properties);
			send__disconnect(context, MQTT_RC_PROTOCOL_ERROR, NULL);
			return MOSQ_ERR_PROTOCOL;
		}
		mosquitto__free(auth_method);

		mosquitto_property_read_binary(properties, MQTT_PROP_AUTHENTICATION_DATA, &auth_data, &auth_data_len, false);

		mosquitto_property_free_all(&properties); /* FIXME - TEMPORARY UNTIL PROPERTIES PROCESSED */
	}

	log__printf(NULL, MOSQ_LOG_DEBUG, "Received AUTH from %s (rc%d, %s)", context->id, reason_code, context->auth_method);


	if(reason_code == MQTT_RC_REAUTHENTICATE){
		/* This is a re-authentication attempt */
		mosquitto__set_state(context, mosq_cs_reauthenticating);
		rc = mosquitto_security_auth_start(context, true, auth_data, auth_data_len, &auth_data_out, &auth_data_out_len);
	}else{
		if(context->state != mosq_cs_reauthenticating){
			mosquitto__set_state(context, mosq_cs_authenticating);
		}
		rc = mosquitto_security_auth_continue(context, auth_data, auth_data_len, &auth_data_out, &auth_data_out_len);
	}
	mosquitto__free(auth_data);
	if(rc == MOSQ_ERR_SUCCESS){
		if(context->state == mosq_cs_authenticating){
			return connect__on_authorised(context, auth_data_out, auth_data_out_len);
		}else{
			mosquitto__set_state(context, mosq_cs_active);
			rc = send__auth(context, MQTT_RC_SUCCESS, auth_data_out, auth_data_out_len);
			free(auth_data_out);
			return rc;
		}
	}else if(rc == MOSQ_ERR_AUTH_CONTINUE){
		rc = send__auth(context, MQTT_RC_CONTINUE_AUTHENTICATION, auth_data_out, auth_data_out_len);
		free(auth_data_out);
		return rc;
	}else{
		free(auth_data_out);
		if(context->state == mosq_cs_authenticating && context->will){
			/* Free will without sending if this is our first authentication attempt */
			will__clear(context);
		}
		if(rc == MOSQ_ERR_AUTH){
			send__connack(context, 0, MQTT_RC_NOT_AUTHORIZED, NULL);
			if(context->state == mosq_cs_authenticating){
				mosquitto__free(context->id);
				context->id = NULL;
			}
			return MOSQ_ERR_PROTOCOL;
		}else if(rc == MOSQ_ERR_NOT_SUPPORTED){
			/* Client has requested extended authentication, but we don't support it. */
			send__connack(context, 0, MQTT_RC_BAD_AUTHENTICATION_METHOD, NULL);
			if(context->state == mosq_cs_authenticating){
				mosquitto__free(context->id);
				context->id = NULL;
			}
			return MOSQ_ERR_PROTOCOL;
		}else{
			if(context->state == mosq_cs_authenticating){
				mosquitto__free(context->id);
				context->id = NULL;
			}
			return rc;
		}
	}
}
