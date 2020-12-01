/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>

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

#include "mqtt_protocol.h"
#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "send_mosq.h"

#ifdef WITH_CONTROL
/* Process messages coming in on $CONTROL/<feature>. These messages aren't
 * passed on to other clients. */
int control__process(struct mosquitto *context, struct mosquitto_msg_store *stored)
{
	struct mosquitto__callback *cb_found;
	struct mosquitto_evt_control event_data;
	struct mosquitto__security_options *opts;
	mosquitto_property *properties = NULL;
	int rc = MOSQ_ERR_SUCCESS;

	if(db.config->per_listener_settings){
		opts = &context->listener->security_options;
	}else{
		opts = &db.config->security_options;
	}
	HASH_FIND(hh, opts->plugin_callbacks.control, stored->topic, strlen(stored->topic), cb_found);
	if(cb_found){
		memset(&event_data, 0, sizeof(event_data));
		event_data.client = context;
		event_data.topic = stored->topic;
		event_data.payload = stored->payload;
		event_data.payloadlen = stored->payloadlen;
		event_data.qos = stored->qos;
		event_data.retain = stored->retain;
		event_data.properties = stored->properties;
		event_data.reason_code = MQTT_RC_SUCCESS;
		event_data.reason_string = NULL;

		rc = cb_found->cb(MOSQ_EVT_CONTROL, &event_data, cb_found->userdata);
		if(rc){
			if(context->protocol == mosq_p_mqtt5 && event_data.reason_string){
				mosquitto_property_add_string(&properties, MQTT_PROP_REASON_STRING, event_data.reason_string);
			}
		}
		free(event_data.reason_string);
		event_data.reason_string = NULL;
	}

	if(stored->qos == 1){
		if(send__puback(context, stored->source_mid, MQTT_RC_SUCCESS, properties)) rc = 1;
	}else if(stored->qos == 2){
		if(send__pubrec(context, stored->source_mid, MQTT_RC_SUCCESS, properties)) rc = 1;
	}
	mosquitto_property_free_all(&properties);

	return rc;
}
#endif

int control__register_callback(struct mosquitto__security_options *opts, MOSQ_FUNC_generic_callback cb_func, const char *topic, void *userdata)
{
#ifdef WITH_CONTROL
	struct mosquitto__callback *cb_found, *cb_new;
	size_t topic_len;

	if(topic == NULL || cb_func == NULL) return MOSQ_ERR_INVAL;
	topic_len = strlen(topic);
	if(topic_len == 0 || topic_len > 65535) return MOSQ_ERR_INVAL;
	if(strncmp(topic, "$CONTROL/", strlen("$CONTROL/")) || strlen(topic) < strlen("$CONTROL/A/v1")){
		return MOSQ_ERR_INVAL;
	}

	HASH_FIND(hh, opts->plugin_callbacks.control, topic, topic_len, cb_found);
	if(cb_found){
		return MOSQ_ERR_ALREADY_EXISTS;
	}

	cb_new = mosquitto__calloc(1, sizeof(struct mosquitto__callback));
	if(cb_new == NULL){
		return MOSQ_ERR_NOMEM;
	}
	cb_new->data = mosquitto__strdup(topic);
	if(cb_new->data == NULL){
		mosquitto__free(cb_new);
		return MOSQ_ERR_NOMEM;
	}
	cb_new->cb = cb_func;
	cb_new->userdata = userdata;
	HASH_ADD_KEYPTR(hh, opts->plugin_callbacks.control, cb_new->data, strlen(cb_new->data), cb_new);

	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}

int control__unregister_callback(struct mosquitto__security_options *opts, MOSQ_FUNC_generic_callback cb_func, const char *topic)
{
#ifdef WITH_CONTROL
	struct mosquitto__callback *cb_found;
	size_t topic_len;

	if(topic == NULL) return MOSQ_ERR_INVAL;
	topic_len = strlen(topic);
	if(topic_len == 0 || topic_len > 65535) return MOSQ_ERR_INVAL;
	if(strncmp(topic, "$CONTROL/", strlen("$CONTROL/"))) return MOSQ_ERR_INVAL;

	HASH_FIND(hh, opts->plugin_callbacks.control, topic, topic_len, cb_found);
	if(cb_found){
		HASH_DELETE(hh, opts->plugin_callbacks.control, cb_found);
		mosquitto__free(cb_found->data);
		mosquitto__free(cb_found);

		return MOSQ_ERR_SUCCESS;;
	}
	return MOSQ_ERR_NOT_FOUND;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}
