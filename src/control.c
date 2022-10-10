/*
Copyright (c) 2020-2021 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include <stdio.h>
#include <utlist.h>

#include "mqtt_protocol.h"
#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "send_mosq.h"

#ifdef WITH_CONTROL
/* Process messages coming in on $CONTROL/<feature>. These messages aren't
 * passed on to other clients. */
int control__process(struct mosquitto *context, struct mosquitto_base_msg *base_msg)
{
	struct mosquitto__callback *cb_found;
	struct mosquitto_evt_control event_data;
	struct mosquitto__security_options *opts;
	mosquitto_property *properties = NULL;
	int rc = MOSQ_ERR_SUCCESS;
	int rc2;

	/* Check global plugins and non-per-listener settings first */
	opts = &db.config->security_options;
	HASH_FIND(hh, opts->plugin_callbacks.control, base_msg->topic, strlen(base_msg->topic), cb_found);

	/* If not found, check for per-listener plugins. */
	if(cb_found == NULL && db.config->per_listener_settings){
		opts = &context->listener->security_options;
		HASH_FIND(hh, opts->plugin_callbacks.control, base_msg->topic, strlen(base_msg->topic), cb_found);
	}
	if(cb_found){
		memset(&event_data, 0, sizeof(event_data));
		event_data.client = context;
		event_data.topic = base_msg->topic;
		event_data.payload = base_msg->payload;
		event_data.payloadlen = base_msg->payloadlen;
		event_data.qos = base_msg->qos;
		event_data.retain = base_msg->retain;
		event_data.properties = base_msg->properties;
		event_data.reason_code = MQTT_RC_SUCCESS;
		event_data.reason_string = NULL;

		rc = cb_found->cb(MOSQ_EVT_CONTROL, &event_data, cb_found->userdata);
		if(rc){
			if(context->protocol == mosq_p_mqtt5 && event_data.reason_string){
				mosquitto_property_add_string(&properties, MQTT_PROP_REASON_STRING, event_data.reason_string);
			}
		}
		SAFE_FREE(event_data.reason_string);
	}

	if(base_msg->qos == 1){
		rc2 = send__puback(context, base_msg->source_mid, MQTT_RC_SUCCESS, properties);
		if(rc2) rc = rc2;
	}else if(base_msg->qos == 2){
		rc2 = send__pubrec(context, base_msg->source_mid, MQTT_RC_SUCCESS, properties);
		if(rc2) rc = rc2;
	}
	mosquitto_property_free_all(&properties);

	return rc;
}
#endif

int control__register_callback(mosquitto_plugin_id_t *pid, MOSQ_FUNC_generic_callback cb_func, const char *topic, void *userdata)
{
#ifdef WITH_CONTROL
	struct mosquitto__security_options *opts;
	struct mosquitto__callback *cb_found, *cb_new;
	size_t topic_len;

	if(topic == NULL || cb_func == NULL) return MOSQ_ERR_INVAL;
	topic_len = strlen(topic);
	if(topic_len == 0 || topic_len > 65535) return MOSQ_ERR_INVAL;
	if(strncmp(topic, "$CONTROL/", strlen("$CONTROL/")) || strlen(topic) < strlen("$CONTROL/A/v1")){
		return MOSQ_ERR_INVAL;
	}

	opts = &db.config->security_options;

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
		mosquitto__FREE(cb_new);
		return MOSQ_ERR_NOMEM;
	}
	cb_new->cb = cb_func;
	cb_new->userdata = userdata;
	HASH_ADD_KEYPTR(hh, opts->plugin_callbacks.control, cb_new->data, strlen(cb_new->data), cb_new);

	if(pid->plugin_name){
		struct control_endpoint *ep;
		ep = mosquitto_malloc(sizeof(struct control_endpoint) + topic_len + 2);
		if(ep){
			ep->next = NULL;
			ep->prev = NULL;
			snprintf(ep->topic, topic_len+1, "%s", topic);
			DL_APPEND(pid->control_endpoints, ep);
		}
		log__printf(NULL, MOSQ_LOG_INFO, "Plugin %s has registered to receive 'control' events on topic %s.",
				pid->plugin_name, topic);
	}
	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}

int control__unregister_callback(mosquitto_plugin_id_t *identifier, MOSQ_FUNC_generic_callback cb_func, const char *topic)
{
#ifdef WITH_CONTROL
	struct mosquitto__security_options *opts;

	struct mosquitto__callback *cb_found;
	size_t topic_len;
	struct control_endpoint *ep;

	if(topic == NULL) return MOSQ_ERR_INVAL;
	topic_len = strlen(topic);
	if(topic_len == 0 || topic_len > 65535) return MOSQ_ERR_INVAL;
	if(strncmp(topic, "$CONTROL/", strlen("$CONTROL/"))) return MOSQ_ERR_INVAL;

	opts = &db.config->security_options;

	HASH_FIND(hh, opts->plugin_callbacks.control, topic, topic_len, cb_found);
	if(cb_found && cb_found->cb == cb_func){
		HASH_DELETE(hh, opts->plugin_callbacks.control, cb_found);
		mosquitto__FREE(cb_found->data);
		mosquitto__FREE(cb_found);

		DL_FOREACH(identifier->control_endpoints, ep){
			if(!strcmp(topic, ep->topic)){
				DL_DELETE(identifier->control_endpoints, ep);
				mosquitto__FREE(ep);
				break;
			}
		}
		return MOSQ_ERR_SUCCESS;
	}
	return MOSQ_ERR_NOT_FOUND;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}

/* Unregister all control callbacks for a single plugin */
void control__unregister_all_callbacks(mosquitto_plugin_id_t *identifier)
{
	struct mosquitto__security_options *opts;

	struct mosquitto__callback *cb_found;
	struct control_endpoint *ep, *ep_tmp;

	opts = &db.config->security_options;

	DL_FOREACH_SAFE(identifier->control_endpoints, ep, ep_tmp){
		HASH_FIND(hh, opts->plugin_callbacks.control, ep->topic, strlen(ep->topic), cb_found);
		if(cb_found){
			HASH_DELETE(hh, opts->plugin_callbacks.control, cb_found);
			mosquitto__FREE(cb_found->data);
			mosquitto__FREE(cb_found);
		}

		DL_DELETE(identifier->control_endpoints, ep);
		mosquitto__FREE(ep);
	}
}
