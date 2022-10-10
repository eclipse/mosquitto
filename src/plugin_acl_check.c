/*
Copyright (c) 2011-2021 Roger Light <roger@atchoo.org>

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
#include <string.h>

#include "mosquitto_broker.h"
#include "mosquitto_broker_internal.h"
#include "mosquitto_plugin.h"
#include "memory_mosq.h"
#include "lib_load.h"
#include "utlist.h"

int acl__pre_check(struct mosquitto__plugin_config *plugin, struct mosquitto *context, int access)
{
	const char *username;

	username = mosquitto_client_username(context);
	if(plugin->deny_special_chars == true){
		/* Check whether the client id or username contains a +, # or / and if
		* so deny access.
		*
		* Do this check for every message regardless, we have to protect the
		* plugins against possible pattern based attacks.
		*/
		if(username && strpbrk(username, "+#")){
			log__printf(NULL, MOSQ_LOG_NOTICE, "ACL denying access to client with dangerous username \"%s\"", username);
			return MOSQ_ERR_ACL_DENIED;
		}
		if(context->id && strpbrk(context->id, "+#")){
			log__printf(NULL, MOSQ_LOG_NOTICE, "ACL denying access to client with dangerous client id \"%s\"", context->id);
			return MOSQ_ERR_ACL_DENIED;
		}
	}

	if(plugin->plugin.version == 4){
		if(access == MOSQ_ACL_UNSUBSCRIBE){
			return MOSQ_ERR_SUCCESS;
		}
	}else if(plugin->plugin.version == 3){
		if(access == MOSQ_ACL_UNSUBSCRIBE){
			return MOSQ_ERR_SUCCESS;
		}
	}else if(plugin->plugin.version == 2){
		if(access == MOSQ_ACL_SUBSCRIBE || access == MOSQ_ACL_UNSUBSCRIBE){
			return MOSQ_ERR_SUCCESS;
		}
	}
	return MOSQ_ERR_PLUGIN_DEFER;
}


static int acl__check_dollar(const char *topic, int access)
{
	int rc;
	bool match = false;

	if(topic[0] != '$') return MOSQ_ERR_SUCCESS;

	if(!strncmp(topic, "$SYS", 4)){
		if(access == MOSQ_ACL_WRITE){
			/* Potentially allow write access for bridge status, otherwise explicitly deny. */
			rc = mosquitto_topic_matches_sub("$SYS/broker/connection/+/state", topic, &match);
			if(rc == MOSQ_ERR_SUCCESS && match == true){
				return MOSQ_ERR_SUCCESS;
			}else{
				return MOSQ_ERR_ACL_DENIED;
			}
		}else{
			return MOSQ_ERR_SUCCESS;
		}
	}else if(!strncmp(topic, "$share", 6)){
		/* Only allow sub/unsub to shared subscriptions */
		if(access == MOSQ_ACL_SUBSCRIBE || access == MOSQ_ACL_UNSUBSCRIBE){
			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_ACL_DENIED;
		}
	}else{
		/* This is an unknown $ topic, for the moment just defer to actual tests. */
		return MOSQ_ERR_SUCCESS;
	}
}


static int plugin__acl_check(struct mosquitto__security_options *opts, struct mosquitto *context, const char *topic, uint32_t payloadlen, void* payload, uint8_t qos, bool retain, int access)
{
	int rc = MOSQ_ERR_PLUGIN_DEFER;
	struct mosquitto_acl_msg msg;
	struct mosquitto__callback *cb_base;
	struct mosquitto_evt_acl_check event_data;

	memset(&msg, 0, sizeof(msg));
	msg.topic = topic;
	msg.payloadlen = payloadlen;
	msg.payload = payload;
	msg.qos = qos;
	msg.retain = retain;

	DL_FOREACH(opts->plugin_callbacks.acl_check, cb_base){
		rc = MOSQ_ERR_PLUGIN_DEFER;
		/* FIXME - username deny special chars */

		memset(&event_data, 0, sizeof(event_data));
		event_data.client = context;
		event_data.access = access;
		event_data.topic = topic;
		event_data.payloadlen = payloadlen;
		event_data.payload = payload;
		event_data.qos = qos;
		event_data.retain = retain;
		event_data.properties = NULL;
		rc = cb_base->cb(MOSQ_EVT_ACL_CHECK, &event_data, cb_base->userdata);
		if(rc != MOSQ_ERR_PLUGIN_DEFER && rc != MOSQ_ERR_PLUGIN_IGNORE){
			return rc;
		}
	}

	return rc;
}

int mosquitto_acl_check(struct mosquitto *context, const char *topic, uint32_t payloadlen, void* payload, uint8_t qos, bool retain, int access)
{
	int rc;
	int rc_final;

	if(!context->id){
		return MOSQ_ERR_ACL_DENIED;
	}
	if(context->bridge){
		return MOSQ_ERR_SUCCESS;
	}

	rc = acl__check_dollar(topic, access);
	if(rc) return rc;

	/*
	 * If no plugins exist we should accept at this point so set rc to success.
	 */
	rc_final = MOSQ_ERR_SUCCESS;

	/* If per_listener_settings is true, these are the global plugins.
	 * If per listener_settings is false, these are global and listener plugins. */
	if(db.config->security_options.plugin_callbacks.acl_check){
		rc = plugin__acl_check(&db.config->security_options, context, topic, payloadlen,
				payload, qos, retain, access);

		if(rc == MOSQ_ERR_PLUGIN_IGNORE){
			/* Do nothing, this is as if the plugin doesn't exist */
		}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
			rc_final = MOSQ_ERR_PLUGIN_DEFER;
		}else{
			return rc;
		}
	}

	if(db.config->per_listener_settings){
		if(context->listener){
			if(context->listener->security_options.plugin_callbacks.acl_check){
				rc = plugin__acl_check(&context->listener->security_options, context, topic, payloadlen,
						payload, qos, retain, access);

				if(rc == MOSQ_ERR_PLUGIN_IGNORE){
					/* Do nothing, this is as if the plugin doesn't exist */
				}else if(rc == MOSQ_ERR_PLUGIN_DEFER){
					rc_final = MOSQ_ERR_PLUGIN_DEFER;
				}else{
					return rc;
				}
			}
		}else{
			return MOSQ_ERR_ACL_DENIED;
		}
	}

	/* If all plugins deferred, this is a denial. If rc == MOSQ_ERR_SUCCESS
	 * here, then no plugins were configured, or all plugins ignored. */
	if(rc_final == MOSQ_ERR_PLUGIN_DEFER){
		rc_final = MOSQ_ERR_ACL_DENIED;
	}
	return rc_final;
}
