/*
Copyright (c) 2009-2021 Roger Light <roger@atchoo.org>

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
#include <utlist.h>

#include "mosquitto_broker_internal.h"
#include "mosquitto/mqtt_protocol.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "send_mosq.h"
#include "sys_tree.h"
#include "tls_mosq.h"
#include "util_mosq.h"
#include "will_mosq.h"

#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_LWS
#  include <libwebsockets.h>
#endif


static char nibble_to_hex(uint8_t value)
{
	if(value < 0x0A){
		return (char)('0'+value);
	}else{
		return (char)(65 /*'A'*/ +value-10);
	}
}


static char *clientid_gen(uint16_t *idlen, const char *auto_id_prefix, uint16_t auto_id_prefix_len)
{
	char *clientid;
	uint8_t rnd[16];
	int pos;

	if(mosquitto_getrandom(rnd, 16)){
		return NULL;
	}

	*idlen = (uint16_t)(auto_id_prefix_len + 36);

	clientid = (char *)mosquitto_calloc((size_t)(*idlen) + 1, sizeof(char));
	if(!clientid){
		return NULL;
	}
	if(auto_id_prefix){
		memcpy(clientid, auto_id_prefix, auto_id_prefix_len);
	}

	pos = 0;
	for(int i=0; i<16; i++){
		clientid[auto_id_prefix_len + pos + 0] = nibble_to_hex(rnd[i] & 0x0F);
		clientid[auto_id_prefix_len + pos + 1] = nibble_to_hex((rnd[i] >> 4) & 0x0F);
		pos += 2;
		if(pos == 8 || pos == 13 || pos == 18 || pos == 23){
			clientid[auto_id_prefix_len + pos] = '-';
			pos++;
		}
	}

	return clientid;
}


int connect__on_authorised(struct mosquitto *context, void *auth_data_out, uint16_t auth_data_out_len)
{
	struct mosquitto *found_context;
	struct mosquitto__subleaf *leaf;
	mosquitto_property *connack_props = NULL;
	uint8_t connect_ack = 0;
	int rc;
	int in_quota, out_quota;
	uint16_t in_maximum, out_maximum;

	/* Find if this client already has an entry. This must be done *after* any security checks. */
	HASH_FIND(hh_id, db.contexts_by_id, context->id, strlen(context->id), found_context);
	if(found_context){
		/* Found a matching client */
		if(!net__is_connected(found_context)){
			/* Client is reconnecting after a disconnect */
			/* FIXME - does anything need to be done here? */
		}else{
			/* Client is already connected, disconnect old version. This is
			 * done in context__cleanup() below. */
		}

		if(context->clean_start == true){
			sub__clean_session(found_context);
			found_context->session_expiry_interval = MQTT_SESSION_EXPIRY_IMMEDIATE;
			plugin_persist__handle_client_delete(found_context);
		}
		context->is_persisted = found_context->is_persisted;
		found_context->is_persisted = false; /* stops persistence for context being removed */

		if(context->clean_start == false && found_context->session_expiry_interval != MQTT_SESSION_EXPIRY_IMMEDIATE){
			if(context->protocol == mosq_p_mqtt311 || context->protocol == mosq_p_mqtt5){
				connect_ack |= 0x01;
			}

			if(found_context->msgs_in.inflight || found_context->msgs_in.queued
					|| found_context->msgs_out.inflight || found_context->msgs_out.queued){

				in_quota = context->msgs_in.inflight_quota;
				out_quota = context->msgs_out.inflight_quota;
				in_maximum = context->msgs_in.inflight_maximum;
				out_maximum = context->msgs_out.inflight_maximum;

				memcpy(&context->msgs_in, &found_context->msgs_in, sizeof(struct mosquitto_msg_data));
				memcpy(&context->msgs_out, &found_context->msgs_out, sizeof(struct mosquitto_msg_data));
				context->last_cmsg_id = found_context->last_cmsg_id;

				memset(&found_context->msgs_in, 0, sizeof(struct mosquitto_msg_data));
				memset(&found_context->msgs_out, 0, sizeof(struct mosquitto_msg_data));

				context->msgs_in.inflight_quota = in_quota;
				context->msgs_out.inflight_quota = out_quota;
				context->msgs_in.inflight_maximum = in_maximum;
				context->msgs_out.inflight_maximum = out_maximum;

				db__message_reconnect_reset(context);
			}
			context->subs = found_context->subs;
			found_context->subs = NULL;
			context->subs_capacity = found_context->subs_capacity;
			context->subs_count = found_context->subs_count;
			found_context->subs_capacity = 0;
			found_context->subs_count = 0;
			context->last_mid = found_context->last_mid;

			for(int i=0; i<context->subs_capacity; i++){
				if(context->subs[i]){
					leaf = context->subs[i]->hier->subs;
					while(leaf){
						if(leaf->context == found_context){
							leaf->context = context;
						}
						leaf = leaf->next;
					}

					if(context->subs[i]->shared){
						leaf = context->subs[i]->shared->subs;
						while(leaf){
							if(leaf->context == found_context){
								leaf->context = context;
							}
							leaf = leaf->next;
						}
					}
				}
			}
		}

		if((found_context->protocol == mosq_p_mqtt5 && found_context->session_expiry_interval == MQTT_SESSION_EXPIRY_IMMEDIATE)
				|| (found_context->protocol != mosq_p_mqtt5 && found_context->clean_start == true)
				|| (context->clean_start == true)
				){

			context__send_will(found_context);
		}

		session_expiry__remove(found_context);
		will_delay__remove(found_context);
		will__clear(found_context);

		found_context->clean_start = true;
		found_context->session_expiry_interval = MQTT_SESSION_EXPIRY_IMMEDIATE;
		mosquitto__set_state(found_context, mosq_cs_duplicate);
		if(found_context->protocol == mosq_p_mqtt5){
			send__disconnect(found_context, MQTT_RC_SESSION_TAKEN_OVER, NULL);
		}
		do_disconnect(found_context, MOSQ_ERR_SESSION_TAKEN_OVER);
	}

	if(db.config->global_max_clients > 0 && HASH_CNT(hh_id, db.contexts_by_id) >= (unsigned int)db.config->global_max_clients){
		if(context->protocol == mosq_p_mqtt5){
			send__connack(context, 0, MQTT_RC_SERVER_BUSY, NULL);
		}
		rc = MOSQ_ERR_INVAL;
		goto error;
	}

	if(db.config->connection_messages == true){
		if(context->is_bridge){
			if(context->username){
				log__printf(NULL, MOSQ_LOG_NOTICE, "New bridge connected from %s:%d as %s (p%d, c%d, k%d, u'%s').",
						context->address, context->remote_port, context->id, context->protocol, context->clean_start, context->keepalive, context->username);
			}else{
				log__printf(NULL, MOSQ_LOG_NOTICE, "New bridge connected from %s:%d as %s (p%d, c%d, k%d).",
						context->address, context->remote_port, context->id, context->protocol, context->clean_start, context->keepalive);
			}
		}else{
			if(context->username){
				log__printf(NULL, MOSQ_LOG_NOTICE, "New client connected from %s:%d as %s (p%d, c%d, k%d, u'%s').",
						context->address, context->remote_port, context->id, context->protocol, context->clean_start, context->keepalive, context->username);
			}else{
				log__printf(NULL, MOSQ_LOG_NOTICE, "New client connected from %s:%d as %s (p%d, c%d, k%d).",
						context->address, context->remote_port, context->id, context->protocol, context->clean_start, context->keepalive);
			}
		}

		if(context->will){
			log__printf(NULL, MOSQ_LOG_DEBUG, "Will message specified (%ld bytes) (r%d, q%d).",
					(long)context->will->msg.payloadlen,
					context->will->msg.retain,
					context->will->msg.qos);

			log__printf(NULL, MOSQ_LOG_DEBUG, "\t%s", context->will->msg.topic);
		}else{
			log__printf(NULL, MOSQ_LOG_DEBUG, "No will message specified.");
		}
	}
#ifdef WITH_TLS
	if(context->ssl){
		log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s negotiated %s cipher %s",
				context->id,
				SSL_get_cipher_version(context->ssl),
				SSL_get_cipher_name(context->ssl));
	}
#endif

	context->ping_t = 0;
	context->is_dropping = false;

	/* Remove any queued messages that are no longer allowed through ACL,
	 * assuming a possible change of username. */
	db__check_acl_of_all_messages(context);
	context__add_to_by_id(context);

#ifdef WITH_PERSISTENCE
	if(!context->clean_start){
		db.persistence_changes++;
	}
#endif
	context->max_qos = context->listener->max_qos;

	if(db.config->max_keepalive &&
			(context->keepalive > db.config->max_keepalive || context->keepalive == 0)){

		keepalive__remove(context);
		context->keepalive = db.config->max_keepalive;
		keepalive__add(context);
		if(context->protocol == mosq_p_mqtt5){
			if(mosquitto_property_add_int16(&connack_props, MQTT_PROP_SERVER_KEEP_ALIVE, context->keepalive)){
				rc = MOSQ_ERR_NOMEM;
				goto error;
			}
		}else{
			send__connack(context, connect_ack, CONNACK_REFUSED_IDENTIFIER_REJECTED, NULL);
			rc = MOSQ_ERR_INVAL;
			goto error;
		}
	}


	if(context->protocol == mosq_p_mqtt5){
		if(context->listener->max_topic_alias > 0){
			if(mosquitto_property_add_int16(&connack_props, MQTT_PROP_TOPIC_ALIAS_MAXIMUM, context->listener->max_topic_alias)){
				rc = MOSQ_ERR_NOMEM;
				goto error;
			}
		}
		if(context->assigned_id){
			if(mosquitto_property_add_string(&connack_props, MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER, context->id)){
				rc = MOSQ_ERR_NOMEM;
				goto error;
			}
		}
		if(context->auth_method){
			if(mosquitto_property_add_string(&connack_props, MQTT_PROP_AUTHENTICATION_METHOD, context->auth_method)){
				rc = MOSQ_ERR_NOMEM;
				goto error;
			}

			if(auth_data_out && auth_data_out_len > 0){
				if(mosquitto_property_add_binary(&connack_props, MQTT_PROP_AUTHENTICATION_DATA, auth_data_out, auth_data_out_len)){
					rc = MOSQ_ERR_NOMEM;
					goto error;
				}
			}
		}
	}
	SAFE_FREE(auth_data_out);

	mosquitto__set_state(context, mosq_cs_active);
	rc = send__connack(context, connect_ack, CONNACK_ACCEPTED, connack_props);
	mosquitto_property_free_all(&connack_props);
	if(rc){
		return rc;
	}
	db__expire_all_messages(context);
	rc = db__message_write_queued_out(context);
	if(rc){
		return rc;
	}
	rc = db__message_write_inflight_out_all(context);

	if(rc == MOSQ_ERR_SUCCESS){
		plugin__handle_connect(context);

		if(context->session_expiry_interval != MQTT_SESSION_EXPIRY_IMMEDIATE){
			plugin_persist__handle_client_add(context);
		}else if(context->will){
			plugin_persist__handle_will_add(context);
		}
	}
	return rc;
error:
	SAFE_FREE(auth_data_out);
	mosquitto_property_free_all(&connack_props);
	return rc;
}


static int will__read(struct mosquitto *context, const char *clientid, struct mosquitto_message_all **will, uint8_t will_qos, int will_retain)
{
	int rc = MOSQ_ERR_SUCCESS;
	size_t slen;
	uint16_t tlen;
	struct mosquitto_message_all *will_struct = NULL;
	char *will_topic_mount = NULL;
	uint16_t payloadlen;
	mosquitto_property *properties = NULL;

	will_struct = mosquitto_calloc(1, sizeof(struct mosquitto_message_all));
	if(!will_struct){
		rc = MOSQ_ERR_NOMEM;
		goto error_cleanup;
	}
	if(context->protocol == PROTOCOL_VERSION_v5){
		rc = property__read_all(CMD_WILL, &context->in_packet, &properties);
		if(rc){
			goto error_cleanup;
		}

		rc = property__process_will(context, will_struct, &properties);
		mosquitto_property_free_all(&properties);
		if(rc){
			goto error_cleanup;
		}
	}
	rc = packet__read_string(&context->in_packet, &will_struct->msg.topic, &tlen);
	if(rc){
		goto error_cleanup;
	}
	if(!tlen){
		log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s: Will with empty topic.",
				context->id);
		rc = MOSQ_ERR_PROTOCOL;
		goto error_cleanup;
	}

	if(context->listener->mount_point){
		slen = strlen(context->listener->mount_point) + strlen(will_struct->msg.topic) + 1;
		will_topic_mount = mosquitto_malloc(slen+1);
		if(!will_topic_mount){
			rc = MOSQ_ERR_NOMEM;
			goto error_cleanup;
		}

		snprintf(will_topic_mount, slen, "%s%s", context->listener->mount_point, will_struct->msg.topic);
		will_topic_mount[slen] = '\0';

		mosquitto_FREE(will_struct->msg.topic);
		will_struct->msg.topic = will_topic_mount;
	}

	if(!strncmp(will_struct->msg.topic, "$CONTROL/", strlen("$CONTROL/"))){
		rc = MOSQ_ERR_ACL_DENIED;
		goto error_cleanup;
	}
	rc = mosquitto_pub_topic_check(will_struct->msg.topic);
	if(rc){
		goto error_cleanup;
	}

	rc = packet__read_uint16(&context->in_packet, &payloadlen);
	if(rc){
		goto error_cleanup;
	}

	will_struct->msg.payloadlen = payloadlen;
	if(will_struct->msg.payloadlen > 0){
		if(db.config->message_size_limit && will_struct->msg.payloadlen > (int)db.config->message_size_limit){
			log__printf(NULL, MOSQ_LOG_DEBUG, "Client %s connected with too large Will payload", clientid);
			if(context->protocol == mosq_p_mqtt5){
				send__connack(context, 0, MQTT_RC_PACKET_TOO_LARGE, NULL);
			}else{
				send__connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED, NULL);
			}
			rc = MOSQ_ERR_PAYLOAD_SIZE;
			goto error_cleanup;
		}
		will_struct->msg.payload = mosquitto_malloc((size_t)will_struct->msg.payloadlen);
		if(!will_struct->msg.payload){
			rc = MOSQ_ERR_NOMEM;
			goto error_cleanup;
		}

		rc = packet__read_bytes(&context->in_packet, will_struct->msg.payload, (uint32_t)will_struct->msg.payloadlen);
		if(rc){
			goto error_cleanup;
		}
	}

	will_struct->msg.qos = will_qos;
	will_struct->msg.retain = will_retain;

	*will = will_struct;
	return MOSQ_ERR_SUCCESS;

error_cleanup:
	if(will_struct){
		mosquitto_FREE(will_struct->msg.topic);
		mosquitto_FREE(will_struct->msg.payload);
		mosquitto_property_free_all(&will_struct->properties);
		mosquitto_FREE(will_struct);
	}
	return rc;
}


static int check_protocol_version(struct mosquitto__listener *listener, int protocol_version)
{
	/* Allow bridge protocol as well. */
	protocol_version &= 0x7F;

	if((protocol_version == 3 && listener->disable_protocol_v3 == false)
			|| (protocol_version == 4 && listener->disable_protocol_v4 == false)
			|| (protocol_version == 5 && listener->disable_protocol_v5 == false)
			){

		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_NOT_SUPPORTED;
	}
}


inline static int send__connack_error_and_return(struct mosquitto *context, uint8_t err_code, int rc)
{
	send__connack(context, 0, err_code, NULL);
	return rc;
}


inline static int send__connack_bad_username_or_password_error(struct mosquitto *context, int rc)
{
	uint8_t err_code  = context->protocol == mosq_p_mqtt5
									? (uint8_t)MQTT_RC_BAD_USERNAME_OR_PASSWORD
									: (uint8_t)CONNACK_REFUSED_BAD_USERNAME_PASSWORD;
	return send__connack_error_and_return(context, err_code, rc);
}


static int read_protocol_name(struct mosquitto *context, char protocol_name[7])
{
	/* Read protocol name as length then bytes rather than with read_string
	 * because the length is fixed and we can check that. Removes the need
	 * for another malloc as well. */

	uint16_t slen = 0;

	if(packet__read_uint16(&context->in_packet, &slen)){
		log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s:%d: CONNECT with missing protocol string length.",
				context->address, context->remote_port);
		return MOSQ_ERR_PROTOCOL;
	}
	if(slen != 4 /* MQTT */ && slen != 6 /* MQIsdp */){
		log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s:%d: CONNECT with incorrect protocol string length (%d).",
				context->address, context->remote_port, slen);
		return MOSQ_ERR_PROTOCOL;
	}
	if(packet__read_bytes(&context->in_packet, protocol_name, slen)){
		log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s:%d: CONNECT with missing protocol string.",
				context->address, context->remote_port);
		return MOSQ_ERR_PROTOCOL;
	}
	protocol_name[slen] = '\0';

	return MOSQ_ERR_SUCCESS;
}


static int read_and_verify_protocol_version(struct mosquitto *context, const char *protocol_name,
		uint8_t *protocol_version)
{
	uint8_t tmp_protocol_version = 0;
	if(packet__read_byte(&context->in_packet, &tmp_protocol_version)){
		log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s:%d: CONNECT with missing protocol version.",
				context->address, context->remote_port);
		return MOSQ_ERR_PROTOCOL;
	}

	if(check_protocol_version(context->listener, tmp_protocol_version)){
		if(tmp_protocol_version == 3 || tmp_protocol_version == 4){
			context->protocol = mosq_p_mqtt311;
			send__connack(context, 0, CONNACK_REFUSED_PROTOCOL_VERSION, NULL);
		}else{
			context->protocol = mosq_p_mqtt5;
			send__connack(context, 0, MQTT_RC_UNSUPPORTED_PROTOCOL_VERSION, NULL);
		}
		return MOSQ_ERR_NOT_SUPPORTED;
	}

	if(!strcmp(protocol_name, PROTOCOL_NAME_v31)){
		if((tmp_protocol_version&0x7F) != PROTOCOL_VERSION_v31){
			if(db.config->connection_messages == true){
				log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s:%d: CONNECT with invalid protocol version (%d).",
						context->address, context->remote_port, tmp_protocol_version);
			}
			send__connack(context, 0, CONNACK_REFUSED_PROTOCOL_VERSION, NULL);
			return MOSQ_ERR_PROTOCOL;
		}
		context->protocol = mosq_p_mqtt31;
		if((tmp_protocol_version&0x80) == 0x80){
			context->is_bridge = true;
		}
	}else if(!strcmp(protocol_name, PROTOCOL_NAME)){
		if((tmp_protocol_version&0x7F) == PROTOCOL_VERSION_v311){
			context->protocol = mosq_p_mqtt311;

			if((tmp_protocol_version&0x80) == 0x80){
				context->is_bridge = true;
			}
		}else if((tmp_protocol_version&0x7F) == PROTOCOL_VERSION_v5){
			context->protocol = mosq_p_mqtt5;
		}else{
			if(db.config->connection_messages == true){
				log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s:%d: CONNECT with invalid protocol version (%d).",
						context->address, context->remote_port, tmp_protocol_version);
			}
			send__connack(context, 0, CONNACK_REFUSED_PROTOCOL_VERSION, NULL);
			return MOSQ_ERR_PROTOCOL;
		}
		if((context->in_packet.command&0x0F) != 0x00){
			/* Reserved flags not set to 0, must disconnect. */
			log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s:%d: CONNECT with non-zero reserved flags (%02X).",
					context->address, context->remote_port, context->in_packet.command);
			return MOSQ_ERR_PROTOCOL;
		}
	}else{
		if(db.config->connection_messages == true){
			log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s:%d: CONNECT with invalid protocol \"%s\".",
					context->address, context->remote_port, protocol_name);
		}
		return MOSQ_ERR_PROTOCOL;
	}
	if((tmp_protocol_version&0x7F) != PROTOCOL_VERSION_v31 && context->in_packet.command != CMD_CONNECT){
		return MOSQ_ERR_MALFORMED_PACKET;
	}

	*protocol_version = tmp_protocol_version;
	return MOSQ_ERR_SUCCESS;
}


static int read_and_verify_connect_flags(struct mosquitto *context, uint8_t *connect_flags)
{
	if(packet__read_byte(&context->in_packet, connect_flags)){
		log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s:%d: CONNECT with missing connect flags.",
				context->address, context->remote_port);
		return MOSQ_ERR_PROTOCOL;
	}
	if(context->protocol == mosq_p_mqtt311 || context->protocol == mosq_p_mqtt5){
		if((*connect_flags & 0x01) != 0x00){
			log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s:%d: CONNECT with non-zero connect reserved flag (%02X).",
					context->address, context->remote_port, *connect_flags);
			return MOSQ_ERR_PROTOCOL;
		}
	}

	return MOSQ_ERR_SUCCESS;
}


static void set_session_expiry_interval(struct mosquitto *context, uint8_t clean_start, uint8_t protocol_version)
{
	/* session_expiry_interval will be overridden if the properties are read later */
	if(clean_start == false && protocol_version != PROTOCOL_VERSION_v5){
		/* v3* has clean_start == false mean the session never expires */
		context->session_expiry_interval = MQTT_SESSION_EXPIRY_NEVER;
	}else{
		context->session_expiry_interval = MQTT_SESSION_EXPIRY_IMMEDIATE;
	}
}


static int read_and_reset_keepalive(struct mosquitto *context)
{
	/* _remove here because net__socket_accept() uses _add and we must have the
	 * correct keepalive value */
	keepalive__remove(context);

	if(packet__read_uint16(&context->in_packet, &(context->keepalive))){
		log__printf(NULL, MOSQ_LOG_INFO, "%s sent CONNECT with missing keepalive.",
				context->id);
		return MOSQ_ERR_PROTOCOL;
	}
	keepalive__add(context);

	return MOSQ_ERR_SUCCESS;
}


static int read_and_verify_v5_connect_properties(struct mosquitto *context, mosquitto_property **properties, uint8_t protocol_version)
{
	int rc;

	if(protocol_version == PROTOCOL_VERSION_v5){
		rc = property__read_all(CMD_CONNECT, &context->in_packet, properties);
		if(rc == MOSQ_ERR_DUPLICATE_PROPERTY || rc == MOSQ_ERR_PROTOCOL){
			send__connack(context, 0, MQTT_RC_PROTOCOL_ERROR, NULL);
		}else if(rc == MOSQ_ERR_MALFORMED_PACKET){
			send__connack(context, 0, MQTT_RC_MALFORMED_PACKET, NULL);
		}
		if(rc){
			return rc;
		}
	}
	rc = property__process_connect(context, properties);
	if(rc != MOSQ_ERR_SUCCESS){
		return send__connack_error_and_return(context, MQTT_RC_PROTOCOL_ERROR, rc);
	}

	return MOSQ_ERR_SUCCESS;
}


static int verify_will_options(struct mosquitto *context, uint8_t will, uint8_t will_qos, uint8_t will_retain, uint8_t protocol_version)
{
	if(will_qos == 3){
		log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s:%d: CONNECT with invalid Will QoS (%d).",
				context->address, context->remote_port, will_qos);
		return MOSQ_ERR_PROTOCOL;
	}

	if(will && will_retain && db.config->retain_available == false){
		if(protocol_version == mosq_p_mqtt5){
			send__connack(context, 0, MQTT_RC_RETAIN_NOT_SUPPORTED, NULL);
		}
		return MOSQ_ERR_NOT_SUPPORTED;
	}

	if(will && will_qos > context->listener->max_qos){
		if(protocol_version == mosq_p_mqtt5){
			send__connack(context, 0, MQTT_RC_QOS_NOT_SUPPORTED, NULL);
		}
		return MOSQ_ERR_NOT_SUPPORTED;
	}

	return MOSQ_ERR_SUCCESS;
}


static int handle_zero_length_clientid(struct mosquitto *context, char **clientid, bool *allow_zero_length_clientid,
		uint8_t clean_start)
{
	if(context->protocol == mosq_p_mqtt31){
		log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s:%d: v3.1 CONNECT with zero length clientid.",
				context->address, context->remote_port);
		send__connack(context, 0, CONNACK_REFUSED_IDENTIFIER_REJECTED, NULL);
		return MOSQ_ERR_PROTOCOL;
	}

	/* mqtt311/mqtt5 */
	mosquitto_FREE(*clientid);

	if(db.config->per_listener_settings){
		*allow_zero_length_clientid = context->listener->security_options->allow_zero_length_clientid;
	}else{
		*allow_zero_length_clientid = db.config->security_options.allow_zero_length_clientid;
	}

	if((context->protocol == mosq_p_mqtt311 && clean_start == 0) || *allow_zero_length_clientid == false){
		log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s:%d: CONNECT with zero length clientid when forbidden.",
				context->address, context->remote_port);
		uint8_t err_code = context->protocol == mosq_p_mqtt311 ? (uint8_t)CONNACK_REFUSED_IDENTIFIER_REJECTED : (uint8_t)MQTT_RC_UNSPECIFIED;
		return send__connack_error_and_return(context, err_code, MOSQ_ERR_PROTOCOL);
	}

	*clientid = clientid_gen(&(uint16_t){0}, context->listener->security_options->auto_id_prefix,
			context->listener->security_options->auto_id_prefix_len);
	if(*clientid == NULL){
		return MOSQ_ERR_NOMEM;
	}
	context->assigned_id = true;

	return MOSQ_ERR_SUCCESS;
}


static int check_clientid_prefixes(struct mosquitto *context, const char *clientid)
{
	if(db.config->clientid_prefixes){
		if(strncmp(db.config->clientid_prefixes, clientid, strlen(db.config->clientid_prefixes))){
			uint8_t err_code = context->protocol == mosq_p_mqtt5 ? (uint8_t)MQTT_RC_NOT_AUTHORIZED : (uint8_t)CONNACK_REFUSED_NOT_AUTHORIZED;
			return send__connack_error_and_return(context, err_code, MOSQ_ERR_AUTH);
		}
	}
	return MOSQ_ERR_SUCCESS;
}


static int read_and_verify_clientid_from_packet(struct mosquitto *context, char **clientid,
		bool *allow_zero_length_clientid, uint8_t clean_start)
{
	int rc;
	uint16_t slen;

	rc = packet__read_string(&context->in_packet, clientid, &slen);
	if(rc == MOSQ_ERR_MALFORMED_UTF8){
		if(context->protocol == mosq_p_mqtt5){
			send__connack(context, 0, MQTT_RC_CLIENTID_NOT_VALID, NULL);
		}
		return MOSQ_ERR_CLIENT_IDENTIFIER_NOT_VALID;
	}else if(rc > 0){
		return MOSQ_ERR_PROTOCOL;
	}

	if(slen == 0){
		rc = handle_zero_length_clientid(context, clientid, allow_zero_length_clientid, clean_start);
		if(rc != MOSQ_ERR_SUCCESS){
			return rc;
		}
	}

	rc = check_clientid_prefixes(context, *clientid);
	if(rc != MOSQ_ERR_SUCCESS){
		return rc;
	}

	return MOSQ_ERR_SUCCESS;
}


static int set_username_from_packet(struct mosquitto *context, char **username, const char *clientid)
{
	int rc;

	rc = packet__read_string(&context->in_packet, username, &(uint16_t){0});
	if(rc == MOSQ_ERR_NOMEM){
		return MOSQ_ERR_NOMEM;
	}
	if(rc != MOSQ_ERR_SUCCESS){
		if(context->protocol == mosq_p_mqtt31){
			/* Username flag given, but no username. Ignore. */
			/* NOTE: Removed setting of username_flag to zero as it is unused afterwards */
		}else{
			log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s: CONNECT with username flag but no username.",
					clientid);
			return MOSQ_ERR_PROTOCOL;
		}
	}

	return MOSQ_ERR_SUCCESS;
}


static int set_password_from_packet(struct mosquitto *context, char **password, uint16_t *password_len, const char *clientid)
{
	int rc;

	rc = packet__read_binary(&context->in_packet, (uint8_t **)password, password_len);
	if(rc == MOSQ_ERR_NOMEM){
		return MOSQ_ERR_NOMEM;
	}

	if(rc == MOSQ_ERR_MALFORMED_PACKET){
		if(context->protocol == mosq_p_mqtt31){
			/* Password flag given, but no password. Ignore. */
		}else{
			log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s: CONNECT with password flag but no password.",
					clientid);
			return MOSQ_ERR_PROTOCOL;
		}
	}

	return MOSQ_ERR_SUCCESS;
}


static int read_and_verify_client_credentials_from_packet(struct mosquitto *context,
		char **username, uint8_t username_flag,
		char **password, uint16_t *password_len, uint8_t password_flag,
		const char *clientid)
{
	int rc;

	if(username_flag){
		rc = set_username_from_packet(context, username, clientid);
		if(rc != MOSQ_ERR_SUCCESS){
			return rc;
		}
	}else{
		if(context->protocol == mosq_p_mqtt311 || context->protocol == mosq_p_mqtt31){
			if(password_flag){
				/* username_flag == 0 && password_flag == 1 is forbidden */
				log__printf(NULL, MOSQ_LOG_ERR, "Protocol error from %s: password without username, closing connection.", clientid);
				return MOSQ_ERR_PROTOCOL;
			}
		}
	}
	if(password_flag){
		rc = set_password_from_packet(context, password, password_len, clientid);
		if(rc != MOSQ_ERR_SUCCESS){
			return rc;
		}
	}

	return MOSQ_ERR_SUCCESS;
}


static int check_additional_trailing_data(struct mosquitto *context, uint8_t protocol_version)
{
	if(context->in_packet.pos != context->in_packet.remaining_length){
		/* Surplus data at end of packet, this must be an error. */
		log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s: CONNECT packet with overlong remaining length (%d:%d).",
				context->id, context->in_packet.pos, context->in_packet.remaining_length);
		if(protocol_version == PROTOCOL_VERSION_v5){
			send__connack(context, 0, MQTT_RC_MALFORMED_PACKET, NULL);
		}
		return MOSQ_ERR_PROTOCOL;
	}

	return MOSQ_ERR_SUCCESS;
}

#ifdef WITH_TLS


inline static int get_client_cert_and_subject_name(struct mosquitto *context, X509 **client_cert, X509_NAME **name)
{
	*client_cert = SSL_get_peer_certificate(context->ssl);
	if(*client_cert == NULL){
		return send__connack_bad_username_or_password_error(context, MOSQ_ERR_AUTH);
	}

	*name = X509_get_subject_name(*client_cert);
	if(*name == NULL){
		X509_free(*client_cert);
		return send__connack_bad_username_or_password_error(context, MOSQ_ERR_AUTH);
	}

	return MOSQ_ERR_SUCCESS;
}


inline static int free_x509_and_send_connack_error(struct mosquitto *context, X509 *client_cert, int rc)
{
	X509_free(client_cert);
	return send__connack_bad_username_or_password_error(context, rc);
}


inline static int free_x509_and_BIO_and_send_connack_error(struct mosquitto *context, X509 *client_cert,
		BIO *subject_name, int rc)
{
	BIO_free(subject_name);
	return free_x509_and_send_connack_error(context, client_cert, rc);
}


static int set_username_from_cert_identity(struct mosquitto *context)
{
	X509 *client_cert = NULL;
	X509_NAME *name = NULL;

	if(get_client_cert_and_subject_name(context, &client_cert, &name)){
		return MOSQ_ERR_AUTH;
	}

	int i = -1;
	X509_NAME_ENTRY *name_entry = NULL;

	i = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
	if(i == -1){
		return free_x509_and_send_connack_error(context, client_cert, MOSQ_ERR_AUTH);
	}
	name_entry = X509_NAME_get_entry(name, i);
	if(!name_entry){
		goto success;
	}

	ASN1_STRING *name_asn1 = NULL;
	name_asn1 = X509_NAME_ENTRY_get_data(name_entry);
	if(name_asn1 == NULL){
		return free_x509_and_send_connack_error(context, client_cert, MOSQ_ERR_AUTH);
	}
	const char *cert_identity = (const char *)ASN1_STRING_get0_data(name_asn1);
	if(!cert_identity || mosquitto_validate_utf8(cert_identity, (int)strlen(cert_identity))){
		return free_x509_and_send_connack_error(context, client_cert, MOSQ_ERR_AUTH);
	}
	mosquitto_free(context->username);
	context->username = mosquitto_strdup(cert_identity);
	if(context->username == NULL){
		return free_x509_and_send_connack_error(context, client_cert, MOSQ_ERR_NOMEM);
	}
	/* Make sure there isn't an embedded NUL character in the CN */
	if((size_t)ASN1_STRING_length(name_asn1) != strlen(context->username)){
		return free_x509_and_send_connack_error(context, client_cert, MOSQ_ERR_AUTH);
	}

success:
	X509_free(client_cert);
	client_cert = NULL;
	return MOSQ_ERR_SUCCESS;
}


static int set_username_from_cert_subject_name(struct mosquitto *context)
{
	X509 *client_cert = NULL;
	X509_NAME *name = NULL;

	if(get_client_cert_and_subject_name(context, &client_cert, &name)){
		return MOSQ_ERR_AUTH;
	}

	char *subject = NULL;
	char *data_start = NULL;
	BIO *subject_bio = NULL;
	long name_length = 0;

	subject_bio = BIO_new(BIO_s_mem());
	X509_NAME_print_ex(subject_bio, X509_get_subject_name(client_cert), 0, XN_FLAG_RFC2253);
	data_start = NULL;
	name_length = BIO_get_mem_data(subject_bio, &data_start);
	subject = mosquitto_malloc(sizeof(char)*(size_t)(name_length+1));
	if(!subject){
		return free_x509_and_BIO_and_send_connack_error(context, client_cert, subject_bio, MOSQ_ERR_NOMEM);
	}
	memcpy(subject, data_start, (size_t)name_length);
	subject[name_length] = '\0';
	BIO_free(subject_bio);

	if(mosquitto_validate_utf8(subject, (int)strlen(subject))){
		mosquitto_free(subject);
		return free_x509_and_send_connack_error(context, client_cert, MOSQ_ERR_AUTH);
	}
	context->username = subject;
	if(!context->username){
		X509_free(client_cert);
		return MOSQ_ERR_AUTH;
	}

	X509_free(client_cert);
	client_cert = NULL;
	return MOSQ_ERR_SUCCESS;
}
#endif


static int handle_username_from_cert_options(struct mosquitto *context, char **username, char **password, uint16_t password_len)
{
	int rc;

#ifdef WITH_TLS
	if(context->listener->ssl_ctx && (context->listener->use_identity_as_username || context->listener->use_subject_as_username)){
		/* Don't need the username or password if provided */
		mosquitto_FREE(*username);
		mosquitto_FREE(*password);

		if(!context->ssl){
			return send__connack_bad_username_or_password_error(context, MOSQ_ERR_AUTH);
		}
#ifdef FINAL_WITH_TLS_PSK
		if(context->listener->psk_hint){
			/* Client should have provided an identity to get this far. */
			if(!context->username){
				return send__connack_bad_username_or_password_error(context, MOSQ_ERR_AUTH);
			}
		}else
#endif /* FINAL_WITH_TLS_PSK */
		{
			if(context->listener->use_identity_as_username){
				rc = set_username_from_cert_identity(context);
			}else{   /* use_subject_as_username */
				rc = set_username_from_cert_subject_name(context);
			}
			if(rc){
				return rc;
			}
		}
	}else
#endif /* WITH_TLS */
	{
#ifdef WITH_TLS
		if(context->listener->use_identity_as_username && context->listener->require_certificate){
			mosquitto_FREE(*username);
			mosquitto_FREE(*password);

			if(!context->username){
				return send__connack_bad_username_or_password_error(context, MOSQ_ERR_AUTH);
			}
		}else
#endif
		{
			/* FIXME - these ensure the mosquitto_clientid() and
			* mosquitto_client_username() functions work, but is hacky */
			context->username = *username;
			context->password = *password;
			context->password_len = password_len;
			*username = NULL; /* Avoid free() in error: below. */
			*password = NULL;
		}
	}

	return MOSQ_ERR_SUCCESS;
}


static int handle_username_as_clientid_option(struct mosquitto *context)
{
	if(context->username){
		mosquitto_FREE(context->id);
		context->id = mosquitto_strdup(context->username);
		if(!context->id){
			return MOSQ_ERR_NOMEM;
		}
	}else{
		uint8_t err_code = context->protocol == mosq_p_mqtt5
												? (uint8_t)MQTT_RC_NOT_AUTHORIZED
												: (uint8_t)CONNACK_REFUSED_NOT_AUTHORIZED;
		return send__connack_error_and_return(context, err_code, MOSQ_ERR_AUTH);
	}

	return MOSQ_ERR_SUCCESS;
}


int handle__connect(struct mosquitto *context)
{
	char protocol_name[7];
	uint8_t protocol_version;
	uint8_t connect_flags;
	char *clientid = NULL;
	struct mosquitto *found_context;
	struct mosquitto_message_all *will_struct = NULL;
	uint8_t will, will_retain, will_qos, clean_start;
	uint8_t username_flag, password_flag;
	char *username = NULL, *password = NULL;
	uint16_t password_len = 0;
	int rc;
	mosquitto_property *properties = NULL;
	void *auth_data = NULL;
	uint16_t auth_data_len = 0;
	void *auth_data_out = NULL;
	uint16_t auth_data_out_len = 0;
	bool allow_zero_length_clientid;

	if(!context->listener){
		return MOSQ_ERR_INVAL;
	}

	/* Don't accept multiple CONNECT commands. */
	if(context->state != mosq_cs_new){
		log__printf(NULL, MOSQ_LOG_NOTICE, "Bad client %s:%d sending multiple CONNECT messages.",
				context->address, context->remote_port);
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}

#ifdef WITH_TLS
	if(context->in_packet.command == 0x16 && context->listener->ssl_ctx == NULL){ /* 0x16 is TLS handshake client hello */
		log__printf(NULL, MOSQ_LOG_NOTICE, "Client from %s:%d appears to be using TLS to connect to a non-TLS listener.",
				context->address, context->remote_port);
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}
#endif

	rc = read_protocol_name(context, protocol_name);
	if(rc != MOSQ_ERR_SUCCESS){
		goto handle_connect_error;
	}

	rc = read_and_verify_protocol_version(context, protocol_name, &protocol_version);
	if(rc != MOSQ_ERR_SUCCESS){
		if(rc == MOSQ_ERR_MALFORMED_PACKET){
			return rc;
		}
		goto handle_connect_error;
	}

	rc = read_and_verify_connect_flags(context, &connect_flags);
	if(rc != MOSQ_ERR_SUCCESS){
		goto handle_connect_error;
	}

	clean_start = (connect_flags & 0x02) >> 1;
	set_session_expiry_interval(context, clean_start, protocol_version);

	rc = read_and_reset_keepalive(context);
	if(rc != MOSQ_ERR_SUCCESS){
		goto handle_connect_error;
	}

	rc = read_and_verify_v5_connect_properties(context, &properties, protocol_version);
	if(rc != MOSQ_ERR_SUCCESS){
		goto handle_connect_error;
	}

	will = connect_flags & 0x04;
	will_qos = (connect_flags & 0x18) >> 3;
	will_retain = ((connect_flags & 0x20) == 0x20);
	rc = verify_will_options(context, will, will_qos, will_retain, protocol_version);
	if(rc != MOSQ_ERR_SUCCESS){
		goto handle_connect_error;
	}

	mosquitto_property_read_string(properties, MQTT_PROP_AUTHENTICATION_METHOD, &context->auth_method, false);
	mosquitto_property_read_binary(properties, MQTT_PROP_AUTHENTICATION_DATA, &auth_data, &auth_data_len, false);
	mosquitto_property_free_all(&properties);

	if(auth_data && !context->auth_method){
		send__connack(context, 0, MQTT_RC_PROTOCOL_ERROR, NULL);
		log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s:%d CONNECT with missing clientid string.",
				context->address, context->remote_port);
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}

	rc = read_and_verify_clientid_from_packet(context, &clientid, &allow_zero_length_clientid, clean_start);
	if(rc != MOSQ_ERR_SUCCESS){
		goto handle_connect_error;
	}

	if(will){
		rc = will__read(context, clientid, &will_struct, will_qos, will_retain);
		if(rc){
			if(context->protocol == mosq_p_mqtt5){
				if(rc == MOSQ_ERR_DUPLICATE_PROPERTY || rc == MOSQ_ERR_PROTOCOL){
					send__connack(context, 0, MQTT_RC_PROTOCOL_ERROR, NULL);
				}else if(rc == MOSQ_ERR_MALFORMED_PACKET){
					send__connack(context, 0, MQTT_RC_MALFORMED_PACKET, NULL);
				}
			}
			goto handle_connect_error;
		}
	}else{
		if(context->protocol == mosq_p_mqtt311 || context->protocol == mosq_p_mqtt5){
			if(will_qos != 0 || will_retain != 0){
				log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s: CONNECT without Will with non-zero QoS (%d) or retain (%d).",
						clientid, will_qos, will_retain);
				rc = MOSQ_ERR_PROTOCOL;
				goto handle_connect_error;
			}
		}
	}

	// Client credentials
	password_flag = connect_flags & 0x40;
	username_flag = connect_flags & 0x80;
	rc = read_and_verify_client_credentials_from_packet(context, &username, username_flag, &password, &password_len, password_flag, clientid);
	if(rc != MOSQ_ERR_SUCCESS){
		goto handle_connect_error;
	}

	rc = check_additional_trailing_data(context, protocol_version);
	if(rc != MOSQ_ERR_SUCCESS){
		goto handle_connect_error;
	}

	/* Once context->id is set, if we return from this function with an error
	 * we must make sure that context->id is freed and set to NULL, so that the
	 * client isn't erroneously removed from the by_id hash table. */
	context->id = clientid;
	clientid = NULL;

	/* use_identity_as_username or use_subject_as_username */
	rc = handle_username_from_cert_options(context, &username, &password, password_len);
	if(rc != MOSQ_ERR_SUCCESS){
		goto handle_connect_error;
	}

	/* use_username_as_clientid */
	if(context->listener->use_username_as_clientid){
		rc = handle_username_as_clientid_option(context);
		if(rc != MOSQ_ERR_SUCCESS){
			goto handle_connect_error;
		}
	}

	/* Check for an existing delayed auth check, reject if present */
	HASH_FIND(hh_id, db.contexts_by_id_delayed_auth, context->id, strlen(context->id), found_context);
	if(found_context){
		rc = MOSQ_ERR_UNKNOWN;
		goto handle_connect_error;
	}

	context->clean_start = clean_start;
	context->will = will_struct;
	will_struct = NULL;

	if(context->auth_method){
		rc = mosquitto_security_auth_start(context, false, auth_data, auth_data_len, &auth_data_out, &auth_data_out_len);
		mosquitto_FREE(auth_data);
		if(rc == MOSQ_ERR_SUCCESS){
			return connect__on_authorised(context, auth_data_out, auth_data_out_len);
		}else if(rc == MOSQ_ERR_AUTH_CONTINUE){
			mosquitto__set_state(context, mosq_cs_authenticating);
			rc = send__auth(context, MQTT_RC_CONTINUE_AUTHENTICATION, auth_data_out, auth_data_out_len);
			SAFE_FREE(auth_data_out);
			return rc;
		}else{
			SAFE_FREE(auth_data_out);
			will__clear(context);
			if(rc == MOSQ_ERR_AUTH){
				send__connack(context, 0, MQTT_RC_NOT_AUTHORIZED, NULL);
				mosquitto_FREE(context->id);
				goto handle_connect_error;
			}else if(rc == MOSQ_ERR_NOT_SUPPORTED){
				/* Client has requested extended authentication, but we don't support it. */
				send__connack(context, 0, MQTT_RC_BAD_AUTHENTICATION_METHOD, NULL);
				mosquitto_FREE(context->id);
				goto handle_connect_error;
			}else{
				mosquitto_FREE(context->id);
				goto handle_connect_error;
			}
		}
	}else{
#ifdef WITH_TLS
		if(context->listener->ssl_ctx && (context->listener->use_identity_as_username || context->listener->use_subject_as_username)){
			/* Authentication assumed to be cleared */
		}else
#endif
		{
			rc = mosquitto_basic_auth(context);
			switch(rc){
				case MOSQ_ERR_SUCCESS:
					break;
				case MOSQ_ERR_AUTH_DELAYED:
					mosquitto__set_state(context, mosq_cs_delayed_auth);
					HASH_ADD_KEYPTR(hh_id, db.contexts_by_id_delayed_auth, context->id, strlen(context->id), context);
					return MOSQ_ERR_SUCCESS;
					break;
				case MOSQ_ERR_AUTH:
					if(context->protocol == mosq_p_mqtt5){
						send__connack(context, 0, MQTT_RC_NOT_AUTHORIZED, NULL);
					}else{
						send__connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED, NULL);
					}
					goto handle_connect_error;
					break;
				case MOSQ_ERR_UNSPECIFIED:
				case MOSQ_ERR_IMPLEMENTATION_SPECIFIC:
				case MOSQ_ERR_CLIENT_IDENTIFIER_NOT_VALID:
				case MOSQ_ERR_BAD_USERNAME_OR_PASSWORD:
				case MOSQ_ERR_SERVER_UNAVAILABLE:
				case MOSQ_ERR_SERVER_BUSY:
				case MOSQ_ERR_BANNED:
				case MOSQ_ERR_BAD_AUTHENTICATION_METHOD:
				case MOSQ_ERR_CONNECTION_RATE_EXCEEDED:
					if(context->protocol == mosq_p_mqtt5){
						send__connack(context, 0, (uint8_t)rc, NULL);
					}else{
						send__connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED, NULL);
					}
					goto handle_connect_error;
					break;
				default:
					rc = MOSQ_ERR_UNKNOWN;
					goto handle_connect_error;
					break;
			}
		}
		return connect__on_authorised(context, NULL, 0);
	}


handle_connect_error:
	mosquitto_property_free_all(&properties);
	mosquitto_FREE(auth_data);
	mosquitto_FREE(clientid);
	mosquitto_FREE(username);
	mosquitto_FREE(password);
	if(will_struct){
		mosquitto_property_free_all(&will_struct->properties);
		mosquitto_FREE(will_struct->msg.payload);
		mosquitto_FREE(will_struct->msg.topic);
		mosquitto_FREE(will_struct);
	}
	will__clear(context);
	/* We return an error here which means the client is freed later on. */
	context->clean_start = true;
	context->session_expiry_interval = MQTT_SESSION_EXPIRY_IMMEDIATE;
	context->will_delay_interval = 0;
	return rc;
}
