/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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
#include <utlist.h>

#include "mosquitto_broker_internal.h"
#include "mqtt_protocol.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "send_mosq.h"
#include "sys_tree.h"
#include "time_mosq.h"
#include "tls_mosq.h"
#include "util_mosq.h"
#include "will_mosq.h"

#ifdef WITH_WEBSOCKETS
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

static char *client_id_gen(uint16_t *idlen, const char *auto_id_prefix, uint16_t auto_id_prefix_len)
{
	char *client_id;
	uint8_t rnd[16];
	int i;
	int pos;

	if(util__random_bytes(rnd, 16)) return NULL;

	*idlen = (uint16_t)(auto_id_prefix_len + 36);

	client_id = (char *)mosquitto__calloc((size_t)(*idlen) + 1, sizeof(char));
	if(!client_id){
		return NULL;
	}
	if(auto_id_prefix){
		memcpy(client_id, auto_id_prefix, auto_id_prefix_len);
	}

	pos = 0;
	for(i=0; i<16; i++){
		client_id[auto_id_prefix_len + pos + 0] = nibble_to_hex(rnd[i] & 0x0F);
		client_id[auto_id_prefix_len + pos + 1] = nibble_to_hex((rnd[i] >> 4) & 0x0F);
		pos += 2;
		if(pos == 8 || pos == 13 || pos == 18 || pos == 23){
			client_id[auto_id_prefix_len + pos] = '-';
			pos++;
		}
	}

	return client_id;
}

/* Remove any queued messages that are no longer allowed through ACL,
 * assuming a possible change of username. */
void connection_check_acl(struct mosquitto *context, struct mosquitto_client_msg **head)
{
	struct mosquitto_client_msg *msg_tail, *tmp;

	DL_FOREACH_SAFE((*head), msg_tail, tmp){
		if(msg_tail->direction == mosq_md_out){
			if(mosquitto_acl_check(context, msg_tail->store->topic,
								   msg_tail->store->payloadlen, msg_tail->store->payload,
								   msg_tail->store->qos, msg_tail->store->retain, MOSQ_ACL_READ) != MOSQ_ERR_SUCCESS){

				DL_DELETE((*head), msg_tail);
				db__msg_store_ref_dec(&msg_tail->store);
				mosquitto_property_free_all(&msg_tail->properties);
				mosquitto__free(msg_tail);
			}
		}
	}
}


int connect__on_authorised(struct mosquitto *context, void *auth_data_out, uint16_t auth_data_out_len)
{
	struct mosquitto *found_context;
	struct mosquitto__subleaf *leaf;
	mosquitto_property *connack_props = NULL;
	uint8_t connect_ack = 0;
	int i;
	int rc;

	/* Find if this client already has an entry. This must be done *after* any security checks. */
	HASH_FIND(hh_id, db.contexts_by_id, context->id, strlen(context->id), found_context);
	if(found_context){
		/* Found a matching client */
		if(found_context->sock == INVALID_SOCKET){
			/* Client is reconnecting after a disconnect */
			/* FIXME - does anything need to be done here? */
		}else{
			/* Client is already connected, disconnect old version. This is
			 * done in context__cleanup() below. */
			if(db.config->connection_messages == true){
				log__printf(NULL, MOSQ_LOG_ERR, "Client %s already connected, closing old connection.", context->id);
			}
		}

		if(context->clean_start == false && found_context->session_expiry_interval > 0){
			if(context->protocol == mosq_p_mqtt311 || context->protocol == mosq_p_mqtt5){
				connect_ack |= 0x01;
			}

			if(found_context->msgs_in.inflight || found_context->msgs_in.queued
					|| found_context->msgs_out.inflight || found_context->msgs_out.queued){

				memcpy(&context->msgs_in, &found_context->msgs_in, sizeof(struct mosquitto_msg_data));
				memcpy(&context->msgs_out, &found_context->msgs_out, sizeof(struct mosquitto_msg_data));

				memset(&found_context->msgs_in, 0, sizeof(struct mosquitto_msg_data));
				memset(&found_context->msgs_out, 0, sizeof(struct mosquitto_msg_data));

				db__message_reconnect_reset(context);
			}
			context->subs = found_context->subs;
			found_context->subs = NULL;
			context->sub_count = found_context->sub_count;
			found_context->sub_count = 0;
			context->last_mid = found_context->last_mid;

			for(i=0; i<context->sub_count; i++){
				if(context->subs[i]){
					leaf = context->subs[i]->subs;
					while(leaf){
						if(leaf->context == found_context){
							leaf->context = context;
						}
						leaf = leaf->next;
					}
				}
			}
		}

		if(context->clean_start == true){
			sub__clean_session(found_context);
		}
		session_expiry__remove(found_context);
		will_delay__remove(found_context);
		will__clear(found_context);

		found_context->clean_start = true;
		found_context->session_expiry_interval = 0;
		mosquitto__set_state(found_context, mosq_cs_duplicate);
		do_disconnect(found_context, MOSQ_ERR_SUCCESS);
	}

	rc = acl__find_acls(context);
	if(rc){
		free(auth_data_out);
		return rc;
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

		if(context->will) {
			log__printf(NULL, MOSQ_LOG_DEBUG, "Will message specified (%ld bytes) (r%d, q%d).",
					(long)context->will->msg.payloadlen,
					context->will->msg.retain,
					context->will->msg.qos);

			log__printf(NULL, MOSQ_LOG_DEBUG, "\t%s", context->will->msg.topic);
		} else {
			log__printf(NULL, MOSQ_LOG_DEBUG, "No will message specified.");
		}
	}

	context->ping_t = 0;
	context->is_dropping = false;

	connection_check_acl(context, &context->msgs_in.inflight);
	connection_check_acl(context, &context->msgs_in.queued);
	connection_check_acl(context, &context->msgs_out.inflight);
	connection_check_acl(context, &context->msgs_out.queued);

	HASH_ADD_KEYPTR(hh_id, db.contexts_by_id, context->id, strlen(context->id), context);

#ifdef WITH_PERSISTENCE
	if(!context->clean_start){
		db.persistence_changes++;
	}
#endif
	context->max_qos = context->listener->max_qos;

	if(context->protocol == mosq_p_mqtt5){
		if(context->listener->max_topic_alias > 0){
			if(mosquitto_property_add_int16(&connack_props, MQTT_PROP_TOPIC_ALIAS_MAXIMUM, context->listener->max_topic_alias)){
				rc = MOSQ_ERR_NOMEM;
				goto error;
			}
		}
		if(context->keepalive > db.config->max_keepalive){
			context->keepalive = db.config->max_keepalive;
			if(mosquitto_property_add_int16(&connack_props, MQTT_PROP_SERVER_KEEP_ALIVE, context->keepalive)){
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
	free(auth_data_out);
	auth_data_out = NULL;

	keepalive__add(context);

	mosquitto__set_state(context, mosq_cs_active);
	rc = send__connack(context, connect_ack, CONNACK_ACCEPTED, connack_props);
	mosquitto_property_free_all(&connack_props);
	if(rc) return rc;
	rc = db__message_write_queued_out(context);
	if(rc) return rc;
	rc = db__message_write_inflight_out_all(context);
	return rc;
error:
	free(auth_data_out);
	mosquitto_property_free_all(&connack_props);
	return rc;
}


static int will__read(struct mosquitto *context, struct mosquitto_message_all **will, uint8_t will_qos, int will_retain)
{
	int rc = MOSQ_ERR_SUCCESS;
	size_t slen;
	uint16_t tlen;
	struct mosquitto_message_all *will_struct = NULL;
	char *will_topic_mount = NULL;
	uint16_t payloadlen;
	mosquitto_property *properties = NULL;

	will_struct = mosquitto__calloc(1, sizeof(struct mosquitto_message_all));
	if(!will_struct){
		rc = MOSQ_ERR_NOMEM;
		goto error_cleanup;
	}
	if(context->protocol == PROTOCOL_VERSION_v5){
		rc = property__read_all(CMD_WILL, &context->in_packet, &properties);
		if(rc) goto error_cleanup;

		rc = property__process_will(context, will_struct, &properties);
		mosquitto_property_free_all(&properties);
		if(rc) goto error_cleanup;
	}
	rc = packet__read_string(&context->in_packet, &will_struct->msg.topic, &tlen);
	if(rc) goto error_cleanup;
	if(!tlen){
		rc = MOSQ_ERR_PROTOCOL;
		goto error_cleanup;
	}

	if(context->listener->mount_point){
		slen = strlen(context->listener->mount_point) + strlen(will_struct->msg.topic) + 1;
		will_topic_mount = mosquitto__malloc(slen+1);
		if(!will_topic_mount){
			rc = MOSQ_ERR_NOMEM;
			goto error_cleanup;
		}

		snprintf(will_topic_mount, slen, "%s%s", context->listener->mount_point, will_struct->msg.topic);
		will_topic_mount[slen] = '\0';

		mosquitto__free(will_struct->msg.topic);
		will_struct->msg.topic = will_topic_mount;
	}

	rc = mosquitto_pub_topic_check(will_struct->msg.topic);
	if(rc) goto error_cleanup;

	rc = packet__read_uint16(&context->in_packet, &payloadlen);
	if(rc) goto error_cleanup;

	will_struct->msg.payloadlen = payloadlen;
	if(will_struct->msg.payloadlen > 0){
		will_struct->msg.payload = mosquitto__malloc((size_t)will_struct->msg.payloadlen);
		if(!will_struct->msg.payload){
			rc = MOSQ_ERR_NOMEM;
			goto error_cleanup;
		}

		rc = packet__read_bytes(&context->in_packet, will_struct->msg.payload, (uint32_t)will_struct->msg.payloadlen);
		if(rc) goto error_cleanup;
	}

	will_struct->msg.qos = will_qos;
	will_struct->msg.retain = will_retain;

	*will = will_struct;
	return MOSQ_ERR_SUCCESS;

error_cleanup:
	if(will_struct){
		mosquitto__free(will_struct->msg.topic);
		mosquitto__free(will_struct->msg.payload);
		mosquitto_property_free_all(&will_struct->properties);
		mosquitto__free(will_struct);
	}
	return rc;
}



int handle__connect(struct mosquitto *context)
{
	char protocol_name[7];
	uint8_t protocol_version;
	uint8_t connect_flags;
	char *client_id = NULL;
	struct mosquitto_message_all *will_struct = NULL;
	uint8_t will, will_retain, will_qos, clean_start;
	uint8_t username_flag, password_flag;
	char *username = NULL, *password = NULL;
	int rc;
	uint16_t slen;
	mosquitto_property *properties = NULL;
	void *auth_data = NULL;
	uint16_t auth_data_len = 0;
	void *auth_data_out = NULL;
	uint16_t auth_data_out_len = 0;
	bool allow_zero_length_clientid;
#ifdef WITH_TLS
	int i;
	X509 *client_cert = NULL;
	X509_NAME *name;
	X509_NAME_ENTRY *name_entry;
	ASN1_STRING *name_asn1 = NULL;
	BIO *subject_bio;
	char *data_start;
	long name_length;
	char *subject;
#endif

	G_CONNECTION_COUNT_INC();

	if(!context->listener){
		return MOSQ_ERR_INVAL;
	}

	/* Don't accept multiple CONNECT commands. */
	if(context->state != mosq_cs_new){
		log__printf(NULL, MOSQ_LOG_NOTICE, "Bad client %s sending multiple CONNECT messages.", context->id);
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}

	/* Read protocol name as length then bytes rather than with read_string
	 * because the length is fixed and we can check that. Removes the need
	 * for another malloc as well. */
	if(packet__read_uint16(&context->in_packet, &slen)){
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}
	if(slen != 4 /* MQTT */ && slen != 6 /* MQIsdp */){
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}
	if(packet__read_bytes(&context->in_packet, protocol_name, slen)){
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}
	protocol_name[slen] = '\0';

	if(packet__read_byte(&context->in_packet, &protocol_version)){
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}
	if(!strcmp(protocol_name, PROTOCOL_NAME_v31)){
		if((protocol_version&0x7F) != PROTOCOL_VERSION_v31){
			if(db.config->connection_messages == true){
				log__printf(NULL, MOSQ_LOG_INFO, "Invalid protocol version %d in CONNECT from %s.",
						protocol_version, context->address);
			}
			send__connack(context, 0, CONNACK_REFUSED_PROTOCOL_VERSION, NULL);
			rc = MOSQ_ERR_PROTOCOL;
			goto handle_connect_error;
		}
		context->protocol = mosq_p_mqtt31;
		if((protocol_version&0x80) == 0x80){
			context->is_bridge = true;
		}
	}else if(!strcmp(protocol_name, PROTOCOL_NAME)){
		if((protocol_version&0x7F) == PROTOCOL_VERSION_v311){
			context->protocol = mosq_p_mqtt311;

			if((protocol_version&0x80) == 0x80){
				context->is_bridge = true;
			}
		}else if((protocol_version&0x7F) == PROTOCOL_VERSION_v5){
			context->protocol = mosq_p_mqtt5;
		}else{
			if(db.config->connection_messages == true){
				log__printf(NULL, MOSQ_LOG_INFO, "Invalid protocol version %d in CONNECT from %s.",
						protocol_version, context->address);
			}
			send__connack(context, 0, CONNACK_REFUSED_PROTOCOL_VERSION, NULL);
			rc = MOSQ_ERR_PROTOCOL;
			goto handle_connect_error;
		}
		if((context->in_packet.command&0x0F) != 0x00){
			/* Reserved flags not set to 0, must disconnect. */
			rc = MOSQ_ERR_PROTOCOL;
			goto handle_connect_error;
		}
	}else{
		if(db.config->connection_messages == true){
			log__printf(NULL, MOSQ_LOG_INFO, "Invalid protocol \"%s\" in CONNECT from %s.",
					protocol_name, context->address);
		}
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}

	if(packet__read_byte(&context->in_packet, &connect_flags)){
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}
	if(context->protocol == mosq_p_mqtt311 || context->protocol == mosq_p_mqtt5){
		if((connect_flags & 0x01) != 0x00){
			rc = MOSQ_ERR_PROTOCOL;
			goto handle_connect_error;
		}
	}

	clean_start = (connect_flags & 0x02) >> 1;
	/* session_expiry_interval will be overriden if the properties are read later */
	if(clean_start == false && protocol_version != PROTOCOL_VERSION_v5){
		/* v3* has clean_start == false mean the session never expires */
		context->session_expiry_interval = UINT32_MAX;
	}else{
		context->session_expiry_interval = 0;
	}
	will = connect_flags & 0x04;
	will_qos = (connect_flags & 0x18) >> 3;
	if(will_qos == 3){
		log__printf(NULL, MOSQ_LOG_INFO, "Invalid Will QoS in CONNECT from %s.",
				context->address);
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}
	will_retain = ((connect_flags & 0x20) == 0x20);
	password_flag = connect_flags & 0x40;
	username_flag = connect_flags & 0x80;

	if(will && will_retain && db.config->retain_available == false){
		if(protocol_version == mosq_p_mqtt5){
			send__connack(context, 0, MQTT_RC_RETAIN_NOT_SUPPORTED, NULL);
		}
		rc = MOSQ_ERR_NOT_SUPPORTED;
		goto handle_connect_error;
	}

	if(packet__read_uint16(&context->in_packet, &(context->keepalive))){
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}

	if(protocol_version == PROTOCOL_VERSION_v5){
		rc = property__read_all(CMD_CONNECT, &context->in_packet, &properties);
		if(rc) goto handle_connect_error;
	}
	property__process_connect(context, &properties);

	if(will && will_qos > context->listener->max_qos){
		if(protocol_version == mosq_p_mqtt5){
			send__connack(context, 0, MQTT_RC_QOS_NOT_SUPPORTED, NULL);
		}
		rc = MOSQ_ERR_NOT_SUPPORTED;
		goto handle_connect_error;
	}

	if(mosquitto_property_read_string(properties, MQTT_PROP_AUTHENTICATION_METHOD, &context->auth_method, false)){
		mosquitto_property_read_binary(properties, MQTT_PROP_AUTHENTICATION_DATA, &auth_data, &auth_data_len, false);
	}

	mosquitto_property_free_all(&properties); /* FIXME - TEMPORARY UNTIL PROPERTIES PROCESSED */

	if(packet__read_string(&context->in_packet, &client_id, &slen)){
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}

	if(slen == 0){
		if(context->protocol == mosq_p_mqtt31){
			send__connack(context, 0, CONNACK_REFUSED_IDENTIFIER_REJECTED, NULL);
			rc = MOSQ_ERR_PROTOCOL;
			goto handle_connect_error;
		}else{ /* mqtt311/mqtt5 */
			mosquitto__free(client_id);
			client_id = NULL;

			if(db.config->per_listener_settings){
				allow_zero_length_clientid = context->listener->security_options.allow_zero_length_clientid;
			}else{
				allow_zero_length_clientid = db.config->security_options.allow_zero_length_clientid;
			}
			if((context->protocol == mosq_p_mqtt311 && clean_start == 0) || allow_zero_length_clientid == false){
				if(context->protocol == mosq_p_mqtt311){
					send__connack(context, 0, CONNACK_REFUSED_IDENTIFIER_REJECTED, NULL);
				}else{
					send__connack(context, 0, MQTT_RC_UNSPECIFIED, NULL);
				}
				rc = MOSQ_ERR_PROTOCOL;
				goto handle_connect_error;
			}else{
				if(db.config->per_listener_settings){
					client_id = client_id_gen(&slen, context->listener->security_options.auto_id_prefix, context->listener->security_options.auto_id_prefix_len);
				}else{
					client_id = client_id_gen(&slen, db.config->security_options.auto_id_prefix, db.config->security_options.auto_id_prefix_len);
				}
				if(!client_id){
					rc = MOSQ_ERR_NOMEM;
					goto handle_connect_error;
				}
				context->assigned_id = true;
			}
		}
	}

	/* clientid_prefixes check */
	if(db.config->clientid_prefixes){
		if(strncmp(db.config->clientid_prefixes, client_id, strlen(db.config->clientid_prefixes))){
			if(context->protocol == mosq_p_mqtt5){
				send__connack(context, 0, MQTT_RC_NOT_AUTHORIZED, NULL);
			}else{
				send__connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED, NULL);
			}
			rc = MOSQ_ERR_AUTH;
			goto handle_connect_error;
		}
	}

	if(will){
		rc = will__read(context, &will_struct, will_qos, will_retain);
		if(rc) goto handle_connect_error;
	}else{
		if(context->protocol == mosq_p_mqtt311 || context->protocol == mosq_p_mqtt5){
			if(will_qos != 0 || will_retain != 0){
				rc = MOSQ_ERR_PROTOCOL;
				goto handle_connect_error;
			}
		}
	}

	if(username_flag){
		rc = packet__read_string(&context->in_packet, &username, &slen);
		if(rc == MOSQ_ERR_NOMEM){
			rc = MOSQ_ERR_NOMEM;
			goto handle_connect_error;
		}else if(rc != MOSQ_ERR_SUCCESS){
			if(context->protocol == mosq_p_mqtt31){
				/* Username flag given, but no username. Ignore. */
				username_flag = 0;
			}else{
				rc = MOSQ_ERR_PROTOCOL;
				goto handle_connect_error;
			}
		}
	}else{
		if(context->protocol == mosq_p_mqtt311 || context->protocol == mosq_p_mqtt31){
			if(password_flag){
				/* username_flag == 0 && password_flag == 1 is forbidden */
				log__printf(NULL, MOSQ_LOG_ERR, "Protocol error from %s: password without username, closing connection.", client_id);
				rc = MOSQ_ERR_PROTOCOL;
				goto handle_connect_error;
			}
		}
	}
	if(password_flag){
		rc = packet__read_binary(&context->in_packet, (uint8_t **)&password, &slen);
		if(rc == MOSQ_ERR_NOMEM){
			rc = MOSQ_ERR_NOMEM;
			goto handle_connect_error;
		}else if(rc == MOSQ_ERR_PROTOCOL){
			if(context->protocol == mosq_p_mqtt31){
				/* Password flag given, but no password. Ignore. */
			}else{
				rc = MOSQ_ERR_PROTOCOL;
				goto handle_connect_error;
			}
		}
	}

	if(context->in_packet.pos != context->in_packet.remaining_length){
		/* Surplus data at end of packet, this must be an error. */
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}

	/* Once context->id is set, if we return from this function with an error
	 * we must make sure that context->id is freed and set to NULL, so that the
	 * client isn't erroneously removed from the by_id hash table. */
	context->id = client_id;
	client_id = NULL;

#ifdef WITH_TLS
	if(context->listener->ssl_ctx && (context->listener->use_identity_as_username || context->listener->use_subject_as_username)){
		/* Don't need the username or password if provided */
		mosquitto__free(username);
		username = NULL;
		mosquitto__free(password);
		password = NULL;

		if(!context->ssl){
			if(context->protocol == mosq_p_mqtt5){
				send__connack(context, 0, MQTT_RC_BAD_USERNAME_OR_PASSWORD, NULL);
			}else{
				send__connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD, NULL);
			}
			rc = MOSQ_ERR_AUTH;
			goto handle_connect_error;
		}
#ifdef FINAL_WITH_TLS_PSK
		if(context->listener->psk_hint){
			/* Client should have provided an identity to get this far. */
			if(!context->username){
				if(context->protocol == mosq_p_mqtt5){
					send__connack(context, 0, MQTT_RC_BAD_USERNAME_OR_PASSWORD, NULL);
				}else{
					send__connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD, NULL);
				}
				rc = MOSQ_ERR_AUTH;
				goto handle_connect_error;
			}
		}else{
#endif /* FINAL_WITH_TLS_PSK */
			client_cert = SSL_get_peer_certificate(context->ssl);
			if(!client_cert){
				if(context->protocol == mosq_p_mqtt5){
					send__connack(context, 0, MQTT_RC_BAD_USERNAME_OR_PASSWORD, NULL);
				}else{
					send__connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD, NULL);
				}
				rc = MOSQ_ERR_AUTH;
				goto handle_connect_error;
			}
			name = X509_get_subject_name(client_cert);
			if(!name){
				if(context->protocol == mosq_p_mqtt5){
					send__connack(context, 0, MQTT_RC_BAD_USERNAME_OR_PASSWORD, NULL);
				}else{
					send__connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD, NULL);
				}
				rc = MOSQ_ERR_AUTH;
				goto handle_connect_error;
			}
			if (context->listener->use_identity_as_username) { /* use_identity_as_username */
				i = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
				if(i == -1){
					if(context->protocol == mosq_p_mqtt5){
						send__connack(context, 0, MQTT_RC_BAD_USERNAME_OR_PASSWORD, NULL);
					}else{
						send__connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD, NULL);
					}
					rc = MOSQ_ERR_AUTH;
					goto handle_connect_error;
				}
				name_entry = X509_NAME_get_entry(name, i);
				if(name_entry){
					name_asn1 = X509_NAME_ENTRY_get_data(name_entry);
					if (name_asn1 == NULL) {
						if(context->protocol == mosq_p_mqtt5){
							send__connack(context, 0, MQTT_RC_BAD_USERNAME_OR_PASSWORD, NULL);
						}else{
							send__connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD, NULL);
						}
						rc = MOSQ_ERR_AUTH;
						goto handle_connect_error;
					}
#if OPENSSL_VERSION_NUMBER < 0x10100000L
					context->username = mosquitto__strdup((char *) ASN1_STRING_data(name_asn1));
#else
					context->username = mosquitto__strdup((char *) ASN1_STRING_get0_data(name_asn1));
#endif
					if(!context->username){
						if(context->protocol == mosq_p_mqtt5){
							send__connack(context, 0, MQTT_RC_SERVER_UNAVAILABLE, NULL);
						}else{
							send__connack(context, 0, CONNACK_REFUSED_SERVER_UNAVAILABLE, NULL);
						}
						rc = MOSQ_ERR_NOMEM;
						goto handle_connect_error;
					}
					/* Make sure there isn't an embedded NUL character in the CN */
					if ((size_t)ASN1_STRING_length(name_asn1) != strlen(context->username)) {
						if(context->protocol == mosq_p_mqtt5){
							send__connack(context, 0, MQTT_RC_BAD_USERNAME_OR_PASSWORD, NULL);
						}else{
							send__connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD, NULL);
						}
						rc = MOSQ_ERR_AUTH;
						goto handle_connect_error;
					}
				}
			} else { /* use_subject_as_username */
				subject_bio = BIO_new(BIO_s_mem());
				X509_NAME_print_ex(subject_bio, X509_get_subject_name(client_cert), 0, XN_FLAG_RFC2253);
				data_start = NULL;
				name_length = BIO_get_mem_data(subject_bio, &data_start);
				subject = mosquitto__malloc(sizeof(char)*(size_t)(name_length+1));
				if(!subject){
					BIO_free(subject_bio);
					rc = MOSQ_ERR_NOMEM;
					goto handle_connect_error;
				}
				memcpy(subject, data_start, (size_t)name_length);
				subject[name_length] = '\0';
				BIO_free(subject_bio);
				context->username = subject;
			}
			if(!context->username){
				rc = MOSQ_ERR_AUTH;
				goto handle_connect_error;
			}
			X509_free(client_cert);
			client_cert = NULL;
#ifdef FINAL_WITH_TLS_PSK
		}
#endif /* FINAL_WITH_TLS_PSK */
	}else
#endif /* WITH_TLS */
	{
		/* FIXME - these ensure the mosquitto_client_id() and
		 * mosquitto_client_username() functions work, but is hacky */
		context->username = username;
		context->password = password;
		username = NULL; /* Avoid free() in error: below. */
		password = NULL;
	}

	if(context->listener->use_username_as_clientid){
		if(context->username){
			mosquitto__free(context->id);
			context->id = mosquitto__strdup(context->username);
			if(!context->id){
				rc = MOSQ_ERR_NOMEM;
				goto handle_connect_error;
			}
		}else{
			if(context->protocol == mosq_p_mqtt5){
				send__connack(context, 0, MQTT_RC_NOT_AUTHORIZED, NULL);
			}else{
				send__connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED, NULL);
			}
			rc = MOSQ_ERR_AUTH;
			goto handle_connect_error;
		}
	}
	context->clean_start = clean_start;
	context->will = will_struct;
	will_struct = NULL;

	if(context->auth_method){
		rc = mosquitto_security_auth_start(context, false, auth_data, auth_data_len, &auth_data_out, &auth_data_out_len);
		mosquitto__free(auth_data);
		if(rc == MOSQ_ERR_SUCCESS){
			return connect__on_authorised(context, auth_data_out, auth_data_out_len);
		}else if(rc == MOSQ_ERR_AUTH_CONTINUE){
			mosquitto__set_state(context, mosq_cs_authenticating);
			rc = send__auth(context, MQTT_RC_CONTINUE_AUTHENTICATION, auth_data_out, auth_data_out_len);
			free(auth_data_out);
			return rc;
		}else{
			free(auth_data_out);
			will__clear(context);
			if(rc == MOSQ_ERR_AUTH){
				send__connack(context, 0, MQTT_RC_NOT_AUTHORIZED, NULL);
				mosquitto__free(context->id);
				context->id = NULL;
				return MOSQ_ERR_PROTOCOL;
			}else if(rc == MOSQ_ERR_NOT_SUPPORTED){
				/* Client has requested extended authentication, but we don't support it. */
				send__connack(context, 0, MQTT_RC_BAD_AUTHENTICATION_METHOD, NULL);
				mosquitto__free(context->id);
				context->id = NULL;
				return MOSQ_ERR_PROTOCOL;
			}else{
				mosquitto__free(context->id);
				context->id = NULL;
				return rc;
			}
		}
	}else{
#ifdef WITH_TLS
		if(context->listener->ssl_ctx && (context->listener->use_identity_as_username || context->listener->use_subject_as_username)){
			/* Authentication assumed to be cleared */
		}else
#endif
		{
			rc = mosquitto_unpwd_check(context);
			if(rc != MOSQ_ERR_SUCCESS){
				/* We must have context->id == NULL here so we don't later try and
				* remove the client from the by_id hash table */
				mosquitto__free(context->id);
				context->id = NULL;
			}
			switch(rc){
				case MOSQ_ERR_SUCCESS:
					break;
				case MOSQ_ERR_AUTH:
					if(context->protocol == mosq_p_mqtt5){
						send__connack(context, 0, MQTT_RC_NOT_AUTHORIZED, NULL);
					}else{
						send__connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED, NULL);
					}
					context__disconnect(context);
					rc = MOSQ_ERR_AUTH;
					goto handle_connect_error;
					break;
				default:
					context__disconnect(context);
					goto handle_connect_error;
					break;
			}
		}
		return connect__on_authorised(context, NULL, 0);
	}


handle_connect_error:
	mosquitto__free(auth_data);
	mosquitto__free(client_id);
	mosquitto__free(username);
	mosquitto__free(password);
	if(will_struct){
		mosquitto_property_free_all(&will_struct->properties);
		mosquitto__free(will_struct->msg.payload);
		mosquitto__free(will_struct->msg.topic);
		mosquitto__free(will_struct);
	}
#ifdef WITH_TLS
	if(client_cert) X509_free(client_cert);
#endif
	/* We return an error here which means the client is freed later on. */
	context->clean_start = true;
	context->session_expiry_interval = 0;
	return rc;
}
