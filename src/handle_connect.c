/*
Copyright (c) 2009-2018 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include <stdio.h>
#include <string.h>

#include "config.h"

#include "mosquitto_broker_internal.h"
#include "mqtt3_protocol.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "send_mosq.h"
#include "sys_tree.h"
#include "time_mosq.h"
#include "tls_mosq.h"
#include "util_mosq.h"

#ifdef WITH_UUID
#  include <uuid/uuid.h>
#endif

#ifdef WITH_WEBSOCKETS
#  include <libwebsockets.h>
#endif

static char *client_id_gen(struct mosquitto_db *db, int *idlen, const char *auto_id_prefix, int auto_id_prefix_len)
{
	char *client_id;
#ifdef WITH_UUID
	uuid_t uuid;
#else
	int i;
#endif

#ifdef WITH_UUID
	*idlen = 36 + auto_id_prefix_len;
#else
	*idlen = 64 + auto_id_prefix_len;
#endif

	client_id = (char *)mosquitto__calloc((*idlen) + 1, sizeof(char));
	if(!client_id){
		return NULL;
	}
	if(auto_id_prefix){
		memcpy(client_id, auto_id_prefix, auto_id_prefix_len);
	}


#ifdef WITH_UUID
	uuid_generate_random(uuid);
	uuid_unparse_lower(uuid, &client_id[auto_id_prefix_len]);
#else
	for(i=0; i<64; i++){
		client_id[i+auto_id_prefix_len] = (rand()%73)+48;
	}
	client_id[i] = '\0';
#endif
	return client_id;
}

/* Remove any queued messages that are no longer allowed through ACL,
 * assuming a possible change of username. */
void connection_check_acl(struct mosquitto_db *db, struct mosquitto *context, struct mosquitto_client_msg **msgs)
{
	struct mosquitto_client_msg *msg_tail, *msg_prev;

	msg_tail = *msgs;
	msg_prev = NULL;
	while(msg_tail){
		if(msg_tail->direction == mosq_md_out){
			if(mosquitto_acl_check(db, context, msg_tail->store->topic, MOSQ_ACL_READ) != MOSQ_ERR_SUCCESS){
				db__msg_store_deref(db, &msg_tail->store);
				if(msg_prev){
					msg_prev->next = msg_tail->next;
					mosquitto__free(msg_tail);
					msg_tail = msg_prev->next;
				}else{
					*msgs = (*msgs)->next;
					mosquitto__free(msg_tail);
					msg_tail = (*msgs);
				}
				// XXX: why it does not update last_msg if msg_tail was the last message ?
			}else{
				msg_prev = msg_tail;
				msg_tail = msg_tail->next;
			}
		}else{
			msg_prev = msg_tail;
			msg_tail = msg_tail->next;
		}
	}
}

int handle__connect(struct mosquitto_db *db, struct mosquitto *context)
{
	char protocol_name[7];
	uint8_t protocol_version;
	uint8_t connect_flags;
	uint8_t connect_ack = 0;
	char *client_id = NULL;
	char *will_payload = NULL, *will_topic = NULL;
	char *will_topic_mount;
	uint16_t will_payloadlen;
	struct mosquitto_message *will_struct = NULL;
	uint8_t will, will_retain, will_qos, clean_session;
	uint8_t username_flag, password_flag;
	char *username = NULL, *password = NULL;
	int rc;
	struct mosquitto__acl_user *acl_tail;
	struct mosquitto *found_context;
	int slen;
	uint16_t slen16;
	struct mosquitto__subleaf *leaf;
	int i;
	struct mosquitto__security_options *security_opts;
#ifdef WITH_TLS
	X509 *client_cert = NULL;
	X509_NAME *name;
	X509_NAME_ENTRY *name_entry;
#endif

	G_CONNECTION_COUNT_INC();

	if(!context->listener){
		return MOSQ_ERR_INVAL;
	}

	/* Don't accept multiple CONNECT commands. */
	if(context->state != mosq_cs_new){
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}

	/* Read protocol name as length then bytes rather than with read_string
	 * because the length is fixed and we can check that. Removes the need
	 * for another malloc as well. */
	if(packet__read_uint16(&context->in_packet, &slen16)){
		rc = 1;
		goto handle_connect_error;
	}
	slen = slen16;
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
		rc = 1;
		goto handle_connect_error;
	}
	if(!strcmp(protocol_name, PROTOCOL_NAME_v31)){
		if((protocol_version&0x7F) != PROTOCOL_VERSION_v31){
			if(db->config->connection_messages == true){
				log__printf(NULL, MOSQ_LOG_INFO, "Invalid protocol version %d in CONNECT from %s.",
						protocol_version, context->address);
			}
			send__connack(context, 0, CONNACK_REFUSED_PROTOCOL_VERSION);
			rc = MOSQ_ERR_PROTOCOL;
			goto handle_connect_error;
		}
		context->protocol = mosq_p_mqtt31;
	}else if(!strcmp(protocol_name, PROTOCOL_NAME_v311)){
		if((protocol_version&0x7F) != PROTOCOL_VERSION_v311){
			if(db->config->connection_messages == true){
				log__printf(NULL, MOSQ_LOG_INFO, "Invalid protocol version %d in CONNECT from %s.",
						protocol_version, context->address);
			}
			send__connack(context, 0, CONNACK_REFUSED_PROTOCOL_VERSION);
			rc = MOSQ_ERR_PROTOCOL;
			goto handle_connect_error;
		}
		if((context->in_packet.command&0x0F) != 0x00){
			/* Reserved flags not set to 0, must disconnect. */
			rc = MOSQ_ERR_PROTOCOL;
			goto handle_connect_error;
		}
		context->protocol = mosq_p_mqtt311;
	}else{
		if(db->config->connection_messages == true){
			log__printf(NULL, MOSQ_LOG_INFO, "Invalid protocol \"%s\" in CONNECT from %s.",
					protocol_name, context->address);
		}
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}

	if(packet__read_byte(&context->in_packet, &connect_flags)){
		rc = 1;
		goto handle_connect_error;
	}
	if(context->protocol == mosq_p_mqtt311){
		if((connect_flags & 0x01) != 0x00){
			rc = MOSQ_ERR_PROTOCOL;
			goto handle_connect_error;
		}
	}

	clean_session = (connect_flags & 0x02) >> 1;
	will = connect_flags & 0x04;
	will_qos = (connect_flags & 0x18) >> 3;
	if(will_qos == 3){
		log__printf(NULL, MOSQ_LOG_INFO, "Invalid Will QoS in CONNECT from %s.",
				context->address);
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}
	will_retain = ((connect_flags & 0x20) == 0x20); // Temporary hack because MSVC<1800 doesn't have stdbool.h.
	password_flag = connect_flags & 0x40;
	username_flag = connect_flags & 0x80;

	if(packet__read_uint16(&context->in_packet, &(context->keepalive))){
		rc = 1;
		goto handle_connect_error;
	}

	if(packet__read_string(&context->in_packet, &client_id, &slen)){
		rc = 1;
		goto handle_connect_error;
	}

	if(slen == 0){
		if(context->protocol == mosq_p_mqtt31){
			send__connack(context, 0, CONNACK_REFUSED_IDENTIFIER_REJECTED);
			rc = MOSQ_ERR_PROTOCOL;
			goto handle_connect_error;
		}else{ /* mqtt311 */
			mosquitto__free(client_id);
			client_id = NULL;

			bool allow_zero_length_clientid;
			if(db->config->per_listener_settings){
				allow_zero_length_clientid = context->listener->security_options.allow_zero_length_clientid;
			}else{
				allow_zero_length_clientid = db->config->security_options.allow_zero_length_clientid;
			}
			if(clean_session == 0 || allow_zero_length_clientid == false){
				send__connack(context, 0, CONNACK_REFUSED_IDENTIFIER_REJECTED);
				rc = MOSQ_ERR_PROTOCOL;
				goto handle_connect_error;
			}else{
				if(db->config->per_listener_settings){
					client_id = client_id_gen(db, &slen, context->listener->security_options.auto_id_prefix, context->listener->security_options.auto_id_prefix_len);
				}else{
					client_id = client_id_gen(db, &slen, db->config->security_options.auto_id_prefix, db->config->security_options.auto_id_prefix_len);
				}
				if(!client_id){
					rc = MOSQ_ERR_NOMEM;
					goto handle_connect_error;
				}
			}
		}
	}

	/* clientid_prefixes check */
	if(db->config->clientid_prefixes){
		if(strncmp(db->config->clientid_prefixes, client_id, strlen(db->config->clientid_prefixes))){
			send__connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED);
			rc = 1;
			goto handle_connect_error;
		}
	}

	if(mosquitto_validate_utf8(client_id, slen) != MOSQ_ERR_SUCCESS){
		rc = 1;
		goto handle_connect_error;
	}

	if(will){
		will_struct = mosquitto__calloc(1, sizeof(struct mosquitto_message));
		if(!will_struct){
			rc = MOSQ_ERR_NOMEM;
			goto handle_connect_error;
		}
		if(packet__read_string(&context->in_packet, &will_topic, &slen)){
			rc = 1;
			goto handle_connect_error;
		}
		if(!slen){
			rc = 1;
			goto handle_connect_error;
		}
		if(mosquitto_validate_utf8(will_topic, slen)){
			log__printf(NULL, MOSQ_LOG_INFO,
					"Malformed UTF-8 in will topic string from %s, disconnecting.",
					client_id);

			rc = 1;
			goto handle_connect_error;
		}

		if(context->listener->mount_point){
			slen = strlen(context->listener->mount_point) + strlen(will_topic) + 1;
			will_topic_mount = mosquitto__malloc(slen+1);
			if(!will_topic_mount){
				rc = MOSQ_ERR_NOMEM;
				goto handle_connect_error;
			}
			snprintf(will_topic_mount, slen, "%s%s", context->listener->mount_point, will_topic);
			will_topic_mount[slen] = '\0';

			mosquitto__free(will_topic);
			will_topic = will_topic_mount;
		}

		if(mosquitto_pub_topic_check(will_topic)){
			rc = 1;
			goto handle_connect_error;
		}

		if(packet__read_uint16(&context->in_packet, &will_payloadlen)){
			rc = 1;
			goto handle_connect_error;
		}
		if(will_payloadlen > 0){
			will_payload = mosquitto__malloc(will_payloadlen);
			if(!will_payload){
				rc = 1;
				goto handle_connect_error;
			}

			rc = packet__read_bytes(&context->in_packet, will_payload, will_payloadlen);
			if(rc){
				rc = 1;
				goto handle_connect_error;
			}
		}
	}else{
		if(context->protocol == mosq_p_mqtt311){
			if(will_qos != 0 || will_retain != 0){
				rc = MOSQ_ERR_PROTOCOL;
				goto handle_connect_error;
			}
		}
	}

	if(username_flag){
		rc = packet__read_string(&context->in_packet, &username, &slen);
		if(rc == MOSQ_ERR_SUCCESS){
			if(mosquitto_validate_utf8(username, slen) != MOSQ_ERR_SUCCESS){
				rc = MOSQ_ERR_PROTOCOL;
				goto handle_connect_error;
			}

			if(password_flag){
				rc = packet__read_string(&context->in_packet, &password, &slen);
				if(rc == MOSQ_ERR_NOMEM){
					rc = MOSQ_ERR_NOMEM;
					goto handle_connect_error;
				}else if(rc == MOSQ_ERR_PROTOCOL){
					if(context->protocol == mosq_p_mqtt31){
						/* Password flag given, but no password. Ignore. */
						password_flag = 0;
					}else if(context->protocol == mosq_p_mqtt311){
						rc = MOSQ_ERR_PROTOCOL;
						goto handle_connect_error;
					}
				}
			}
		}else if(rc == MOSQ_ERR_NOMEM){
			rc = MOSQ_ERR_NOMEM;
			goto handle_connect_error;
		}else{
			if(context->protocol == mosq_p_mqtt31){
				/* Username flag given, but no username. Ignore. */
				username_flag = 0;
			}else if(context->protocol == mosq_p_mqtt311){
				rc = MOSQ_ERR_PROTOCOL;
				goto handle_connect_error;
			}
		}
	}else{
		if(context->protocol == mosq_p_mqtt311){
			if(password_flag){
				/* username_flag == 0 && password_flag == 1 is forbidden */
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

#ifdef WITH_TLS
	if(context->listener && context->listener->ssl_ctx && (context->listener->use_identity_as_username || context->listener->use_subject_as_username)){
		/* Don't need the username or password if provided */
		mosquitto__free(username);
		username = NULL;
		mosquitto__free(password);
		password = NULL;

		if(!context->ssl){
			send__connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD);
			rc = 1;
			goto handle_connect_error;
		}
#ifdef WITH_TLS_PSK
		if(context->listener->psk_hint){
			/* Client should have provided an identity to get this far. */
			if(!context->username){
				send__connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD);
				rc = 1;
				goto handle_connect_error;
			}
		}else{
#endif /* WITH_TLS_PSK */
			client_cert = SSL_get_peer_certificate(context->ssl);
			if(!client_cert){
				send__connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD);
				rc = 1;
				goto handle_connect_error;
			}
			name = X509_get_subject_name(client_cert);
			if(!name){
				send__connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD);
				rc = 1;
				goto handle_connect_error;
			}
			if (context->listener->use_identity_as_username) { //use_identity_as_username
				i = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
				if(i == -1){
					send__connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD);
					rc = 1;
					goto handle_connect_error;
				}
				name_entry = X509_NAME_get_entry(name, i);
				if(name_entry){
					context->username = mosquitto__strdup((char *)X509_NAME_ENTRY_get_data(name_entry));
				}
			} else { // use_subject_as_username
				BIO *subject_bio = BIO_new(BIO_s_mem());
				X509_NAME_print_ex(subject_bio, X509_get_subject_name(client_cert), 0, XN_FLAG_RFC2253);
				char *data_start = NULL;
				long name_length = BIO_get_mem_data(subject_bio, &data_start);
				char *subject = mosquitto__malloc(sizeof(char)*name_length+1);
				if(!subject){
					BIO_free(subject_bio);
					rc = MOSQ_ERR_NOMEM;
					goto handle_connect_error;
				}
				memcpy(subject, data_start, name_length);
				subject[name_length] = '\0';
				BIO_free(subject_bio);
				context->username = subject;
			}
			if(!context->username){
				rc = 1;
				goto handle_connect_error;
			}
			X509_free(client_cert);
			client_cert = NULL;
#ifdef WITH_TLS_PSK
		}
#endif /* WITH_TLS_PSK */
	}else{
#endif /* WITH_TLS */
		if(username_flag){
			rc = mosquitto_unpwd_check(db, context, username, password);
			switch(rc){
				case MOSQ_ERR_SUCCESS:
					break;
				case MOSQ_ERR_AUTH:
					send__connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED);
					context__disconnect(db, context);
					rc = 1;
					goto handle_connect_error;
					break;
				default:
					context__disconnect(db, context);
					rc = 1;
					goto handle_connect_error;
					break;
			}
			context->username = username;
			context->password = password;
			username = NULL; /* Avoid free() in error: below. */
			password = NULL;
		}

		if(!username_flag){
			if((db->config->per_listener_settings && context->listener->security_options.allow_anonymous == false)
					|| (!db->config->per_listener_settings && db->config->security_options.allow_anonymous == false)){

				send__connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED);
				rc = 1;
				goto handle_connect_error;
			}
		}
#ifdef WITH_TLS
	}
#endif

	if(context->listener && context->listener->use_username_as_clientid){
		if(context->username){
			mosquitto__free(client_id);
			client_id = mosquitto__strdup(context->username);
			if(!client_id){
				rc = MOSQ_ERR_NOMEM;
				goto handle_connect_error;
			}
		}else{
			send__connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED);
			rc = 1;
			goto handle_connect_error;
		}
	}

	/* Find if this client already has an entry. This must be done *after* any security checks. */
	HASH_FIND(hh_id, db->contexts_by_id, client_id, strlen(client_id), found_context);
	if(found_context){
		/* Found a matching client */
		if(found_context->sock == INVALID_SOCKET){
			/* Client is reconnecting after a disconnect */
			/* FIXME - does anything need to be done here? */
		}else{
			/* Client is already connected, disconnect old version. This is
			 * done in context__cleanup() below. */
			if(db->config->connection_messages == true){
				log__printf(NULL, MOSQ_LOG_ERR, "Client %s already connected, closing old connection.", client_id);
			}
		}

		if(context->protocol == mosq_p_mqtt311){
			if(clean_session == 0){
				connect_ack |= 0x01;
			}
		}

		context->clean_session = clean_session;

		if(context->clean_session == false && found_context->clean_session == false){
			if(found_context->inflight_msgs || found_context->queued_msgs){
				context->inflight_msgs = found_context->inflight_msgs;
				context->queued_msgs = found_context->queued_msgs;
				found_context->inflight_msgs = NULL;
				found_context->queued_msgs = NULL;
				db__message_reconnect_reset(db, context);
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

		found_context->clean_session = true;
		found_context->state = mosq_cs_expiring;
		do_disconnect(db, found_context);
	}

	/* Associate user with its ACL, assuming we have ACLs loaded. */
	if(db->config->per_listener_settings){
		if(!context->listener){
			return 1;
		}
		security_opts = &context->listener->security_options;
	}else{
		security_opts = &db->config->security_options;
	}

	if(security_opts->acl_list){
		acl_tail = security_opts->acl_list;
		while(acl_tail){
			if(context->username){
				if(acl_tail->username && !strcmp(context->username, acl_tail->username)){
					context->acl_list = acl_tail;
					break;
				}
			}else{
				if(acl_tail->username == NULL){
					context->acl_list = acl_tail;
					break;
				}
			}
			acl_tail = acl_tail->next;
		}
	}else{
		context->acl_list = NULL;
	}


	if(will_struct){
		context->will = will_struct;
		context->will->topic = will_topic;
		if(will_payload){
			context->will->payload = will_payload;
			context->will->payloadlen = will_payloadlen;
		}else{
			context->will->payload = NULL;
			context->will->payloadlen = 0;
		}
		context->will->qos = will_qos;
		context->will->retain = will_retain;
	}

	if(db->config->connection_messages == true){
		if(context->is_bridge){
			if(context->username){
				log__printf(NULL, MOSQ_LOG_NOTICE, "New bridge connected from %s as %s (c%d, k%d, u'%s').", context->address, client_id, clean_session, context->keepalive, context->username);
			}else{
				log__printf(NULL, MOSQ_LOG_NOTICE, "New bridge connected from %s as %s (c%d, k%d).", context->address, client_id, clean_session, context->keepalive);
			}
		}else{
			if(context->username){
				log__printf(NULL, MOSQ_LOG_NOTICE, "New client connected from %s as %s (c%d, k%d, u'%s').", context->address, client_id, clean_session, context->keepalive, context->username);
			}else{
				log__printf(NULL, MOSQ_LOG_NOTICE, "New client connected from %s as %s (c%d, k%d).", context->address, client_id, clean_session, context->keepalive);
			}
		}

		if(context->will) {
			log__printf(NULL, MOSQ_LOG_DEBUG, "Will message specified (%ld bytes) (r%d, q%d).", (long)context->will->payloadlen, context->will->retain, context->will->qos);
			log__printf(NULL, MOSQ_LOG_DEBUG, "\t%s", context->will->topic);
		} else {
			log__printf(NULL, MOSQ_LOG_DEBUG, "No will message specified.");
		}
	}

	context->id = client_id;
	client_id = NULL;
	context->clean_session = clean_session;
	context->ping_t = 0;
	context->is_dropping = false;
	if((protocol_version&0x80) == 0x80){
		context->is_bridge = true;
	}

	connection_check_acl(db, context, &context->inflight_msgs);
	connection_check_acl(db, context, &context->queued_msgs);

	HASH_ADD_KEYPTR(hh_id, db->contexts_by_id, context->id, strlen(context->id), context);

#ifdef WITH_PERSISTENCE
	if(!clean_session){
		db->persistence_changes++;
	}
#endif
	context->state = mosq_cs_connected;
	return send__connack(context, connect_ack, CONNACK_ACCEPTED);

handle_connect_error:
	mosquitto__free(client_id);
	mosquitto__free(username);
	mosquitto__free(password);
	mosquitto__free(will_payload);
	mosquitto__free(will_topic);
	mosquitto__free(will_struct);
#ifdef WITH_TLS
	if(client_cert) X509_free(client_cert);
#endif
	/* We return an error here which means the client is freed later on. */
	return rc;
}

int handle__disconnect(struct mosquitto_db *db, struct mosquitto *context)
{
	if(!context){
		return MOSQ_ERR_INVAL;
	}
	if(context->in_packet.remaining_length != 0){
		return MOSQ_ERR_PROTOCOL;
	}
	log__printf(NULL, MOSQ_LOG_DEBUG, "Received DISCONNECT from %s", context->id);
	if(context->protocol == mosq_p_mqtt311){
		if((context->in_packet.command&0x0F) != 0x00){
			do_disconnect(db, context);
			return MOSQ_ERR_PROTOCOL;
		}
	}
	context->state = mosq_cs_disconnecting;
	do_disconnect(db, context);
	return MOSQ_ERR_SUCCESS;
}
