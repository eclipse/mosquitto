/*
Copyright (c) 2009-2014 Roger Light <roger@atchoo.org>

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

#include <config.h>

#include <mosquitto_broker.h>
#include <mqtt3_protocol.h>
#include <memory_mosq.h>
#include <send_mosq.h>
#include <time_mosq.h>
#include <tls_mosq.h>
#include <util_mosq.h>

#ifdef WITH_UUID
#  include <uuid/uuid.h>
#endif

#ifdef WITH_WEBSOCKETS
#  include <libwebsockets.h>
#endif

#ifdef WITH_SYS_TREE
extern unsigned int g_connection_count;
#endif

static char *client_id_gen(struct mosquitto_db *db)
{
	char *client_id;
#ifdef WITH_UUID
	uuid_t uuid;
#else
	int i;
#endif

#ifdef WITH_UUID
	client_id = (char *)_mosquitto_calloc(37 + db->config->auto_id_prefix_len, sizeof(char));
	if(!client_id){
		return NULL;
	}
	if(db->config->auto_id_prefix){
		memcpy(client_id, db->config->auto_id_prefix, db->config->auto_id_prefix_len);
	}
	uuid_generate_random(uuid);
	uuid_unparse_lower(uuid, &client_id[db->config->auto_id_prefix_len]);
#else
	client_id = (char *)_mosquitto_calloc(65 + db->config->auto_id_prefix_len, sizeof(char));
	if(!client_id){
		return NULL;
	}
	if(db->config->auto_id_prefix){
		memcpy(client_id, db->config->auto_id_prefix, db->config->auto_id_prefix_len);
	}
	for(i=0; i<64; i++){
		client_id[i+db->config->auto_id_prefix_len] = (rand()%73)+48;
	}
	client_id[i] = '\0';
#endif
	return client_id;
}

int mqtt3_handle_connect(struct mosquitto_db *db, struct mosquitto *context)
{
	char *protocol_name = NULL;
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
	struct _mosquitto_acl_user *acl_tail;
	struct mosquitto_client_msg *msg_tail, *msg_prev;
	struct mosquitto *found_context;
	int slen;
	struct _mosquitto_subleaf *leaf;
	int i;
#ifdef WITH_TLS
	X509 *client_cert = NULL;
	X509_NAME *name;
	X509_NAME_ENTRY *name_entry;
#endif

#ifdef WITH_SYS_TREE
	g_connection_count++;
#endif

	/* Don't accept multiple CONNECT commands. */
	if(context->state != mosq_cs_new){
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}

	if(_mosquitto_read_string(&context->in_packet, &protocol_name)){
		rc = 1;
		goto handle_connect_error;
		return 1;
	}
	if(!protocol_name){
		rc = 3;
		goto handle_connect_error;
		return 3;
	}
	if(_mosquitto_read_byte(&context->in_packet, &protocol_version)){
		rc = 1;
		goto handle_connect_error;
		return 1;
	}
	if(!strcmp(protocol_name, PROTOCOL_NAME_v31)){
		if((protocol_version&0x7F) != PROTOCOL_VERSION_v31){
			if(db->config->connection_messages == true){
				_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Invalid protocol version %d in CONNECT from %s.",
						protocol_version, context->address);
			}
			_mosquitto_send_connack(context, 0, CONNACK_REFUSED_PROTOCOL_VERSION);
			_mosquitto_free(protocol_name);
			rc = MOSQ_ERR_PROTOCOL;
			goto handle_connect_error;
		}
		context->protocol = mosq_p_mqtt31;
	}else if(!strcmp(protocol_name, PROTOCOL_NAME_v311)){
		if((protocol_version&0x7F) != PROTOCOL_VERSION_v311){
			if(db->config->connection_messages == true){
				_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Invalid protocol version %d in CONNECT from %s.",
						protocol_version, context->address);
			}
			_mosquitto_send_connack(context, 0, CONNACK_REFUSED_PROTOCOL_VERSION);
			_mosquitto_free(protocol_name);
			rc = MOSQ_ERR_PROTOCOL;
			goto handle_connect_error;
		}
		if((context->in_packet.command&0x0F) != 0x00){
			/* Reserved flags not set to 0, must disconnect. */ 
			_mosquitto_free(protocol_name);
			rc = MOSQ_ERR_PROTOCOL;
			goto handle_connect_error;
		}
		context->protocol = mosq_p_mqtt311;
	}else{
		if(db->config->connection_messages == true){
			_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Invalid protocol \"%s\" in CONNECT from %s.",
					protocol_name, context->address);
		}
		_mosquitto_free(protocol_name);
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}
	_mosquitto_free(protocol_name);

	if(_mosquitto_read_byte(&context->in_packet, &connect_flags)){
		rc = 1;
		goto handle_connect_error;
	}
	clean_session = (connect_flags & 0x02) >> 1;
	will = connect_flags & 0x04;
	will_qos = (connect_flags & 0x18) >> 3;
	if(will_qos == 3){
		_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Invalid Will QoS in CONNECT from %s.",
				context->address);
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}
	will_retain = ((connect_flags & 0x20) == 0x20); // Temporary hack because MSVC<1800 doesn't have stdbool.h.
	password_flag = connect_flags & 0x40;
	username_flag = connect_flags & 0x80;

	if(_mosquitto_read_uint16(&context->in_packet, &(context->keepalive))){
		rc = 1;
		goto handle_connect_error;
	}

	if(_mosquitto_read_string(&context->in_packet, &client_id)){
		rc = 1;
		goto handle_connect_error;
	}

	slen = strlen(client_id);
	if(slen == 0){
		if(context->protocol == mosq_p_mqtt31){
			_mosquitto_send_connack(context, 0, CONNACK_REFUSED_IDENTIFIER_REJECTED);
			rc = MOSQ_ERR_PROTOCOL;
			goto handle_connect_error;
		}else{ /* mqtt311 */
			_mosquitto_free(client_id);
			client_id = NULL;

			if(clean_session == 0 || db->config->allow_zero_length_clientid == false){
				_mosquitto_send_connack(context, 0, CONNACK_REFUSED_IDENTIFIER_REJECTED);
				rc = MOSQ_ERR_PROTOCOL;
				goto handle_connect_error;
			}else{
				client_id = client_id_gen(db);
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
			_mosquitto_send_connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED);
			rc = 1;
			goto handle_connect_error;
		}
	}

	if(will){
		will_struct = _mosquitto_calloc(1, sizeof(struct mosquitto_message));
		if(!will_struct){
			rc = MOSQ_ERR_NOMEM;
			goto handle_connect_error;
		}
		if(_mosquitto_read_string(&context->in_packet, &will_topic)){
			rc = 1;
			goto handle_connect_error;
		}
		if(STREMPTY(will_topic)){
			rc = 1;
			goto handle_connect_error;
		}

		if(context->listener && context->listener->mount_point){
			slen = strlen(context->listener->mount_point) + strlen(will_topic) + 1;
			will_topic_mount = _mosquitto_malloc(slen+1);
			if(!will_topic_mount){
				rc = MOSQ_ERR_NOMEM;
				goto handle_connect_error;
			}
			snprintf(will_topic_mount, slen, "%s%s", context->listener->mount_point, will_topic);
			will_topic_mount[slen] = '\0';

			_mosquitto_free(will_topic);
			will_topic = will_topic_mount;
		}

		if(mosquitto_pub_topic_check(will_topic)){
			rc = 1;
			goto handle_connect_error;
		}

		if(_mosquitto_read_uint16(&context->in_packet, &will_payloadlen)){
			rc = 1;
			goto handle_connect_error;
		}
		if(will_payloadlen > 0){
			will_payload = _mosquitto_malloc(will_payloadlen);
			if(!will_payload){
				rc = 1;
				goto handle_connect_error;
			}

			rc = _mosquitto_read_bytes(&context->in_packet, will_payload, will_payloadlen);
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
		rc = _mosquitto_read_string(&context->in_packet, &username);
		if(rc == MOSQ_ERR_SUCCESS){
			if(password_flag){
				rc = _mosquitto_read_string(&context->in_packet, &password);
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

#ifdef WITH_TLS
	if(context->listener && context->listener->ssl_ctx && context->listener->use_identity_as_username){
		if(!context->ssl){
			_mosquitto_send_connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD);
			rc = 1;
			goto handle_connect_error;
		}
#ifdef REAL_WITH_TLS_PSK
		if(context->listener->psk_hint){
			/* Client should have provided an identity to get this far. */
			if(!context->username){
				_mosquitto_send_connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD);
				rc = 1;
				goto handle_connect_error;
			}
		}else{
#endif /* REAL_WITH_TLS_PSK */
			client_cert = SSL_get_peer_certificate(context->ssl);
			if(!client_cert){
				_mosquitto_send_connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD);
				rc = 1;
				goto handle_connect_error;
			}
			name = X509_get_subject_name(client_cert);
			if(!name){
				_mosquitto_send_connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD);
				rc = 1;
				goto handle_connect_error;
			}

			i = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
			if(i == -1){
				_mosquitto_send_connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD);
				rc = 1;
				goto handle_connect_error;
			}
			name_entry = X509_NAME_get_entry(name, i);
			context->username = _mosquitto_strdup((char *)ASN1_STRING_data(X509_NAME_ENTRY_get_data(name_entry)));
			if(!context->username){
				rc = 1;
				goto handle_connect_error;
			}
			X509_free(client_cert);
			client_cert = NULL;
#ifdef REAL_WITH_TLS_PSK
		}
#endif /* REAL_WITH_TLS_PSK */
	}else{
#endif /* WITH_TLS */
		if(username_flag){
			rc = mosquitto_unpwd_check(db, username, password);
			switch(rc){
				case MOSQ_ERR_SUCCESS:
					break;
				case MOSQ_ERR_AUTH:
					_mosquitto_send_connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED);
					mqtt3_context_disconnect(db, context);
					rc = 1;
					goto handle_connect_error;
					break;
				default:
					mqtt3_context_disconnect(db, context);
					rc = 1;
					goto handle_connect_error;
					break;
			}
			context->username = username;
			context->password = password;
			username = NULL; /* Avoid free() in error: below. */
			password = NULL;
		}

		if(!username_flag && db->config->allow_anonymous == false){
			_mosquitto_send_connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED);
			rc = 1;
			goto handle_connect_error;
		}
#ifdef WITH_TLS
	}
#endif

	if(context->listener && context->listener->use_username_as_clientid){
		if(context->username){
			_mosquitto_free(client_id);
			client_id = _mosquitto_strdup(context->username);
			if(!client_id){
				rc = MOSQ_ERR_NOMEM;
				goto handle_connect_error;
			}
		}else{
			_mosquitto_send_connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED);
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
			 * done in mqtt3_context_cleanup() below. */
			if(db->config->connection_messages == true){
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Client %s already connected, closing old connection.", client_id);
			}
		}

		if(context->protocol == mosq_p_mqtt311){
			if(clean_session == 0){
				connect_ack |= 0x01;
			}
		}

		context->clean_session = clean_session;

		if(context->clean_session == false && found_context->clean_session == false){
			if(found_context->msgs){
				context->msgs = found_context->msgs;
				found_context->msgs = NULL;
				mqtt3_db_message_reconnect_reset(db, context);
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
		found_context->state = mosq_cs_disconnecting;
		do_disconnect(db, found_context);
	}

	/* Associate user with its ACL, assuming we have ACLs loaded. */
	if(db->acl_list){
		acl_tail = db->acl_list;
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
				_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "New bridge connected from %s as %s (c%d, k%d, u'%s').", context->address, client_id, clean_session, context->keepalive, context->username);
			}else{
				_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "New bridge connected from %s as %s (c%d, k%d).", context->address, client_id, clean_session, context->keepalive);
			}
		}else{
			if(context->username){
				_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "New client connected from %s as %s (c%d, k%d, u'%s').", context->address, client_id, clean_session, context->keepalive, context->username);
			}else{
				_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "New client connected from %s as %s (c%d, k%d).", context->address, client_id, clean_session, context->keepalive);
			}
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

	/* Remove any queued messages that are no longer allowed through ACL,
	 * assuming a possible change of username. */
	msg_tail = context->msgs;
	msg_prev = NULL;
	while(msg_tail){
		if(msg_tail->direction == mosq_md_out){
			if(mosquitto_acl_check(db, context, msg_tail->store->topic, MOSQ_ACL_READ) != MOSQ_ERR_SUCCESS){
				mosquitto__db_msg_store_deref(db, &msg_tail->store);
				if(msg_prev){
					msg_prev->next = msg_tail->next;
					_mosquitto_free(msg_tail);
					msg_tail = msg_prev->next;
				}else{
					context->msgs = context->msgs->next;
					if(context->last_msg == msg_tail){
						context->last_msg = NULL;
					}
					_mosquitto_free(msg_tail);
					msg_tail = context->msgs;
				}
			}else{
				msg_prev = msg_tail;
				msg_tail = msg_tail->next;
			}
		}else{
			msg_prev = msg_tail;
			msg_tail = msg_tail->next;
		}
	}

	HASH_ADD_KEYPTR(hh_id, db->contexts_by_id, context->id, strlen(context->id), context);

#ifdef WITH_PERSISTENCE
	if(!clean_session){
		db->persistence_changes++;
	}
#endif
	context->state = mosq_cs_connected;
	return _mosquitto_send_connack(context, connect_ack, CONNACK_ACCEPTED);

handle_connect_error:
	if(client_id) _mosquitto_free(client_id);
	if(username) _mosquitto_free(username);
	if(password) _mosquitto_free(password);
	if(will_payload) _mosquitto_free(will_payload);
	if(will_topic) _mosquitto_free(will_topic);
	if(will_struct) _mosquitto_free(will_struct);
#ifdef WITH_TLS
	if(client_cert) X509_free(client_cert);
#endif
	/* We return an error here which means the client is freed later on. */
	return rc;
}

int mqtt3_handle_disconnect(struct mosquitto_db *db, struct mosquitto *context)
{
	if(!context){
		return MOSQ_ERR_INVAL;
	}
	if(context->in_packet.remaining_length != 0){
		return MOSQ_ERR_PROTOCOL;
	}
	_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Received DISCONNECT from %s", context->id);
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


int mqtt3_handle_subscribe(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc = 0;
	int rc2;
	uint16_t mid;
	char *sub;
	uint8_t qos;
	uint8_t *payload = NULL, *tmp_payload;
	uint32_t payloadlen = 0;
	int len;
	char *sub_mount;

	if(!context) return MOSQ_ERR_INVAL;
	_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Received SUBSCRIBE from %s", context->id);
	/* FIXME - plenty of potential for memory leaks here */

	if(context->protocol == mosq_p_mqtt311){
		if((context->in_packet.command&0x0F) != 0x02){
			return MOSQ_ERR_PROTOCOL;
		}
	}
	if(_mosquitto_read_uint16(&context->in_packet, &mid)) return 1;

	while(context->in_packet.pos < context->in_packet.remaining_length){
		sub = NULL;
		if(_mosquitto_read_string(&context->in_packet, &sub)){
			if(payload) _mosquitto_free(payload);
			return 1;
		}

		if(sub){
			if(!strlen(sub)){
				_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Empty subscription string from %s, disconnecting.",
					context->address);
				_mosquitto_free(sub);
				if(payload) _mosquitto_free(payload);
				return 1;
			}
			if(mosquitto_sub_topic_check(sub)){
				_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Invalid subscription string from %s, disconnecting.",
					context->address);
				_mosquitto_free(sub);
				if(payload) _mosquitto_free(payload);
				return 1;
			}

			if(_mosquitto_read_byte(&context->in_packet, &qos)){
				_mosquitto_free(sub);
				if(payload) _mosquitto_free(payload);
				return 1;
			}
			if(qos > 2){
				_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Invalid QoS in subscription command from %s, disconnecting.",
					context->address);
				_mosquitto_free(sub);
				if(payload) _mosquitto_free(payload);
				return 1;
			}
			if(context->listener && context->listener->mount_point){
				len = strlen(context->listener->mount_point) + strlen(sub) + 1;
				sub_mount = _mosquitto_malloc(len+1);
				if(!sub_mount){
					_mosquitto_free(sub);
					if(payload) _mosquitto_free(payload);
					return MOSQ_ERR_NOMEM;
				}
				snprintf(sub_mount, len, "%s%s", context->listener->mount_point, sub);
				sub_mount[len] = '\0';

				_mosquitto_free(sub);
				sub = sub_mount;

			}
			_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "\t%s (QoS %d)", sub, qos);

#if 0
			/* FIXME
			 * This section has been disabled temporarily. mosquitto_acl_check
			 * calls mosquitto_topic_matches_sub, which can't cope with
			 * checking subscriptions that have wildcards against ACLs that
			 * have wildcards. Bug #1374291 is related.
			 *
			 * It's a very difficult problem when an ACL looks like foo/+/bar
			 * and a subscription request to foo/# is made.
			 *
			 * This should be changed to using MOSQ_ACL_SUBSCRIPTION in the
			 * future anyway.
			 */
			if(context->protocol == mosq_p_mqtt311){
				rc = mosquitto_acl_check(db, context, sub, MOSQ_ACL_READ);
				switch(rc){
					case MOSQ_ERR_SUCCESS:
						break;
					case MOSQ_ERR_ACL_DENIED:
						qos = 0x80;
						break;
					default:
						_mosquitto_free(sub);
						return rc;
				}
			}
#endif

			if(qos != 0x80){
				rc2 = mqtt3_sub_add(db, context, sub, qos, &db->subs);
				if(rc2 == MOSQ_ERR_SUCCESS){
					if(mqtt3_retain_queue(db, context, sub, qos)) rc = 1;
				}else if(rc2 != -1){
					rc = rc2;
				}
				_mosquitto_log_printf(NULL, MOSQ_LOG_SUBSCRIBE, "%s %d %s", context->id, qos, sub);
			}
			_mosquitto_free(sub);

			tmp_payload = _mosquitto_realloc(payload, payloadlen + 1);
			if(tmp_payload){
				payload = tmp_payload;
				payload[payloadlen] = qos;
				payloadlen++;
			}else{
				if(payload) _mosquitto_free(payload);

				return MOSQ_ERR_NOMEM;
			}
		}
	}

	if(context->protocol == mosq_p_mqtt311){
		if(payloadlen == 0){
			/* No subscriptions specified, protocol error. */
			return MOSQ_ERR_PROTOCOL;
		}
	}
	if(_mosquitto_send_suback(context, mid, payloadlen, payload)) rc = 1;
	_mosquitto_free(payload);
	
#ifdef WITH_PERSISTENCE
	db->persistence_changes++;
#endif

	return rc;
}

int mqtt3_handle_unsubscribe(struct mosquitto_db *db, struct mosquitto *context)
{
	uint16_t mid;
	char *sub;

	if(!context) return MOSQ_ERR_INVAL;
	_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Received UNSUBSCRIBE from %s", context->id);

	if(context->protocol == mosq_p_mqtt311){
		if((context->in_packet.command&0x0F) != 0x02){
			return MOSQ_ERR_PROTOCOL;
		}
	}
	if(_mosquitto_read_uint16(&context->in_packet, &mid)) return 1;

	while(context->in_packet.pos < context->in_packet.remaining_length){
		sub = NULL;
		if(_mosquitto_read_string(&context->in_packet, &sub)){
			return 1;
		}

		if(sub){
			if(!strlen(sub)){
				_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Empty unsubscription string from %s, disconnecting.",
					context->id);
				_mosquitto_free(sub);
				return 1;
			}
			if(mosquitto_sub_topic_check(sub)){
				_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Invalid unsubscription string from %s, disconnecting.",
					context->id);
				_mosquitto_free(sub);
				return 1;
			}

			_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "\t%s", sub);
			mqtt3_sub_remove(db, context, sub, &db->subs);
			_mosquitto_log_printf(NULL, MOSQ_LOG_UNSUBSCRIBE, "%s %s", context->id, sub);
			_mosquitto_free(sub);
		}
	}
#ifdef WITH_PERSISTENCE
	db->persistence_changes++;
#endif

	return _mosquitto_send_command_with_mid(context, UNSUBACK, mid, false);
}

