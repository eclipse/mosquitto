/*
Copyright (c) 2009-2016 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

Contributors:
   Roger Light - initial implementation and documentation.
   Tatsuzo Osawa - Add mqtt version 5.
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

static char *client_id_gen(struct mosquitto_db *db)
{
	char *client_id;
#ifdef WITH_UUID
	uuid_t uuid;
#else
	int i;
#endif

#ifdef WITH_UUID
	client_id = (char *)mosquitto__calloc(37 + db->config->auto_id_prefix_len, sizeof(char));
	if(!client_id){
		return NULL;
	}
	if(db->config->auto_id_prefix){
		memcpy(client_id, db->config->auto_id_prefix, db->config->auto_id_prefix_len);
	}
	uuid_generate_random(uuid);
	uuid_unparse_lower(uuid, &client_id[db->config->auto_id_prefix_len]);
#else
	client_id = (char *)mosquitto__calloc(65 + db->config->auto_id_prefix_len, sizeof(char));
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
	struct mosquitto__acl_user *acl_tail;
	struct mosquitto *found_context;
	int slen;
	struct mosquitto__subleaf *leaf;
	int i;
	struct mosquitto_v5_property property;
#ifdef WITH_TLS
	X509 *client_cert = NULL;
	X509_NAME *name;
	X509_NAME_ENTRY *name_entry;
#endif

	G_CONNECTION_COUNT_INC();

	/* Don't accept multiple CONNECT commands. */
	if(context->state != mosq_cs_new){
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}

	if(packet__read_string(&context->in_packet, &protocol_name)){
		rc = 1;
		goto handle_connect_error;
		return 1;
	}
	if(!protocol_name){
		rc = 3;
		goto handle_connect_error;
		return 3;
	}
	if(packet__read_byte(&context->in_packet, &protocol_version)){
		rc = 1;
		goto handle_connect_error;
		return 1;
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
		if(((protocol_version&0x7F) != PROTOCOL_VERSION_v311) && ((protocol_version&0x7F) != PROTOCOL_VERSION_v5)){
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
		if((protocol_version&0x7F) == PROTOCOL_VERSION_v311){
			context->protocol = mosq_p_mqtt311;
		}else{
			context->protocol = mosq_p_mqtt5;
			memset(&property, 0, sizeof(struct mosquitto_v5_property));
			if(context__current_property_init(context)){
				rc = MOSQ_ERR_NOMEM;
				goto handle_connect_error;
			}
		}
	}else{
		if(db->config->connection_messages == true){
			log__printf(NULL, MOSQ_LOG_INFO, "Invalid protocol \"%s\" in CONNECT from %s.",
					protocol_name, context->address);
		}
		rc = MOSQ_ERR_PROTOCOL;
		goto handle_connect_error;
	}
	mosquitto__free(protocol_name);
	protocol_name = NULL;

	if(packet__read_byte(&context->in_packet, &connect_flags)){
		rc = 1;
		goto handle_connect_error;
	}
	if((context->protocol == mosq_p_mqtt311)||(context->protocol == mosq_p_mqtt5)){
		if((connect_flags & 0x01) != 0x00){
			rc = MOSQ_ERR_PROTOCOL;
			goto handle_connect_error;
		}
	}

	clean_session = (connect_flags & 0x02) >> 1; // called clean_start for v5
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

	// Read and parse connect v5 property
	if(context->protocol == mosq_p_mqtt5){
		rc = packet__read_property(context, &context->in_packet, &property, CONNECT);
		if(rc != MQTT5_RC_SUCCESS){
			goto handle_connect_error;
		}
		// Session_expiry_interval should be implimented later.
		context->is_session_expiry_interval = property.is_session_expiry_interval;
		if(property.is_session_expiry_interval){
			context->session_expiry_interval = property.session_expiry_interval;
		}
		// Will_delay_interval should be implimented later.
		if(property.is_will_delay_interval){
			context->will_delay_interval = property.will_delay_interval;
		}else{
			context->will_delay_interval = 0;
		}
		// Receive_maximum should be implimented later.
		if(property.is_receive_maximum){
			if(property.receive_maximum == 0){
				log__printf(NULL, MOSQ_LOG_INFO, "Invalid v5 property: RECEIVE_MAXIMUM = 0");
				rc = MQTT5_RC_PROTOCOL_ERROR;
				goto handle_connect_error;
			}
			context->receive_maximum = property.receive_maximum;
		}else{
			context->receive_maximum = 65535;
		}
		// Maximum_packet_size should be implimented later.
		context->is_maximum_packet_size = property.is_maximum_packet_size;
		if(property.is_maximum_packet_size){
			if((property.maximum_packet_size == 0) || (property.maximum_packet_size > MQTT5_MAX_PACKET_SIZE)){
				log__printf(NULL, MOSQ_LOG_INFO, "Invalid v5 property: MAXIMUM_PACKET_SIZE = %d", property.maximum_packet_size);
				rc = MQTT5_RC_PROTOCOL_ERROR;
				goto handle_connect_error;
			}
			context->maximum_packet_size = property.maximum_packet_size;
		}
		// Topic_alias itself should be implimented later.
		if(property.is_topic_alias_maximum){
			context->topic_alias_maximum = property.topic_alias_maximum;
		}else{
			context->topic_alias_maximum = 0;
		}
		// Request_response itself should be implimented later.
		if(property.is_request_response_information){
			if((property.request_response_information != 0) && (property.request_response_information != 1)){
				log__printf(NULL, MOSQ_LOG_INFO, "Invalid v5 property: REQUEST_RESPONSE_INFORMATION = %d", property.request_response_information);
				rc = MQTT5_RC_PROTOCOL_ERROR;
				goto handle_connect_error;
			}
			context->request_response_information = property.request_response_information;
		}else{
			context->request_response_information = 0;
		}
		// Request_problem can be ignored before using reason strings.
		if(property.is_request_problem_information){
			if((property.request_problem_information != 0) && (property.request_problem_information != 1)){
				log__printf(NULL, MOSQ_LOG_INFO, "Invalid v5 property: REQUEST_PROBLEM_INFORMATION = %d", property.request_problem_information);
				rc = MQTT5_RC_PROTOCOL_ERROR;
				goto handle_connect_error;
			}
			context->request_problem_information = property.request_problem_information;
		}else{
			context->request_problem_information = 1;
		}
		// User_property can be ignored.
		// Authentication is not supported. Should support in the future.
		if((!property.authentication_method) && (property.authentication_data_len > 0)){
			log__printf(NULL, MOSQ_LOG_INFO, "Invalid v5 property: AUTHENTICATION_DATA exist without AUTHENTICATION_METHOD");
			rc = MQTT5_RC_PROTOCOL_ERROR;
			goto handle_connect_error;
		}
		if(property.authentication_method){
			log__printf(NULL, MOSQ_LOG_INFO, "Invalid v5 property: Authentication is not supprted.");
			// Mqtt v5 allow server to disconnect without sending CONNACK about Authentication in order to keep secure.
			goto handle_connect_error_without_connack;
		}
/*		Context->authentication_method = property.authentication_method;
		Property.authentication_method = NULL;
		Context->authentication_data_len = property.authentication_data_len;
		Context->authentication_data = property.authentication_data;
		Property.authentication_data = NULL; */
		packet__property_content_free(&property);
	}

	if(packet__read_string(&context->in_packet, &client_id)){
		rc = 1;
		if(context->protocol == mosq_p_mqtt5) rc = MQTT5_RC_CLIENT_IDENTIFIER_NOT_VALID;
		goto handle_connect_error;
	}

	slen = strlen(client_id);
	if(slen == 0){
		if(context->protocol == mosq_p_mqtt31){
			send__connack(context, 0, CONNACK_REFUSED_IDENTIFIER_REJECTED);
			rc = MOSQ_ERR_PROTOCOL;
			goto handle_connect_error;
		}else{ /* mqtt311 */
			mosquitto__free(client_id);
			client_id = NULL;

			if(clean_session == 0 || db->config->allow_zero_length_clientid == false){
				if(context->protocol == mosq_p_mqtt31){
					send__connack(context, 0, CONNACK_REFUSED_IDENTIFIER_REJECTED);
					rc = MOSQ_ERR_PROTOCOL;
				}else{  // v5
					rc = MQTT5_RC_CLIENT_IDENTIFIER_NOT_VALID;					
				}
				goto handle_connect_error;
			}else{
				client_id = client_id_gen(db);
				if(!client_id){
					rc = MOSQ_ERR_NOMEM;
					goto handle_connect_error;
				}
				if(context->protocol == mosq_p_mqtt5){
					// Set v5 property: Assigned Client Identifier
					context->current_property->assigned_client_identifier = mosquitto__strdup(client_id);
					if(!context->current_property->assigned_client_identifier){
						rc = MOSQ_ERR_NOMEM;
						goto handle_connect_error;
					}
				}
			}
		}
	}

	/* clientid_prefixes check */
	if(db->config->clientid_prefixes){
		if(strncmp(db->config->clientid_prefixes, client_id, strlen(db->config->clientid_prefixes))){
			if(context->protocol == mosq_p_mqtt5){
				rc = MQTT5_RC_NOT_AUTHORIZED;
			}else{
				send__connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED);
				rc = 1;
			}
			goto handle_connect_error;
		}
	}

	if(mosquitto_validate_utf8(client_id, strlen(client_id)) != MOSQ_ERR_SUCCESS){
		rc = 1;
		goto handle_connect_error;
	}

	if(will){
		will_struct = mosquitto__calloc(1, sizeof(struct mosquitto_message));
		if(!will_struct){
			rc = MOSQ_ERR_NOMEM;
			goto handle_connect_error;
		}
		if(packet__read_string(&context->in_packet, &will_topic)){
			rc = 1;
			goto handle_connect_error;
		}
		if(STREMPTY(will_topic)){
			rc = 1;
			goto handle_connect_error;
		}

		if(context->listener && context->listener->mount_point){
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
			if(context->protocol == mosq_p_mqtt5){
				rc = MQTT5_RC_TOPIC_NAME_INVALID;
			}else{
				rc = 1;
			}
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
		if((context->protocol == mosq_p_mqtt311) || (context->protocol == mosq_p_mqtt5)){
			if(will_qos != 0 || will_retain != 0){
				rc = MOSQ_ERR_PROTOCOL;
				goto handle_connect_error;
			}
		}
	}

	if(username_flag){
		rc = packet__read_string(&context->in_packet, &username);
		if(rc == MOSQ_ERR_SUCCESS){
			if(mosquitto_validate_utf8(username, strlen(username)) != MOSQ_ERR_SUCCESS){
				rc = MOSQ_ERR_PROTOCOL;
				goto handle_connect_error;
			}

			if(password_flag){
				rc = packet__read_string(&context->in_packet, &password);
				if(rc == MOSQ_ERR_NOMEM){
					rc = MOSQ_ERR_NOMEM;
					goto handle_connect_error;
				}else if(rc == MOSQ_ERR_PROTOCOL){
					if(context->protocol == mosq_p_mqtt31){
						/* Password flag given, but no password. Ignore. */
						password_flag = 0;
					}else if((context->protocol == mosq_p_mqtt311) || (context->protocol == mosq_p_mqtt5)){
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
			}else if((context->protocol == mosq_p_mqtt311) || (context->protocol == mosq_p_mqtt5)){
				rc = MOSQ_ERR_PROTOCOL;
				goto handle_connect_error;
			}
		}
	}else{
		if(context->protocol == mosq_p_mqtt311){
			if(password_flag){
				/* username_flag == 0 && password_flag == 1 is forbidden */
				/* NOTE: username_flag == 0 && password_flag == 1
				         may be prohibited in v5 but unsupport so far */
				rc = MOSQ_ERR_PROTOCOL;
				goto handle_connect_error;
			}
		}
	}

#ifdef WITH_TLS
	if(context->listener && context->listener->ssl_ctx && (context->listener->use_identity_as_username || context->listener->use_subject_as_username)){
		if(!context->ssl){
			if(context->protocol == mosq_p_mqtt5){
				rc = MQTT5_RC_BAD_USER_NAME_OR_PASSWORD;
			}else{
				send__connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD);
				rc = 1;
			}
			goto handle_connect_error;
		}
#ifdef REAL_WITH_TLS_PSK
		if(context->listener->psk_hint){
			/* Client should have provided an identity to get this far. */
			if(!context->username){
				if(context->protocol == mosq_p_mqtt5){
					rc = MQTT5_RC_BAD_USER_NAME_OR_PASSWORD;
				}else{
					send__connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD);
					rc = 1;
				}
				goto handle_connect_error;
			}
		}else{
#endif /* REAL_WITH_TLS_PSK */
			client_cert = SSL_get_peer_certificate(context->ssl);
			if(!client_cert){
				if(context->protocol == mosq_p_mqtt5){
					rc = MQTT5_RC_BAD_USER_NAME_OR_PASSWORD;
				}else{
					send__connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD);
					rc = 1;
				}
				goto handle_connect_error;
			}
			name = X509_get_subject_name(client_cert);
			if(!name){
				if(context->protocol == mosq_p_mqtt5){
					rc = MQTT5_RC_BAD_USER_NAME_OR_PASSWORD;
				}else{
					send__connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD);
					rc = 1;
				}
				goto handle_connect_error;
			}
			if (context->listener->use_identity_as_username) { //use_identity_as_username
				i = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
				if(i == -1){
					if(context->protocol == mosq_p_mqtt5){
						rc = MQTT5_RC_BAD_USER_NAME_OR_PASSWORD;
					}else{
						send__connack(context, 0, CONNACK_REFUSED_BAD_USERNAME_PASSWORD);
						rc = 1;
					}
					goto handle_connect_error;
				}
				name_entry = X509_NAME_get_entry(name, i);
				if(name_entry){
					context->username = mosquitto__strdup((char *)ASN1_STRING_data(name_entry->value));
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
#ifdef REAL_WITH_TLS_PSK
		}
#endif /* REAL_WITH_TLS_PSK */
	}else{
#endif /* WITH_TLS */
		if(username_flag){
			rc = mosquitto_unpwd_check(db, context, username, password);
			switch(rc){
				case MOSQ_ERR_SUCCESS:
					break;
				case MOSQ_ERR_AUTH:
					if(context->protocol == mosq_p_mqtt5){
						rc = MQTT5_RC_NOT_AUTHORIZED;
					}else{
						send__connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED);
						context__disconnect(db, context);
						rc = 1;
					}
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

		if(!username_flag && db->config->allow_anonymous == false){
			if(context->protocol == mosq_p_mqtt5){
				rc = MQTT5_RC_NOT_AUTHORIZED;
			}else{
				send__connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED);
				rc = 1;
			}
			goto handle_connect_error;
		}
#ifdef WITH_TLS
	}
#endif

	if(context->listener && context->listener->use_username_as_clientid){
		if(context->username){
			if(context->protocol == mosq_p_mqtt5){
				mosquitto__free(context->current_property->assigned_client_identifier);
				context->current_property->assigned_client_identifier = NULL;
			}
			mosquitto__free(client_id);
			client_id = mosquitto__strdup(context->username);
			if(!client_id){
				rc = MOSQ_ERR_NOMEM;
				goto handle_connect_error;
			}
		}else{
			if(context->protocol == mosq_p_mqtt5){
				rc = MQTT5_RC_NOT_AUTHORIZED;
			}else{
				send__connack(context, 0, CONNACK_REFUSED_NOT_AUTHORIZED);
				rc = 1;
			}
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

		if((context->protocol == mosq_p_mqtt311) || (context->protocol == mosq_p_mqtt5)){
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
		found_context->state = mosq_cs_disconnecting;
		// For v5, send disconnect reason code SESSION_TAKEN_OVER.
		if(found_context->protocol == mosq_p_mqtt5){
			found_context->rc_current = MQTT5_RC_SESSION_TAKEN_OVER;
			if(context__current_property_init(found_context)){
				rc = MOSQ_ERR_NOMEM;
				goto handle_connect_error;
			}
			send__disconnect(found_context);
			found_context->rc_current = 0;
			context__current_property_free(found_context);
		}
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
	// setup connack v5 property
	if(context->protocol == mosq_p_mqtt5){
		// Receive Maximum should be supported later.
		//   NOTE: max_queued_messages is local var of database.c so far.
		// Maximum QoS is default (all QoS supported).
		// Retain Available is default (supported).
		// Maximum Packet Size should be config->message_size_limit.
		if((0 < db->config->message_size_limit) && (db->config->message_size_limit <= MQTT_MAX_PAYLOAD)){
			context->current_property->maximum_packet_size = db->config->message_size_limit;
			context->current_property->is_maximum_packet_size = true;
		}else if(db->config->message_size_limit != 0){
			log__printf(NULL, MOSQ_LOG_INFO, "Invalid message_size_limit: %d", db->config->message_size_limit);
		}
		// Assigned Client Identifier is already set in need.
		// Topic Aliase Maximum is default (==0, means not supported). Should support in the future.
		// Reason String is default (not used).
		// User Property is default (not used).
		// Wildcard Subscription Available is default (supported).
		// Subscription Identifiers Available is not supported. Should support in the future.
		context->current_property->subscription_identifier_available = 0;
		context->current_property->is_subscription_identifier_available = true;
		// Shared Subscription is not supported. Should support in the future.
		context->current_property->shared_subscription_available = 0;
		context->current_property->is_shared_subscription_available = true;
		// Server Keep Alive is default (not supported). Should support in the future.
		// Response Information is default (not supported). support in the future.
		//   NOTE: Response Information is used for assigning dynamic topic.
		//         Pulisher and Subscriber can use Request/Response on designated topic.
		// Server Reference is default (not supported). Should support in the future.
		// Authentication is default (not supported). Should support in the future.
		// (When supporting Authentication, add some codes at parsing property also.)
	}

	rc = send__connack(context, connect_ack, CONNACK_ACCEPTED);  // == MQTT5_RC_SUCCESS
	if(context->protocol == mosq_p_mqtt5){
		context__current_property_free(context);
	}
	return rc;

handle_connect_error:
	if(context->protocol == mosq_p_mqtt5){
		if(rc == MOSQ_ERR_PROTOCOL){
			rc = MQTT5_RC_MALFORMED_PACKET;
		}else if(rc == MOSQ_ERR_NOMEM) {
			rc = MQTT5_RC_UNSPECIFIED_ERROR;
		}
		send__connack(context, 0, rc);
	}
handle_connect_error_without_connack:
	if(context->protocol == mosq_p_mqtt5){
		packet__property_content_free(&property);
		context__current_property_free(context);
	}
	mosquitto__free(client_id);
	mosquitto__free(username);
	mosquitto__free(password);
	mosquitto__free(will_payload);
	mosquitto__free(will_topic);
	mosquitto__free(will_struct);
	mosquitto__free(protocol_name);
#ifdef WITH_TLS
	if(client_cert) X509_free(client_cert);
#endif
	/* We return an error here which means the client is freed later on. */
	return rc;
}

int handle__disconnect(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;
	uint8_t rc_current;
	struct mosquitto_v5_property property;

	if(!context){
		return MOSQ_ERR_INVAL;
	}
	if((context->in_packet.remaining_length != 0) && (context->protocol != mosq_p_mqtt5)){
		return MOSQ_ERR_PROTOCOL;
	}
	if(context->protocol == mosq_p_mqtt5){
		memset(&property, 0, sizeof(struct mosquitto_v5_property));
		rc = packet__read_byte(&context->in_packet, &rc_current);
		if(rc != MQTT5_RC_SUCCESS){
			goto handle_disconnect_error;
		}
		rc = packet__read_property(context, &context->in_packet, &property, DISCONNECT);
		if(rc != MQTT5_RC_SUCCESS){
			goto handle_disconnect_error;
		}
		// Session_expiry_interval should be implimented later.
		context->is_session_expiry_interval = property.is_session_expiry_interval;
		if(property.is_session_expiry_interval){
			context->session_expiry_interval = property.session_expiry_interval;
		}
		// Reason_string can be ignored.
		// User_property can be ignored.
		packet__property_content_free(&property);
		log__printf(NULL, MOSQ_LOG_DEBUG, "Received DISCONNECT from %s (%d)", context->id, rc_current);
	}else{
		log__printf(NULL, MOSQ_LOG_DEBUG, "Received DISCONNECT from %s", context->id);
	}
	if((context->protocol == mosq_p_mqtt311) || (context->protocol == mosq_p_mqtt5)){
		if((context->in_packet.command&0x0F) != 0x00){
			if(context->protocol == mosq_p_mqtt5){
				rc = MQTT5_RC_PROTOCOL_ERROR;
				goto handle_disconnect_error;
			}
			do_disconnect(db, context);
			return MOSQ_ERR_PROTOCOL;
		}
	}

	// For v5, do not send the Will when NORMAL_DISCONNECTION received from client
	if((context->protocol == mosq_p_mqtt5) &&(rc_current == MQTT5_RC_NORMAL_DISCONNECTION)){
		if(context->will){
			mosquitto__free(context->will->topic);
			mosquitto__free(context->will->payload);
			mosquitto__free(context->will);
			context->will = NULL;
		}
	}
	context->state = mosq_cs_disconnecting;
	do_disconnect(db, context);
	return MOSQ_ERR_SUCCESS;

handle_disconnect_error:  // For v5 only
	packet__property_content_free(&property);
	if(rc == MOSQ_ERR_PROTOCOL){
		rc = MQTT5_RC_MALFORMED_PACKET;
	}else if(rc == MOSQ_ERR_NOMEM) {
		rc = MQTT5_RC_UNSPECIFIED_ERROR;
	}
	context->rc_current = rc;
	if(context__current_property_init(context)){
		return MOSQ_ERR_NOMEM;	
	}
	send__disconnect(context);
	context->rc_current = 0;
	context__current_property_free(context);

	do_disconnect(db, context);
	return MOSQ_ERR_PROTOCOL;	
}


