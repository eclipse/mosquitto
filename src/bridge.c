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
*/

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifndef WIN32
#include <netdb.h>
#include <sys/socket.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif


#include "mosquitto.h"
#include "mosquitto_broker_internal.h"
#include "mosquitto_internal.h"
#include "net_mosq.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "send_mosq.h"
#include "time_mosq.h"
#include "tls_mosq.h"
#include "util_mosq.h"
#include "will_mosq.h"

#ifdef WITH_BRIDGE

int bridge__new(struct mosquitto_db *db, struct mosquitto__bridge *bridge)
{
	struct mosquitto *new_context = NULL;
	struct mosquitto **bridges;
	char *local_id;

	assert(db);
	assert(bridge);

	local_id = mosquitto__strdup(bridge->local_clientid);

	HASH_FIND(hh_id, db->contexts_by_id, local_id, strlen(local_id), new_context);
	if(new_context){
		/* (possible from persistent db) */
		mosquitto__free(local_id);
	}else{
		/* id wasn't found, so generate a new context */
		new_context = context__init(db, -1);
		if(!new_context){
			mosquitto__free(local_id);
			return MOSQ_ERR_NOMEM;
		}
		new_context->id = local_id;
		HASH_ADD_KEYPTR(hh_id, db->contexts_by_id, new_context->id, strlen(new_context->id), new_context);
	}
	new_context->bridge = bridge;
	new_context->is_bridge = true;

	new_context->username = new_context->bridge->remote_username;
	new_context->password = new_context->bridge->remote_password;

#ifdef WITH_TLS
	new_context->tls_cafile = new_context->bridge->tls_cafile;
	new_context->tls_capath = new_context->bridge->tls_capath;
	new_context->tls_certfile = new_context->bridge->tls_certfile;
	new_context->tls_keyfile = new_context->bridge->tls_keyfile;
	new_context->tls_cert_reqs = SSL_VERIFY_PEER;
	new_context->tls_version = new_context->bridge->tls_version;
	new_context->tls_insecure = new_context->bridge->tls_insecure;
#ifdef REAL_WITH_TLS_PSK
	new_context->tls_psk_identity = new_context->bridge->tls_psk_identity;
	new_context->tls_psk = new_context->bridge->tls_psk;
#endif
#endif

	bridge->try_private_accepted = true;
	new_context->protocol = bridge->protocol_version;

	bridges = mosquitto__realloc(db->bridges, (db->bridge_count+1)*sizeof(struct mosquitto *));
	if(bridges){
		db->bridges = bridges;
		db->bridge_count++;
		db->bridges[db->bridge_count-1] = new_context;
	}else{
		return MOSQ_ERR_NOMEM;
	}

#if defined(__GLIBC__) && defined(WITH_ADNS)
	new_context->bridge->restart_t = 1; /* force quick restart of bridge */
	return bridge__connect_step1(db, new_context);
#else
	return bridge__connect(db, new_context);
#endif
}

int bridge__del(struct mosquitto_db *db, int index)
{
	struct mosquitto *old_context = NULL;
	struct mosquitto **bridges;
	char *local_id;
	int i;

	assert(db);

	local_id = mosquitto__strdup(db->bridges[index]->bridge->local_clientid);
	HASH_FIND(hh_id, db->contexts_by_id, local_id, strlen(local_id), old_context);
	if(old_context){
		HASH_DELETE(hh_id,db->contexts_by_id,old_context);
	}else{
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to found bridge %s in db",local_id);
	}

	db->bridge_count--;

	for(i=index; i<db->bridge_count; i++){
		db->bridges[i] = db->bridges[i+1];
	}

	bridge__disconnect(db,old_context);

	if(db->bridge_count==0){
		db->bridges[0] = NULL;
	}else{
		bridges = mosquitto__realloc(db->bridges, (db->bridge_count)*sizeof(struct mosquitto *));
		if(bridges){
			db->bridges = bridges;
		}else{
			return MOSQ_ERR_NOMEM;
		}
	}
	return 0;
}

#if defined(__GLIBC__) && defined(WITH_ADNS)
int bridge__connect_step1(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;
	int i;
	char *notification_topic;
	int notification_topic_len;
	uint8_t notification_payload;

	if(!context || !context->bridge) return MOSQ_ERR_INVAL;

	context->state = mosq_cs_new;
	context->sock = INVALID_SOCKET;
	context->last_msg_in = mosquitto_time();
	context->next_msg_out = mosquitto_time() + context->bridge->keepalive;
	context->keepalive = context->bridge->keepalive;
	context->clean_session = context->bridge->clean_session;
	context->in_packet.payload = NULL;
	context->ping_t = 0;
	context->bridge->lazy_reconnect = false;
	mqtt3_bridge_packet_cleanup(context);
	mqtt3_db_message_reconnect_reset(db, context);

	if(context->clean_session){
		mqtt3_db_messages_delete(db, context);
	}

	/* Delete all local subscriptions even for clean_session==false. We don't
	 * remove any messages and the next loop carries out the resubscription
	 * anyway. This means any unwanted subs will be removed.
	 */
	mqtt3_subs_clean_session(db, context);

	for(i=0; i<context->bridge->topic_count; i++){
		if(context->bridge->topics[i].direction == bd_out || context->bridge->topics[i].direction == bd_both){
			_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Bridge %s doing local SUBSCRIBE on topic %s", context->id, context->bridge->topics[i].local_topic);
			if(mqtt3_sub_add(db, context, context->bridge->topics[i].local_topic, context->bridge->topics[i].qos, &db->subs)) return 1;
		}
	}

	if(context->bridge->notifications){
		if(context->bridge->notification_topic){
			if(!context->bridge->initial_notification_done){
				notification_payload = '0';
				mqtt3_db_messages_easy_queue(db, context, context->bridge->notification_topic, 1, 1, &notification_payload, 1);
				context->bridge->initial_notification_done = true;
			}
			notification_payload = '0';
			rc = _mosquitto_will_set(context, context->bridge->notification_topic, 1, &notification_payload, 1, true);
			if(rc != MOSQ_ERR_SUCCESS){
				return rc;
			}
		}else{
			notification_topic_len = strlen(context->bridge->remote_clientid)+strlen("$SYS/broker/connection//state");
			notification_topic = _mosquitto_malloc(sizeof(char)*(notification_topic_len+1));
			if(!notification_topic) return MOSQ_ERR_NOMEM;

			snprintf(notification_topic, notification_topic_len+1, "$SYS/broker/connection/%s/state", context->bridge->remote_clientid);

			if(!context->bridge->initial_notification_done){
				notification_payload = '0';
				mqtt3_db_messages_easy_queue(db, context, notification_topic, 1, 1, &notification_payload, 1);
				context->bridge->initial_notification_done = true;
			}

			notification_payload = '0';
			rc = _mosquitto_will_set(context, notification_topic, 1, &notification_payload, 1, true);
			_mosquitto_free(notification_topic);
			if(rc != MOSQ_ERR_SUCCESS){
				return rc;
			}
		}
	}

	_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "Connecting bridge %s (%s:%d)", context->bridge->name, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port);
	rc = _mosquitto_try_connect_step1(context, context->bridge->addresses[context->bridge->cur_address].address);
	if(rc > 0 ){
		if(rc == MOSQ_ERR_TLS){
			_mosquitto_socket_close(db, context);
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}

		return rc;
	}

	return MOSQ_ERR_SUCCESS;
}


int bridge__connect_step2(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;

	if(!context || !context->bridge) return MOSQ_ERR_INVAL;

	_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "Connecting bridge %s (%s:%d)", context->bridge->name, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port);
	rc = _mosquitto_try_connect_step2(context, context->bridge->addresses[context->bridge->cur_address].port, &context->sock);
	if(rc > 0 ){
		if(rc == MOSQ_ERR_TLS){
			_mosquitto_socket_close(db, context);
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}

		return rc;
	}

	rc = _mosquitto_socket_connect_step3(context, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port, NULL, false);
	if(rc > 0 ){
		if(rc == MOSQ_ERR_TLS){
			_mosquitto_socket_close(db, context);
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}

		return rc;
	}

	HASH_ADD(hh_sock, db->contexts_by_sock, sock, sizeof(context->sock), context);

	if(rc == MOSQ_ERR_CONN_PENDING){
		context->state = mosq_cs_connect_pending;
	}
	rc = _mosquitto_send_connect(context, context->keepalive, context->clean_session);
	if(rc == MOSQ_ERR_SUCCESS){
		return MOSQ_ERR_SUCCESS;
	}else if(rc == MOSQ_ERR_ERRNO && errno == ENOTCONN){
		return MOSQ_ERR_SUCCESS;
	}else{
		if(rc == MOSQ_ERR_TLS){
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}
		_mosquitto_socket_close(db, context);
		return rc;
	}
}
#else

int bridge__connect(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;
	int i;
	char *notification_topic;
	int notification_topic_len;
	uint8_t notification_payload;

	if(!context || !context->bridge) return MOSQ_ERR_INVAL;

	context->state = mosq_cs_new;
	context->sock = INVALID_SOCKET;
	context->last_msg_in = mosquitto_time();
	context->next_msg_out = mosquitto_time() + context->bridge->keepalive;
	context->keepalive = context->bridge->keepalive;
	context->clean_session = context->bridge->clean_session;
	context->in_packet.payload = NULL;
	context->ping_t = 0;
	context->bridge->lazy_reconnect = false;
	bridge__packet_cleanup(context);
	db__message_reconnect_reset(db, context);

	if(context->clean_session){
		db__messages_delete(db, context);
	}

	/* Delete all local subscriptions even for clean_session==false. We don't
	 * remove any messages and the next loop carries out the resubscription
	 * anyway. This means any unwanted subs will be removed.
	 */
	sub__clean_session(db, context);

	for(i=0; i<context->bridge->topic_count; i++){
		if(context->bridge->topics[i].direction == bd_out || context->bridge->topics[i].direction == bd_both){
			log__printf(NULL, MOSQ_LOG_DEBUG, "Bridge %s doing local SUBSCRIBE on topic %s", context->id, context->bridge->topics[i].local_topic);
			if(sub__add(db, context, context->bridge->topics[i].local_topic, context->bridge->topics[i].qos, &db->subs)) return 1;
		}
	}

	if(context->bridge->notifications){
		if(context->bridge->notification_topic){
			if(!context->bridge->initial_notification_done){
				notification_payload = '0';
				db__messages_easy_queue(db, context, context->bridge->notification_topic, 1, 1, &notification_payload, 1);
				context->bridge->initial_notification_done = true;
			}

			if (!context->bridge->notifications_local_only) {
				notification_payload = '0';
				rc = will__set(context, context->bridge->notification_topic, 1, &notification_payload, 1, true);
				if(rc != MOSQ_ERR_SUCCESS){
					return rc;
				}
			}
		}else{
			notification_topic_len = strlen(context->bridge->remote_clientid)+strlen("$SYS/broker/connection//state");
			notification_topic = mosquitto__malloc(sizeof(char)*(notification_topic_len+1));
			if(!notification_topic) return MOSQ_ERR_NOMEM;

			snprintf(notification_topic, notification_topic_len+1, "$SYS/broker/connection/%s/state", context->bridge->remote_clientid);

			if(!context->bridge->initial_notification_done){
				notification_payload = '0';
				db__messages_easy_queue(db, context, notification_topic, 1, 1, &notification_payload, 1);
				context->bridge->initial_notification_done = true;
			}

			if (!context->bridge->notifications_local_only) {
				notification_payload = '0';
				rc = will__set(context, notification_topic, 1, &notification_payload, 1, true);
				mosquitto__free(notification_topic);
				if(rc != MOSQ_ERR_SUCCESS){
					return rc;
				}
			}
		}
	}

	log__printf(NULL, MOSQ_LOG_NOTICE, "Connecting bridge %s (%s:%d)", context->bridge->name, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port);
	rc = net__socket_connect(context, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port, NULL, false);
	if(rc > 0 ){
		if(rc == MOSQ_ERR_TLS){
			net__socket_close(db, context);
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}

		return rc;
	}

	HASH_ADD(hh_sock, db->contexts_by_sock, sock, sizeof(context->sock), context);

	if(rc == MOSQ_ERR_CONN_PENDING){
		context->state = mosq_cs_connect_pending;
	}
	rc = send__connect(context, context->keepalive, context->clean_session);
	if(rc == MOSQ_ERR_SUCCESS){
		return MOSQ_ERR_SUCCESS;
	}else if(rc == MOSQ_ERR_ERRNO && errno == ENOTCONN){
		return MOSQ_ERR_SUCCESS;
	}else{
		if(rc == MOSQ_ERR_TLS){
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}
		net__socket_close(db, context);
		return rc;
	}
}

int bridge__disconnect(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;
	char *notification_topic;
	int notification_topic_len;
	uint8_t notification_payload;

	if(!context || !context->bridge) return MOSQ_ERR_INVAL;

	bridge__packet_cleanup(context);

	db__messages_delete(db, context);

	sub__clean_session(db, context);

	notification_topic_len = strlen(context->bridge->remote_clientid)+strlen("$SYS/broker/connection//state");
	notification_topic = mosquitto__malloc(sizeof(char)*(notification_topic_len+1));
	if(!notification_topic) return MOSQ_ERR_NOMEM;

	snprintf(notification_topic, notification_topic_len+1, "$SYS/broker/connection/%s/state", context->bridge->remote_clientid);

	notification_payload = '0';
	db__messages_easy_queue(db, context, notification_topic, 1, 1, &notification_payload, 1);

	log__printf(NULL, MOSQ_LOG_NOTICE, "Disconnecting bridge %s (%s:%d)", context->bridge->name, context->bridge->addresses[0].address, context->bridge->addresses[0].port);
	rc = send__disconnect(context);
	if(rc<0){
		log__printf(NULL, MOSQ_LOG_ERR, "Error disconnecting bridge: %s.", gai_strerror(errno));
		return rc;
	}
	HASH_DELETE(hh_sock, db->contexts_by_sock, context);
	net__socket_close(db, context);
	context->sock = INVALID_SOCKET;
	context->pollfd_index = -1;
	context__disconnect(db, context);

	free(context);

	return rc;
}
#endif


void bridge__packet_cleanup(struct mosquitto *context)
{
	struct mosquitto__packet *packet;
	if(!context) return;

	if(context->current_out_packet){
		packet__cleanup(context->current_out_packet);
		mosquitto__free(context->current_out_packet);
		context->current_out_packet = NULL;
	}
    while(context->out_packet){
		packet__cleanup(context->out_packet);
		packet = context->out_packet;
		context->out_packet = context->out_packet->next;
		mosquitto__free(packet);
	}
	context->out_packet = NULL;
	context->out_packet_last = NULL;

	packet__cleanup(&(context->in_packet));
}

#endif
