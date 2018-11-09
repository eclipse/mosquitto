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

#include "config.h"

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

static void bridge_backoff_step(struct mosquitto *context);
static void bridge__backoff_reset(struct mosquitto *context);

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
#ifdef WITH_TLS_PSK
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
			sub__retain_queue(db, context,
					context->bridge->topics[i].local_topic,
					context->bridge->topics[i].qos);
		}
	}

	/* prepare backoff for a possible failure. Restart timeout will be reset if connection gets established */
	bridge_backoff_step(context);

	if(context->bridge->notifications){
		if(context->bridge->notification_topic){
			if(!context->bridge->initial_notification_done){
				notification_payload = '0';
				db__messages_easy_queue(db, context, context->bridge->notification_topic, 1, 1, &notification_payload, 1);
				context->bridge->initial_notification_done = true;
			}
			notification_payload = '0';
			rc = will__set(context, context->bridge->notification_topic, 1, &notification_payload, 1, true);
			if(rc != MOSQ_ERR_SUCCESS){
				return rc;
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

			notification_payload = '0';
			rc = will__set(context, notification_topic, 1, &notification_payload, 1, true);
			mosquitto__free(notification_topic);
			if(rc != MOSQ_ERR_SUCCESS){
				return rc;
			}
		}
	}

	log__printf(NULL, MOSQ_LOG_NOTICE, "Connecting bridge (step 1) %s (%s:%d)", context->bridge->name, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port);
	rc = net__try_connect_step1(context, context->bridge->addresses[context->bridge->cur_address].address);
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

	return MOSQ_ERR_SUCCESS;
}


int bridge__connect_step2(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;

	if(!context || !context->bridge) return MOSQ_ERR_INVAL;

	log__printf(NULL, MOSQ_LOG_NOTICE, "Connecting bridge (step 2) %s (%s:%d)", context->bridge->name, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port);
	rc = net__try_connect_step2(context, context->bridge->addresses[context->bridge->cur_address].port, &context->sock);
	if(rc > 0){
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
	return rc;
}


int bridge__connect_step3(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;

	rc = net__socket_connect_step3(context, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port, NULL, false);
	if(rc > 0){
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

	if(context->bridge->round_robin == false && context->bridge->cur_address != 0){
		context->bridge->primary_retry = mosquitto_time() + 5;
	}

	rc = send__connect(context, context->keepalive, context->clean_session);
	if(rc == MOSQ_ERR_SUCCESS){
		bridge__backoff_reset(context);
		return MOSQ_ERR_SUCCESS;
	}else if(rc == MOSQ_ERR_ERRNO && errno == ENOTCONN){
		bridge__backoff_reset(context);
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
#else

int bridge__connect(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc, rc2;
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
			sub__retain_queue(db, context,
					context->bridge->topics[i].local_topic,
					context->bridge->topics[i].qos);
		}
	}

	/* prepare backoff for a possible failure. Restart timeout will be reset if connection gets established */
	bridge_backoff_step(context);

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
	if(rc > 0){
		if(rc == MOSQ_ERR_TLS){
			net__socket_close(db, context);
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}

		return rc;
	}else if(rc == MOSQ_ERR_CONN_PENDING){
		context->state = mosq_cs_connect_pending;
	}

	HASH_ADD(hh_sock, db->contexts_by_sock, sock, sizeof(context->sock), context);

	rc2 = send__connect(context, context->keepalive, context->clean_session);
	if(rc2 == MOSQ_ERR_SUCCESS){
		bridge__backoff_reset(context);
		return rc;
	}else if(rc2 == MOSQ_ERR_ERRNO && errno == ENOTCONN){
		bridge__backoff_reset(context);
		return MOSQ_ERR_SUCCESS;
	}else{
		if(rc2 == MOSQ_ERR_TLS){
			return rc2; /* Error already printed */
		}else if(rc2 == MOSQ_ERR_ERRNO){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc2 == MOSQ_ERR_EAI){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}
		net__socket_close(db, context);
		return rc2;
	}
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

static int rand_between(int base, int cap)
{
	return (rand() % (cap - base)) + base;
}

static void bridge_backoff_step(struct mosquitto *context)
{
	struct mosquitto__bridge *bridge;
	if(!context || !context->bridge) return;

	bridge = context->bridge;

	/* skip if not using backoff */
	if(bridge->backoff_cap){
		/* “Decorrelated Jitter” calculation, according to:
		 * https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
		 */
		bridge->restart_timeout = rand_between(bridge->backoff_base, bridge->restart_timeout * 3);
		if(bridge->restart_timeout > bridge->backoff_cap){
			bridge->restart_timeout = bridge->backoff_cap;
		}
	}
}

static void bridge__backoff_reset(struct mosquitto *context)
{
	struct mosquitto__bridge *bridge;
	if(!context || !context->bridge) return;

	bridge = context->bridge;

	/* skip if not using backoff */
	if(bridge->backoff_cap){
		bridge->restart_timeout = bridge->backoff_base;
	}
}

#endif
