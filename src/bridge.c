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

#ifndef WIN32
#include <unistd.h>
#else
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "mqtt_protocol.h"
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

static void bridge__backoff_step(struct mosquitto *context);
static void bridge__backoff_reset(struct mosquitto *context);

void bridge__start_all(void)
{
	int i;

	for(i=0; i<db.config->bridge_count; i++){
		if(bridge__new(&(db.config->bridges[i]))){
			log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Unable to connect to bridge %s.", 
					db.config->bridges[i].name);
		}
	}
}


int bridge__new(struct mosquitto__bridge *bridge)
{
	struct mosquitto *new_context = NULL;
	struct mosquitto **bridges;
	char *local_id;

	assert(bridge);

	local_id = mosquitto__strdup(bridge->local_clientid);

	HASH_FIND(hh_id, db.contexts_by_id, local_id, strlen(local_id), new_context);
	if(new_context){
		/* (possible from persistent db) */
		mosquitto__free(local_id);
	}else{
		/* id wasn't found, so generate a new context */
		new_context = context__init(-1);
		if(!new_context){
			mosquitto__free(local_id);
			return MOSQ_ERR_NOMEM;
		}
		new_context->id = local_id;
		HASH_ADD_KEYPTR(hh_id, db.contexts_by_id, new_context->id, strlen(new_context->id), new_context);
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
	new_context->tls_ocsp_required = new_context->bridge->tls_ocsp_required;
	new_context->tls_version = new_context->bridge->tls_version;
	new_context->tls_insecure = new_context->bridge->tls_insecure;
	new_context->tls_alpn = new_context->bridge->tls_alpn;
	new_context->tls_engine = db.config->default_listener.tls_engine;
	new_context->tls_keyform = db.config->default_listener.tls_keyform;
#ifdef FINAL_WITH_TLS_PSK
	new_context->tls_psk_identity = new_context->bridge->tls_psk_identity;
	new_context->tls_psk = new_context->bridge->tls_psk;
#endif
#endif

	bridge->try_private_accepted = true;
	if(bridge->clean_start_local == -1){
		/* default to "regular" clean start setting */
		bridge->clean_start_local = bridge->clean_start;
	}
	new_context->retain_available = bridge->outgoing_retain;
	new_context->protocol = bridge->protocol_version;

	bridges = mosquitto__realloc(db.bridges, (size_t)(db.bridge_count+1)*sizeof(struct mosquitto *));
	if(bridges){
		db.bridges = bridges;
		db.bridge_count++;
		db.bridges[db.bridge_count-1] = new_context;
	}else{
		return MOSQ_ERR_NOMEM;
	}

#if defined(__GLIBC__) && defined(WITH_ADNS)
	new_context->bridge->restart_t = 1; /* force quick restart of bridge */
	return bridge__connect_step1(new_context);
#else
	return bridge__connect(new_context);
#endif
}

#if defined(__GLIBC__) && defined(WITH_ADNS)
int bridge__connect_step1(struct mosquitto *context)
{
	int rc;
	char *notification_topic;
	size_t notification_topic_len;
	uint8_t notification_payload;
	int i;
	uint8_t qos;

	if(!context || !context->bridge) return MOSQ_ERR_INVAL;

	mosquitto__set_state(context, mosq_cs_new);
	context->sock = INVALID_SOCKET;
	context->last_msg_in = db.now_s;
	context->next_msg_out = db.now_s + context->bridge->keepalive;
	context->keepalive = context->bridge->keepalive;
	context->clean_start = context->bridge->clean_start;
	context->in_packet.payload = NULL;
	context->ping_t = 0;
	context->bridge->lazy_reconnect = false;
	context->maximum_packet_size = context->bridge->maximum_packet_size;
	bridge__packet_cleanup(context);
	db__message_reconnect_reset(context);

	db__messages_delete(context, false);

	/* Delete all local subscriptions even for clean_start==false. We don't
	 * remove any messages and the next loop carries out the resubscription
	 * anyway. This means any unwanted subs will be removed.
	 */
	sub__clean_session(context);

	for(i=0; i<context->bridge->topic_count; i++){
		if(context->bridge->topics[i].direction == bd_out || context->bridge->topics[i].direction == bd_both){
			log__printf(NULL, MOSQ_LOG_DEBUG, "Bridge %s doing local SUBSCRIBE on topic %s", context->id, context->bridge->topics[i].local_topic);
			if(context->bridge->topics[i].qos > context->max_qos){
				qos = context->max_qos;
			}else{
				qos = context->bridge->topics[i].qos;
			}
			if(sub__add(context,
						context->bridge->topics[i].local_topic,
						qos,
						0,
						MQTT_SUB_OPT_NO_LOCAL | MQTT_SUB_OPT_RETAIN_AS_PUBLISHED,
						&db.subs) > 0){
				return 1;
			}
			retain__queue(context,
					context->bridge->topics[i].local_topic,
					qos, 0);
		}
	}

	/* prepare backoff for a possible failure. Restart timeout will be reset if connection gets established */
	bridge__backoff_step(context);

	if(context->bridge->notifications){
		if(context->max_qos == 0){
			qos = 0;
		}else{
			qos = 1;
		}
		if(context->bridge->notification_topic){
			if(!context->bridge->initial_notification_done){
				notification_payload = '0';
				db__messages_easy_queue(context, context->bridge->notification_topic, qos, 1, &notification_payload, 1, 0, NULL);
				context->bridge->initial_notification_done = true;
			}
			notification_payload = '0';
			rc = will__set(context, context->bridge->notification_topic, 1, &notification_payload, qos, true, NULL);
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
				db__messages_easy_queue(context, notification_topic, qos, 1, &notification_payload, 1, 0, NULL);
				context->bridge->initial_notification_done = true;
			}

			notification_payload = '0';
			rc = will__set(context, notification_topic, 1, &notification_payload, qos, true, NULL);
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
			net__socket_close(context);
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


int bridge__connect_step2(struct mosquitto *context)
{
	int rc;

	if(!context || !context->bridge) return MOSQ_ERR_INVAL;

	log__printf(NULL, MOSQ_LOG_NOTICE, "Connecting bridge (step 2) %s (%s:%d)", context->bridge->name, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port);
	rc = net__try_connect_step2(context, context->bridge->addresses[context->bridge->cur_address].port, &context->sock);
	if(rc > 0){
		if(rc == MOSQ_ERR_TLS){
			net__socket_close(context);
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}

		return rc;
	}

	HASH_ADD(hh_sock, db.contexts_by_sock, sock, sizeof(context->sock), context);

	if(rc == MOSQ_ERR_CONN_PENDING){
		mosquitto__set_state(context, mosq_cs_connect_pending);
	}
	return rc;
}


int bridge__connect_step3(struct mosquitto *context)
{
	int rc;

	rc = net__socket_connect_step3(context, context->bridge->addresses[context->bridge->cur_address].address);
	if(rc > 0){
		if(rc == MOSQ_ERR_TLS){
			net__socket_close(context);
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}

		return rc;
	}

	if(context->bridge->round_robin == false && context->bridge->cur_address != 0){
		context->bridge->primary_retry = db.now_s + 5;
	}

	rc = send__connect(context, context->keepalive, context->clean_start, NULL);
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
		net__socket_close(context);
		return rc;
	}
}
#else

int bridge__connect(struct mosquitto *context)
{
	int rc, rc2;
	int i;
	char *notification_topic = NULL;
	size_t notification_topic_len;
	uint8_t notification_payload;
	uint8_t qos;

	if(!context || !context->bridge) return MOSQ_ERR_INVAL;

	mosquitto__set_state(context, mosq_cs_new);
	context->sock = INVALID_SOCKET;
	context->last_msg_in = db.now_s;
	context->next_msg_out = db.now_s + context->bridge->keepalive;
	context->keepalive = context->bridge->keepalive;
	context->clean_start = context->bridge->clean_start;
	context->in_packet.payload = NULL;
	context->ping_t = 0;
	context->bridge->lazy_reconnect = false;
	context->maximum_packet_size = context->bridge->maximum_packet_size;
	bridge__packet_cleanup(context);
	db__message_reconnect_reset(context);

	db__messages_delete(context, false);

	/* Delete all local subscriptions even for clean_start==false. We don't
	 * remove any messages and the next loop carries out the resubscription
	 * anyway. This means any unwanted subs will be removed.
	 */
	sub__clean_session(context);

	for(i=0; i<context->bridge->topic_count; i++){
		if(context->bridge->topics[i].direction == bd_out || context->bridge->topics[i].direction == bd_both){
			log__printf(NULL, MOSQ_LOG_DEBUG, "Bridge %s doing local SUBSCRIBE on topic %s", context->id, context->bridge->topics[i].local_topic);
			if(context->bridge->topics[i].qos > context->max_qos){
				qos = context->max_qos;
			}else{
				qos = context->bridge->topics[i].qos;
			}
			if(sub__add(context,
						context->bridge->topics[i].local_topic,
						qos,
						0,
						MQTT_SUB_OPT_NO_LOCAL | MQTT_SUB_OPT_RETAIN_AS_PUBLISHED,
						&db.subs) > 0){

				return 1;
			}
		}
	}

	/* prepare backoff for a possible failure. Restart timeout will be reset if connection gets established */
	bridge__backoff_step(context);

	if(context->bridge->notifications){
		if(context->max_qos == 0){
			qos = 0;
		}else{
			qos = 1;
		}
		if(context->bridge->notification_topic){
			if(!context->bridge->initial_notification_done){
				notification_payload = '0';
				db__messages_easy_queue(context, context->bridge->notification_topic, qos, 1, &notification_payload, 1, 0, NULL);
				context->bridge->initial_notification_done = true;
			}

			notification_payload = '0';
			rc = will__set(context, context->bridge->notification_topic, 1, &notification_payload, qos, true, NULL);
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
				db__messages_easy_queue(context, notification_topic, qos, 1, &notification_payload, 1, 0, NULL);
				context->bridge->initial_notification_done = true;
			}

			notification_payload = '0';
			rc = will__set(context, notification_topic, 1, &notification_payload, qos, true, NULL);
			if(rc != MOSQ_ERR_SUCCESS){
				mosquitto__free(notification_topic);
				return rc;
			}
			mosquitto__free(notification_topic);
		}
	}

	log__printf(NULL, MOSQ_LOG_NOTICE, "Connecting bridge %s (%s:%d)", context->bridge->name, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port);
	rc = net__socket_connect(context,
			context->bridge->addresses[context->bridge->cur_address].address,
			context->bridge->addresses[context->bridge->cur_address].port,
			context->bridge->bind_address,
			false);

	if(rc > 0){
		if(rc == MOSQ_ERR_TLS){
			net__socket_close(context);
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}

		return rc;
	}else if(rc == MOSQ_ERR_CONN_PENDING){
		mosquitto__set_state(context, mosq_cs_connect_pending);
	}

	HASH_ADD(hh_sock, db.contexts_by_sock, sock, sizeof(context->sock), context);

	rc2 = send__connect(context, context->keepalive, context->clean_start, NULL);
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
		net__socket_close(context);
		return rc2;
	}
}
#endif


int bridge__on_connect(struct mosquitto *context)
{
	int i;
	char *notification_topic;
	size_t notification_topic_len;
	char notification_payload;
	int sub_opts;
	bool retain = true;
	uint8_t qos;

	if(context->bridge->notifications){
		if(context->max_qos == 0){
			qos = 0;
		}else{
			qos = 1;
		}
		if(!context->retain_available){
			retain = false;
		}
		notification_payload = '1';
		if(context->bridge->notification_topic){
			if(!context->bridge->notifications_local_only){
				if(send__real_publish(context, mosquitto__mid_generate(context),
						context->bridge->notification_topic, 1, &notification_payload, qos, retain, 0, NULL, NULL, 0)){

					return 1;
				}
			}
			db__messages_easy_queue(context, context->bridge->notification_topic, qos, 1, &notification_payload, 1, 0, NULL);
		}else{
			notification_topic_len = strlen(context->bridge->remote_clientid)+strlen("$SYS/broker/connection//state");
			notification_topic = mosquitto__malloc(sizeof(char)*(notification_topic_len+1));
			if(!notification_topic) return MOSQ_ERR_NOMEM;

			snprintf(notification_topic, notification_topic_len+1, "$SYS/broker/connection/%s/state", context->bridge->remote_clientid);
			notification_payload = '1';
			if(!context->bridge->notifications_local_only){
				if(send__real_publish(context, mosquitto__mid_generate(context),
						notification_topic, 1, &notification_payload, qos, retain, 0, NULL, NULL, 0)){

					mosquitto__free(notification_topic);
					return 1;
				}
			}
			db__messages_easy_queue(context, notification_topic, qos, 1, &notification_payload, 1, 0, NULL);
			mosquitto__free(notification_topic);
		}
	}
	for(i=0; i<context->bridge->topic_count; i++){
		if(context->bridge->topics[i].direction == bd_in || context->bridge->topics[i].direction == bd_both){
			if(context->bridge->topics[i].qos > context->max_qos){
				sub_opts = context->max_qos;
			}else{
				sub_opts = context->bridge->topics[i].qos;
			}
			if(context->bridge->protocol_version == mosq_p_mqtt5){
				sub_opts = sub_opts
					| MQTT_SUB_OPT_NO_LOCAL
					| MQTT_SUB_OPT_RETAIN_AS_PUBLISHED
					| MQTT_SUB_OPT_SEND_RETAIN_ALWAYS;
			}
			if(send__subscribe(context, NULL, 1, &context->bridge->topics[i].remote_topic, sub_opts, NULL)){
				return 1;
			}
		}else{
			if(context->bridge->attempt_unsubscribe){
				if(send__unsubscribe(context, NULL, 1, &context->bridge->topics[i].remote_topic, NULL)){
					/* direction = inwards only. This means we should not be subscribed
					* to the topic. It is possible that we used to be subscribed to
					* this topic so unsubscribe. */
					return 1;
				}
			}
		}
	}
	for(i=0; i<context->bridge->topic_count; i++){
		if(context->bridge->topics[i].direction == bd_out || context->bridge->topics[i].direction == bd_both){
			if(context->bridge->topics[i].qos > context->max_qos){
				qos = context->max_qos;
			}else{
				qos = context->bridge->topics[i].qos;
			}
			retain__queue(context,
					context->bridge->topics[i].local_topic,
					qos, 0);
		}
	}

	return MOSQ_ERR_SUCCESS;
}


int bridge__register_local_connections(void)
{
#ifdef WITH_EPOLL
	struct mosquitto *context, *ctxt_tmp = NULL;

	HASH_ITER(hh_sock, db.contexts_by_sock, context, ctxt_tmp){
		if(context->bridge){
			if(mux__add_in(context)){
				log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll initial registering bridge: %s", strerror(errno));
				return MOSQ_ERR_UNKNOWN;
			}
		}
	}
#endif
	return MOSQ_ERR_SUCCESS;
}


void bridge__cleanup(struct mosquitto *context)
{
	int i;

	for(i=0; i<db.bridge_count; i++){
		if(db.bridges[i] == context){
			db.bridges[i] = NULL;
		}
	}
	mosquitto__free(context->bridge->local_clientid);
	context->bridge->local_clientid = NULL;

	mosquitto__free(context->bridge->local_username);
	context->bridge->local_username = NULL;

	mosquitto__free(context->bridge->local_password);
	context->bridge->local_password = NULL;

	if(context->bridge->remote_clientid != context->id){
		mosquitto__free(context->bridge->remote_clientid);
	}
	context->bridge->remote_clientid = NULL;

	if(context->bridge->remote_username != context->username){
		mosquitto__free(context->bridge->remote_username);
	}
	context->bridge->remote_username = NULL;

	if(context->bridge->remote_password != context->password){
		mosquitto__free(context->bridge->remote_password);
	}
	context->bridge->remote_password = NULL;
#ifdef WITH_TLS
	if(context->ssl_ctx){
		SSL_CTX_free(context->ssl_ctx);
		context->ssl_ctx = NULL;
	}
#endif
}


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
	int r;
	util__random_bytes(&r, sizeof(int));
	return (r % (cap - base)) + base;
}

static void bridge__backoff_step(struct mosquitto *context)
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

void bridge_check(void)
{
	static time_t last_check = 0;
	struct mosquitto *context = NULL;
	socklen_t len;
	int i;
	int rc;
	int err;

	if(db.now_s <= last_check) return;

	for(i=0; i<db.bridge_count; i++){
		if(!db.bridges[i]) continue;

		context = db.bridges[i];

		if(context->sock != INVALID_SOCKET){
			mosquitto__check_keepalive(context);

			/* Check for bridges that are not round robin and not currently
			 * connected to their primary broker. */
			if(context->bridge->round_robin == false
					&& context->bridge->cur_address != 0
					&& context->bridge->primary_retry
					&& db.now_s > context->bridge->primary_retry){

				if(context->bridge->primary_retry_sock == INVALID_SOCKET){
					rc = net__try_connect(context->bridge->addresses[0].address,
							context->bridge->addresses[0].port,
							&context->bridge->primary_retry_sock,
							context->bridge->bind_address, false);

					if(rc == 0){
						COMPAT_CLOSE(context->bridge->primary_retry_sock);
						context->bridge->primary_retry_sock = INVALID_SOCKET;
						context->bridge->primary_retry = 0;
						net__socket_close(context);
						context->bridge->cur_address = 0;
					}
				}else{
					len = sizeof(int);
					if(!getsockopt(context->bridge->primary_retry_sock, SOL_SOCKET, SO_ERROR, (char *)&err, &len)){
						if(err == 0){
							COMPAT_CLOSE(context->bridge->primary_retry_sock);
							context->bridge->primary_retry_sock = INVALID_SOCKET;
							context->bridge->primary_retry = 0;
							net__socket_close(context);
							context->bridge->cur_address = context->bridge->address_count-1;
						}else{
							COMPAT_CLOSE(context->bridge->primary_retry_sock);
							context->bridge->primary_retry_sock = INVALID_SOCKET;
							context->bridge->primary_retry = db.now_s+5;
						}
					}else{
						COMPAT_CLOSE(context->bridge->primary_retry_sock);
						context->bridge->primary_retry_sock = INVALID_SOCKET;
						context->bridge->primary_retry = db.now_s+5;
					}
				}
			}
		}



		if(context->sock == INVALID_SOCKET){
			/* Want to try to restart the bridge connection */
			if(!context->bridge->restart_t){
				context->bridge->restart_t = db.now_s+context->bridge->restart_timeout;
				context->bridge->cur_address++;
				if(context->bridge->cur_address == context->bridge->address_count){
					context->bridge->cur_address = 0;
				}
			}else{
				if((context->bridge->start_type == bst_lazy && context->bridge->lazy_reconnect)
						|| (context->bridge->start_type == bst_automatic && db.now_s > context->bridge->restart_t)){

#if defined(__GLIBC__) && defined(WITH_ADNS)
					if(context->adns){
						/* Connection attempted, waiting on DNS lookup */
						rc = gai_error(context->adns);
						if(rc == EAI_INPROGRESS){
							/* Just keep on waiting */
						}else if(rc == 0){
							rc = bridge__connect_step2(context);
							if(rc == MOSQ_ERR_SUCCESS){
								mux__add_in(context);
								if(context->current_out_packet){
									mux__add_out(context);
								}
							}else if(rc == MOSQ_ERR_CONN_PENDING){
								context->bridge->restart_t = 0;
							}else{
								context->bridge->cur_address++;
								if(context->bridge->cur_address == context->bridge->address_count){
									context->bridge->cur_address = 0;
								}
								context->bridge->restart_t = 0;
							}
						}else{
							/* Need to retry */
							if(context->adns->ar_result){
								freeaddrinfo(context->adns->ar_result);
							}
							mosquitto__free(context->adns);
							context->adns = NULL;
							context->bridge->restart_t = 0;
						}
					}else{
						rc = bridge__connect_step1(context);
						if(rc){
							context->bridge->cur_address++;
							if(context->bridge->cur_address == context->bridge->address_count){
								context->bridge->cur_address = 0;
							}
						}else{
							/* Short wait for ADNS lookup */
							context->bridge->restart_t = 1;
						}
					}
#else
					{
						rc = bridge__connect(context);
						context->bridge->restart_t = 0;
						if(rc == MOSQ_ERR_SUCCESS){
							if(context->bridge->round_robin == false && context->bridge->cur_address != 0){
								context->bridge->primary_retry = db.now_s + 5;
							}
							mux__add_in(context);
							if(context->current_out_packet){
								mux__add_out(context);
							}
						}else{
							context->bridge->cur_address++;
							if(context->bridge->cur_address == context->bridge->address_count){
								context->bridge->cur_address = 0;
							}
						}
					}
#endif
				}
			}
		}
	}
}

#endif
