/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifndef WIN32
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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
#include "utlist.h"

#ifdef WITH_BRIDGE

static void bridge__backoff_step(struct mosquitto *context);
static void bridge__backoff_reset(struct mosquitto *context);
#if defined(__GLIBC__) && defined(WITH_ADNS)
static int bridge__connect_step1(struct mosquitto *context);
static int bridge__connect_step2(struct mosquitto *context);
#endif
static void bridge__packet_cleanup(struct mosquitto *context);

static struct mosquitto *bridge__new(struct mosquitto__bridge *bridge)
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
		new_context = context__init();
		if(!new_context){
			mosquitto__free(local_id);
			return NULL;
		}
		new_context->id = local_id;
		HASH_ADD_KEYPTR(hh_id, db.contexts_by_id, new_context->id, strlen(new_context->id), new_context);
	}
	new_context->bridge = bridge;
	new_context->is_bridge = true;

	new_context->username = bridge->remote_username;
	new_context->password = bridge->remote_password;

#ifdef WITH_TLS
	new_context->tls_cafile = bridge->tls_cafile;
	new_context->tls_capath = bridge->tls_capath;
	new_context->tls_certfile = bridge->tls_certfile;
	new_context->tls_keyfile = bridge->tls_keyfile;
	new_context->tls_cert_reqs = SSL_VERIFY_PEER;
	new_context->tls_ocsp_required = bridge->tls_ocsp_required;
	new_context->tls_version = bridge->tls_version;
	new_context->tls_insecure = bridge->tls_insecure;
	new_context->tls_alpn = bridge->tls_alpn;
	new_context->tls_ciphers = bridge->tls_ciphers;
	new_context->tls_13_ciphers = bridge->tls_13_ciphers;
	new_context->tls_engine = db.config->default_listener.tls_engine;
	new_context->tls_keyform = db.config->default_listener.tls_keyform;
	new_context->ssl_ctx_defaults = true;
#ifdef FINAL_WITH_TLS_PSK
	new_context->tls_psk_identity = bridge->tls_psk_identity;
	new_context->tls_psk = bridge->tls_psk;
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
		return NULL;
	}

	return new_context;
}

static void bridge__destroy(struct mosquitto *context)
{
	send__disconnect(context, MQTT_RC_SUCCESS, NULL);
	context__cleanup(context, true);
}

void bridge__start_all(void)
{
	int i;

	for(i=0; i<db.config->bridge_count; i++){
		struct mosquitto *context;
		int ret;

		context = bridge__new(db.config->bridges[i]);
		assert(context);

#if defined(__GLIBC__) && defined(WITH_ADNS)
		context->bridge->restart_t = 1; /* force quick restart of bridge */
		ret = bridge__connect_step1(context);
#else
		ret = bridge__connect(context);
#endif

		if (ret){
			log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Unable to connect bridge %s.",
					context->bridge->name);
		}

		db.config->bridges[i] = NULL;
	}
}

static int bridge__set_tcp_keepalive(struct mosquitto *context)
{
	unsigned int idle = context->bridge->tcp_keepalive_idle;
	unsigned int interval = context->bridge->tcp_keepalive_interval;
	unsigned int counter = context->bridge->tcp_keepalive_counter;
	unsigned int enabled = 1;
	bool ret;

	if(idle == 0 || interval == 0 || counter == 0) return MOSQ_ERR_SUCCESS;

#ifdef WIN32
	ret =
		setsockopt(context->sock, SOL_SOCKET, SO_KEEPALIVE, (char *)&enabled, sizeof(enabled)) ||
		setsockopt(context->sock, IPPROTO_TCP, TCP_KEEPIDLE, (char *)&idle, sizeof(idle)) ||
		setsockopt(context->sock, IPPROTO_TCP, TCP_KEEPINTVL, (char *)&interval, sizeof(interval)) ||
		setsockopt(context->sock, IPPROTO_TCP, TCP_KEEPCNT, (char *)&counter, sizeof(counter));
#else
	ret =
		setsockopt(context->sock, SOL_SOCKET, SO_KEEPALIVE, (const void*)&enabled, sizeof(enabled)) ||
		setsockopt(context->sock, IPPROTO_TCP, TCP_KEEPIDLE, (const void*)&idle, sizeof(idle)) ||
		setsockopt(context->sock, IPPROTO_TCP, TCP_KEEPINTVL, (const void*)&interval, sizeof(interval)) ||
		setsockopt(context->sock, IPPROTO_TCP, TCP_KEEPCNT, (const void*)&counter, sizeof(counter));
#endif

	if(ret) return MOSQ_ERR_UNKNOWN;

	return MOSQ_ERR_SUCCESS;
}

#ifdef WITH_TCP_USER_TIMEOUT
static int bridge__set_tcp_user_timeout(struct mosquitto *context) {
	int timeout = context->bridge->tcp_user_timeout;
	if(timeout >= 0) {
		if(setsockopt(context->sock, IPPROTO_TCP, TCP_USER_TIMEOUT, (char *)&timeout, sizeof(timeout))) {
			return MOSQ_ERR_UNKNOWN;
		}
	}

	return MOSQ_ERR_SUCCESS;
}
#endif

#if defined(__GLIBC__) && defined(WITH_ADNS)
static int bridge__connect_step1(struct mosquitto *context)
{
	int rc;
	char *notification_topic;
	size_t notification_topic_len;
	uint8_t notification_payload;
	struct mosquitto__bridge_topic *cur_topic;
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

	LL_FOREACH(context->bridge->topics, cur_topic){
		if(cur_topic->direction == bd_out || cur_topic->direction == bd_both){
			log__printf(NULL, MOSQ_LOG_DEBUG, "Bridge %s doing local SUBSCRIBE on topic %s", context->id, cur_topic->local_topic);
			if(cur_topic->qos > context->max_qos){
				qos = context->max_qos;
			}else{
				qos = cur_topic->qos;
			}
			if(sub__add(context,
						cur_topic->local_topic,
						qos,
						0,
						MQTT_SUB_OPT_NO_LOCAL | MQTT_SUB_OPT_RETAIN_AS_PUBLISHED,
						&db.subs) > 0){
				return 1;
			}
			retain__queue(context,
					cur_topic->local_topic,
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
			mux__delete(context);
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


static int bridge__connect_step2(struct mosquitto *context)
{
	int rc;

	if(!context || !context->bridge) return MOSQ_ERR_INVAL;

	log__printf(NULL, MOSQ_LOG_NOTICE, "Connecting bridge (step 2) %s (%s:%d)", context->bridge->name, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port);
	rc = net__try_connect_step2(context, context->bridge->addresses[context->bridge->cur_address].port, &context->sock);
	if(rc > 0){
		if(rc == MOSQ_ERR_TLS){
			mux__delete(context);
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
		mux__add_out(context);
	}
	return rc;
}


int bridge__connect_step3(struct mosquitto *context)
{
	int rc;
	mosquitto_property topic_alias_max, *topic_alias_max_prop = NULL;

	rc = net__socket_connect_step3(context, context->bridge->addresses[context->bridge->cur_address].address);
	if(rc > 0){
		if(rc == MOSQ_ERR_TLS){
			mux__delete(context);
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

	if (bridge__set_tcp_keepalive(context) != MOSQ_ERR_SUCCESS) return MOSQ_ERR_UNKNOWN;
#ifdef WITH_TCP_USER_TIMEOUT
	if(bridge__set_tcp_user_timeout(context)) return MOSQ_ERR_UNKNOWN;
#endif

	if(context->bridge->max_topic_alias != 0){
		topic_alias_max.next = NULL;
		topic_alias_max.value.i16 = context->bridge->max_topic_alias;
		topic_alias_max.identifier = MQTT_PROP_TOPIC_ALIAS_MAXIMUM;
		topic_alias_max.client_generated = false;
		topic_alias_max_prop = &topic_alias_max;
	}

	rc = send__connect(context, context->keepalive, context->clean_start, topic_alias_max_prop);
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
		mux__delete(context);
		net__socket_close(context);
		return rc;
	}
}
#else

int bridge__connect(struct mosquitto *context)
{
	int rc, rc2;
	char *notification_topic = NULL;
	size_t notification_topic_len;
	uint8_t notification_payload;
	struct mosquitto__bridge_topic *cur_topic;
	uint8_t qos;
	mosquitto_property topic_alias_max, *topic_alias_max_prop = NULL;

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

	LL_FOREACH(context->bridge->topics, cur_topic){
		if(cur_topic->direction == bd_out || cur_topic->direction == bd_both){
			log__printf(NULL, MOSQ_LOG_DEBUG, "Bridge %s doing local SUBSCRIBE on topic %s", context->id, cur_topic->local_topic);
			if(cur_topic->qos > context->max_qos){
				qos = context->max_qos;
			}else{
				qos = cur_topic->qos;
			}
			if(sub__add(context,
						cur_topic->local_topic,
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
			mux__delete(context);
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
		mux__add_out(context);
	}

	HASH_ADD(hh_sock, db.contexts_by_sock, sock, sizeof(context->sock), context);

	if (bridge__set_tcp_keepalive(context) != MOSQ_ERR_SUCCESS) return MOSQ_ERR_UNKNOWN;
#ifdef WITH_TCP_USER_TIMEOUT
	if(bridge__set_tcp_user_timeout(context)) return MOSQ_ERR_UNKNOWN;
#endif

	if(context->bridge->max_topic_alias){
		topic_alias_max.next = NULL;
		topic_alias_max.value.i16 = context->bridge->max_topic_alias;
		topic_alias_max.identifier = MQTT_PROP_TOPIC_ALIAS_MAXIMUM;
		topic_alias_max.client_generated = false;
		topic_alias_max_prop = &topic_alias_max;
	}

	rc2 = send__connect(context, context->keepalive, context->clean_start, topic_alias_max_prop);
	if(rc2 == MOSQ_ERR_SUCCESS){
		return rc;
	}else if(rc2 == MOSQ_ERR_ERRNO && errno == ENOTCONN){
		return MOSQ_ERR_SUCCESS;
	}else{
		if(rc2 == MOSQ_ERR_TLS){
			return rc2; /* Error already printed */
		}else if(rc2 == MOSQ_ERR_ERRNO){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc2 == MOSQ_ERR_EAI){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}
		mux__delete(context);
		net__socket_close(context);
		return rc2;
	}
}
#endif


int bridge__on_connect(struct mosquitto *context)
{
	char *notification_topic;
	size_t notification_topic_len;
	char notification_payload;
	struct mosquitto__bridge_topic *cur_topic;
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
						context->bridge->notification_topic, 1, &notification_payload, qos, retain, 0, 0, NULL, 0)){

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
						notification_topic, 1, &notification_payload, qos, retain, 0, 0, NULL, 0)){

					mosquitto__free(notification_topic);
					return 1;
				}
			}
			db__messages_easy_queue(context, notification_topic, qos, 1, &notification_payload, 1, 0, NULL);
			mosquitto__free(notification_topic);
		}
	}

	LL_FOREACH(context->bridge->topics, cur_topic){
		if(cur_topic->direction == bd_in || cur_topic->direction == bd_both){
			if(cur_topic->qos > context->max_qos){
				sub_opts = context->max_qos;
			}else{
				sub_opts = cur_topic->qos;
			}
			if(context->bridge->protocol_version == mosq_p_mqtt5){
				sub_opts = sub_opts
					| MQTT_SUB_OPT_NO_LOCAL
					| MQTT_SUB_OPT_RETAIN_AS_PUBLISHED
					| MQTT_SUB_OPT_SEND_RETAIN_ALWAYS;
			}
			if(send__subscribe(context, NULL, 1, &cur_topic->remote_topic, sub_opts, NULL)){
				return 1;
			}
		}else{
			if(context->bridge->attempt_unsubscribe){
				if(send__unsubscribe(context, NULL, 1, &cur_topic->remote_topic, NULL)){
					/* direction = inwards only. This means we should not be subscribed
					* to the topic. It is possible that we used to be subscribed to
					* this topic so unsubscribe. */
					return 1;
				}
			}
		}
	}
	LL_FOREACH(context->bridge->topics, cur_topic){
		if(cur_topic->direction == bd_out || cur_topic->direction == bd_both){
			if(cur_topic->qos > context->max_qos){
				qos = context->max_qos;
			}else{
				qos = cur_topic->qos;
			}
			retain__queue(context,
					cur_topic->local_topic,
					qos, 0);
		}
	}

	bridge__backoff_reset(context);

	return MOSQ_ERR_SUCCESS;
}


int bridge__register_local_connections(void)
{
	struct mosquitto *context, *ctxt_tmp = NULL;

	HASH_ITER(hh_sock, db.contexts_by_sock, context, ctxt_tmp){
		if(context->bridge){
			if(mux__new(context)){
				log__printf(NULL, MOSQ_LOG_ERR, "Error in initial bridge registration: %s", strerror(errno));
				return MOSQ_ERR_UNKNOWN;
			}
			mux__add_out(context);
		}
	}
	return MOSQ_ERR_SUCCESS;
}


void bridge__reload(void)
{
	int i;
	int j;

	// destroy old bridges that dissappeared
	for(i=0;i<db.bridge_count;i++){
		for(j=0;j<db.config->bridge_count;j++){
			if(!strcmp(db.bridges[i]->bridge->name, db.config->bridges[j]->name)) break;
		}

		if(j==db.config->bridge_count){
			bridge__destroy(db.bridges[i]);
		}
	}

	for(i=0;i<db.config->bridge_count;i++){
		for(j=0;j<db.bridge_count; j++){
			if(!strcmp(db.config->bridges[i]->name, db.bridges[j]->bridge->name)) break;
		}

		if(j==db.bridge_count){
			// a new bridge was found, create it
			bridge__new(db.config->bridges[i]);
			db.config->bridges[i] = NULL;
			continue;
		}

		if(db.config->bridges[i]->reload_type == brt_immediate){
			// in this case, an existing bridge should match
			for(j=0;j<db.bridge_count;j++){
				if(!strcmp(db.config->bridges[i]->name, db.bridges[j]->bridge->name)) break;
			}

			assert(j<db.bridge_count);
			db.bridges[j]->will_delay_interval = 0;
			bridge__destroy(db.bridges[j]);
			bridge__new(db.config->bridges[i]);
			db.config->bridges[i] = NULL;
		}
	}
}

void bridge__db_cleanup(void)
{
	int i;

	for(i=0; i<db.bridge_count; i++){
		if(db.bridges[i]){
			context__cleanup(db.bridges[i], true);
		}
	}
	mosquitto__free(db.bridges);
}


void bridge__cleanup(struct mosquitto *context)
{
	int i;

	assert(db.bridge_count > 0);

	for(i=0; i<db.bridge_count; i++){
		if(db.bridges[i] == context){
			db.bridges[i] = db.bridges[db.bridge_count-1];
			break;
		}
	}

	db.bridge_count--;
	db.bridges = mosquitto__realloc(db.bridges, (unsigned) db.bridge_count * sizeof(db.bridges[0]));

	mosquitto__free(context->bridge->name);
	context->bridge->name = NULL;

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

	for(i=0; i<context->bridge->address_count; i++){
		mosquitto__free(context->bridge->addresses[i].address);
	}

	mosquitto__free(context->bridge->addresses);
	context->bridge->addresses = NULL;

	config__bridge_cleanup(context->bridge);
	context->bridge = NULL;
}


static void bridge__packet_cleanup(struct mosquitto *context)
{
	struct mosquitto__packet *packet;
	if(!context) return;

    while(context->out_packet){
		packet = context->out_packet;
		context->out_packet = context->out_packet->next;
		mosquitto__free(packet);
	}
	context->out_packet = NULL;
	context->out_packet_last = NULL;
	context->out_packet_count = 0;

	packet__cleanup(&(context->in_packet));
}

static int rand_between(int low, int high)
{
	int r;
	util__random_bytes(&r, sizeof(int));
	return (abs(r) % (high - low)) + low;
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


static void bridge_check_pending(struct mosquitto *context)
{
	int err;
	socklen_t len;

	if(context->state == mosq_cs_connect_pending){
		len = sizeof(int);
		if(!getsockopt(context->sock, SOL_SOCKET, SO_ERROR, (char *)&err, &len)){
			if(err == 0){
				mosquitto__set_state(context, mosq_cs_new);
#if defined(WITH_ADNS) && defined(WITH_BRIDGE)
				if(context->bridge){
					bridge__connect_step3(context);
				}
#endif
			}else if(err == ECONNREFUSED){
				do_disconnect(context, MOSQ_ERR_CONN_LOST);
				return;
			}
		}else{
			do_disconnect(context, MOSQ_ERR_CONN_LOST);
			return;
		}
	}
}

static bool reload_if_needed(struct mosquitto *context)
{
	int i;

	for(i=0;i<db.config->bridge_count;i++){
		if(db.config->bridges[i] && !strcmp(context->bridge->name, db.config->bridges[i]->name)){
			bridge__destroy(context);
			bridge__new(db.config->bridges[i]);
			db.config->bridges[i] = NULL;
			return true;
		}
	}

	return false;
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

		if(net__is_connected(context)){
			mosquitto__check_keepalive(context);
			bridge_check_pending(context);

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
						mux__delete(context);
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
							mux__delete(context);
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

		if(!net__is_connected(context)){
			if(reload_if_needed(context)) continue;

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
								mux__new(context);
								if(context->out_packet){
									mux__add_out(context);
								}
							}else if(rc == MOSQ_ERR_CONN_PENDING){
								mux__new(context);
								mux__add_out(context);
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
						if(rc == MOSQ_ERR_SUCCESS || rc == MOSQ_ERR_CONN_PENDING){
							if(context->bridge->round_robin == false && context->bridge->cur_address != 0){
								context->bridge->primary_retry = db.now_s + 5;
							}
							mux__new(context);
							if(context->out_packet){
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
