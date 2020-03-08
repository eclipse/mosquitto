/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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

#ifndef WIN32
#ifdef WITH_EPOLL
#include <sys/epoll.h>
#endif
#include <poll.h>
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

int bridge__new(struct mosquitto_db *db, struct mosquitto__bridge *bridge)
{
	struct mosquitto *new_context = NULL;
	struct mosquitto **bridges;
	char *local_id;
	int rc;

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
	new_context->tls_ocsp_required = new_context->bridge->tls_ocsp_required;
	new_context->tls_version = new_context->bridge->tls_version;
	new_context->tls_insecure = new_context->bridge->tls_insecure;
	new_context->tls_alpn = new_context->bridge->tls_alpn;
	new_context->tls_engine = db->config->default_listener.tls_engine;
	new_context->tls_keyform = db->config->default_listener.tls_keyform;
#ifdef FINAL_WITH_TLS_PSK
	new_context->tls_psk_identity = new_context->bridge->tls_psk_identity;
	new_context->tls_psk = new_context->bridge->tls_psk;
#endif
#endif

	bridge->try_private_accepted = true;
	new_context->retain_available = bridge->outgoing_retain;
	new_context->protocol = bridge->protocol_version;

	bridges = mosquitto__realloc(db->bridges, (db->bridge_count+1)*sizeof(struct mosquitto *));
	if(bridges){
		db->bridges = bridges;
		db->bridge_count++;
		db->bridges[db->bridge_count-1] = new_context;
	}else{
		return MOSQ_ERR_NOMEM;
	}

	new_context->bridge->restart_t = 1; /* force quick restart of bridge */
	mosquitto__set_state(new_context, mosq_cs_new);

	rc = bridge__connect(db, new_context);
	if (rc == MOSQ_ERR_DNS_RESOLVE_PENDING) {
		return MOSQ_ERR_SUCCESS;
	}
	return rc;
}

int bridge__connect(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;

	int state = mosquitto__get_state(context);
	switch (state) {
	case mosq_cs_disconnected:
		/* fall through */
	case mosq_cs_new:
		/* fall through */
	case mosq_cs_dns_resolve_pending:
		rc = bridge__connect_step1(db, context);
		if (rc != MOSQ_ERR_SUCCESS) {
			return rc;
		}

		rc = bridge__connect_step2(db, context);
		if (rc == MOSQ_ERR_CONN_PENDING) {
			return MOSQ_ERR_SUCCESS;
		} else if (rc != MOSQ_ERR_SUCCESS) {
			return rc;
		}
		/* fall through */

	case mosq_cs_connect_pending:
	case mosq_cs_ssl_connect_pending:
		rc = bridge__connect_step3(db, context);
		if (rc == MOSQ_ERR_SSL_CONN_PENDING) {
			return MOSQ_ERR_SUCCESS;
		} else {
			return rc;
		}

	default:
		log__printf(NULL, MOSQ_LOG_ERR, "Trying to connect bridge[%s] in invalid state:%d",
			context->id ? context->id : "Unknown", state);
		return MOSQ_ERR_INVAL;
	}
}

int bridge__connect_step1(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;
	char *notification_topic;
	int notification_topic_len;
	uint8_t notification_payload;
	int i;

	if(!context || !context->bridge) return MOSQ_ERR_INVAL;
	
	log__printf(NULL, MOSQ_LOG_NOTICE, "Connecting bridge (step 1) %s (%s:%d)",
				context->bridge->name,
				context->bridge->addresses[context->bridge->cur_address].address,
				context->bridge->addresses[context->bridge->cur_address].port);

	rc = net__socket_connect_step1(context, &context->adns,
		&context->bridge->addresses[context->bridge->cur_address].ainfo,
		context->bridge->addresses[context->bridge->cur_address].address,
		context->bridge->addresses[context->bridge->cur_address].port, false);
	if(rc == MOSQ_ERR_DNS_RESOLVE_PENDING){
		mosquitto__set_state(context, mosq_cs_dns_resolve_pending);
		return rc;
	} else if(rc != MOSQ_ERR_SUCCESS){
		context->bridge->restart_t = 0;
		mosquitto__set_state(context, mosq_cs_new);
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

	if (context->sock != INVALID_SOCKET) {
		COMPAT_CLOSE(context->sock);
		context->sock = INVALID_SOCKET;
	}
	context->last_msg_in = mosquitto_time();
	context->next_msg_out = mosquitto_time() + context->bridge->keepalive;
	context->keepalive = context->bridge->keepalive;
	context->clean_start = context->bridge->clean_start;
	context->in_packet.payload = NULL;
	context->ping_t = 0;
	context->bridge->lazy_reconnect = false;
	bridge__packet_cleanup(context);
	db__message_reconnect_reset(db, context);

	if(context->clean_start){
		db__messages_delete(db, context);
	}

	/* Delete all local subscriptions even for clean_start==false. We don't
	 * remove any messages and the next loop carries out the resubscription
	 * anyway. This means any unwanted subs will be removed.
	 */
	sub__clean_session(db, context);

	for(i=0; i<context->bridge->topic_count; i++){
		if(context->bridge->topics[i].direction == bd_out || context->bridge->topics[i].direction == bd_both){
			log__printf(NULL, MOSQ_LOG_DEBUG, "Bridge %s doing local SUBSCRIBE on topic %s", context->id, context->bridge->topics[i].local_topic);
			if(sub__add(db,
						context,
						context->bridge->topics[i].local_topic,
						context->bridge->topics[i].qos,
						0,
						MQTT_SUB_OPT_NO_LOCAL | MQTT_SUB_OPT_RETAIN_AS_PUBLISHED,
						&db->subs) > 0){
				return 1;
			}
		}
	}

	/* prepare backoff for a possible failure. Restart timeout will be reset if connection gets established */
	bridge__backoff_step(context);

	if(context->bridge->notifications){
		if(context->bridge->notification_topic){
			if(!context->bridge->initial_notification_done){
				notification_payload = '0';
				db__messages_easy_queue(db, context, context->bridge->notification_topic, 1, 1, &notification_payload, 1, 0, NULL);
				context->bridge->initial_notification_done = true;
			}
			
			if (!context->bridge->notifications_local_only) {
				notification_payload = '0';
				rc = will__set(context, context->bridge->notification_topic, 1, &notification_payload, 1, true, NULL);
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
				db__messages_easy_queue(db, context, notification_topic, 1, 1, &notification_payload, 1, 0, NULL);
				context->bridge->initial_notification_done = true;
			}

			if (!context->bridge->notifications_local_only) {
				notification_payload = '0';
				rc = will__set(context, notification_topic, 1, &notification_payload, 1, true, NULL);
				mosquitto__free(notification_topic);
				if(rc != MOSQ_ERR_SUCCESS){
					return rc;
				}
			}
		}
	}

	return MOSQ_ERR_SUCCESS;
}

int bridge__connect_step2(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;

	if(!context || !context->bridge) return MOSQ_ERR_INVAL;

	log__printf(NULL, MOSQ_LOG_NOTICE, "Connecting bridge (step 2) %s (%s:%d)",
				context->bridge->name,
				context->bridge->addresses[context->bridge->cur_address].address,
				context->bridge->addresses[context->bridge->cur_address].port);
	rc = net__socket_connect_step2(context, &context->sock,
		context->bridge->addresses[context->bridge->cur_address].address,
		context->bridge->addresses[context->bridge->cur_address].ainfo, NULL, false, false);
	if (rc == MOSQ_ERR_CONN_PENDING) {
		mosquitto__set_state(context, mosq_cs_connect_pending);
	} else if(rc != MOSQ_ERR_SUCCESS){
		context->bridge->restart_t = 0;
		mosquitto__set_state(context, mosq_cs_new);
		if(rc == MOSQ_ERR_TLS){
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}
		return rc;
	}

	HASH_ADD(hh_sock, db->contexts_by_sock, sock, sizeof(context->sock), context);

	return rc;
}


int bridge__connect_step3(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;

	log__printf(NULL, MOSQ_LOG_NOTICE, "Connecting bridge (step 3) %s (%s:%d)",
				context->bridge->name,
				context->bridge->addresses[context->bridge->cur_address].address,
				context->bridge->addresses[context->bridge->cur_address].port);
	rc = net__socket_connect_step3(context, context->bridge->addresses[context->bridge->cur_address].address);
	if (rc == MOSQ_ERR_SUCCESS) {
		mosquitto__set_state(context, mosq_cs_connected);
	} else if (rc == MOSQ_ERR_SSL_CONN_PENDING) {
		mosquitto__set_state(context, mosq_cs_ssl_connect_pending);
		return rc;
	} else {
		context->bridge->restart_t = 0;
		mosquitto__set_state(context, mosq_cs_new);
		if(rc == MOSQ_ERR_TLS){
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

	rc = send__connect(context, context->keepalive, context->clean_start, NULL);
	if(rc == MOSQ_ERR_SUCCESS){
		bridge__backoff_reset(context);
		return MOSQ_ERR_SUCCESS;
	}else if(rc == MOSQ_ERR_ERRNO && errno == ENOTCONN){
		bridge__backoff_reset(context);
		return MOSQ_ERR_SUCCESS;
	}else{
		if(rc == MOSQ_ERR_TLS){
			/* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			log__printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}
		return rc;
	}
}


int bridge__on_connect(struct mosquitto_db *db, struct mosquitto *context)
{
	int i;
	char *notification_topic;
	int notification_topic_len;
	char notification_payload;
	int sub_opts;
	bool retain = true;

	if(context->bridge->notifications){
		if(!context->retain_available){
			retain = false;
		}
		notification_payload = '1';
		if(context->bridge->notification_topic){
			if(!context->bridge->notifications_local_only){
				if(send__real_publish(context, mosquitto__mid_generate(context),
						context->bridge->notification_topic, 1, &notification_payload, 1, retain, 0, NULL, NULL, 0)){

					return 1;
				}
			}
			db__messages_easy_queue(db, context, context->bridge->notification_topic, 1, 1, &notification_payload, 1, 0, NULL);
		}else{
			notification_topic_len = strlen(context->bridge->remote_clientid)+strlen("$SYS/broker/connection//state");
			notification_topic = mosquitto__malloc(sizeof(char)*(notification_topic_len+1));
			if(!notification_topic) return MOSQ_ERR_NOMEM;

			snprintf(notification_topic, notification_topic_len+1, "$SYS/broker/connection/%s/state", context->bridge->remote_clientid);
			notification_payload = '1';
			if(!context->bridge->notifications_local_only){
				if(send__real_publish(context, mosquitto__mid_generate(context),
						notification_topic, 1, &notification_payload, 1, retain, 0, NULL, NULL, 0)){

					mosquitto__free(notification_topic);
					return 1;
				}
			}
			db__messages_easy_queue(db, context, notification_topic, 1, 1, &notification_payload, 1, 0, NULL);
			mosquitto__free(notification_topic);
		}
	}
	for(i=0; i<context->bridge->topic_count; i++){
		if(context->bridge->topics[i].direction == bd_in || context->bridge->topics[i].direction == bd_both){
			sub_opts = context->bridge->topics[i].qos;
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
			retain__queue(db, context,
					context->bridge->topics[i].local_topic,
					context->bridge->topics[i].qos, 0);
		}
	}

	return MOSQ_ERR_SUCCESS;
}


int bridge__register_local_connections(struct mosquitto_db *db)
{
#ifdef WITH_EPOLL
	struct epoll_event ev;
	struct mosquitto *context, *ctxt_tmp = NULL;

	memset(&ev, 0, sizeof(struct epoll_event));

	HASH_ITER(hh_sock, db->contexts_by_sock, context, ctxt_tmp){
		if(context->bridge){
			ev.data.fd = context->sock;
			ev.events = EPOLLIN;
			context->events = EPOLLIN;
			if (epoll_ctl(db->epollfd, EPOLL_CTL_ADD, context->sock, &ev) == -1) {
				log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll initial registering bridge: %s", strerror(errno));
				(void)close(db->epollfd);
				db->epollfd = 0;
				return MOSQ_ERR_UNKNOWN;
			}
		}
	}
#endif
	return MOSQ_ERR_SUCCESS;
}


void bridge__cleanup(struct mosquitto_db *db, struct mosquitto *context)
{
	int i;

	for(i=0; i<db->bridge_count; i++){
		if(db->bridges[i] == context){
			db->bridges[i] = NULL;
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

#ifdef WITH_EPOLL
void bridge_check(struct mosquitto_db *db)
#else
void bridge_check(struct mosquitto_db *db, struct pollfd *pollfds, int *pollfd_index)
#endif
{
	static time_t last_check = 0;
	time_t now;
	struct mosquitto *context = NULL;
#ifdef WITH_EPOLL
	struct epoll_event ev;
#endif
	int i;
	int rc;

	now = mosquitto_time();

	if(now <= last_check) return;

#ifdef WITH_EPOLL
	memset(&ev, 0, sizeof(struct epoll_event));
#endif
	for(i=0; i<db->bridge_count; i++){
		if(!db->bridges[i]) continue;

		context = db->bridges[i];

		if(context->sock != INVALID_SOCKET){
			mosquitto__check_keepalive(db, context);

			/* Check for bridges that are not round robin and not currently
			 * connected to their primary broker. */
			if(context->bridge->round_robin == false
					&& context->bridge->cur_address != 0
					&& context->bridge->primary_retry
					&& now > context->bridge->primary_retry){

				if(context->bridge->primary_retry_sock == INVALID_SOCKET){
					rc = net__try_connect(context, context->bridge->addresses[0].address,
							context->bridge->addresses[0].port,
							&context->bridge->primary_retry_sock, NULL, false, true);

					if(rc == 0){
						COMPAT_CLOSE(context->bridge->primary_retry_sock);
						context->bridge->primary_retry_sock = INVALID_SOCKET;
						context->bridge->primary_retry = 0;
						net__socket_close(db, context);
						context->bridge->cur_address = 0;
					}
				}else{
					rc = net__socket_nonblock_connected(context, context->bridge->primary_retry_sock);
					if (rc == MOSQ_ERR_CONN_PENDING) {
						/* Check next time */
					} else  if(rc == MOSQ_ERR_SUCCESS) {
						COMPAT_CLOSE(context->bridge->primary_retry_sock);
						context->bridge->primary_retry_sock = INVALID_SOCKET;
						context->bridge->primary_retry = 0;
						net__socket_close(db, context);
						context->bridge->cur_address = context->bridge->address_count-1;
					}else{
						COMPAT_CLOSE(context->bridge->primary_retry_sock);
						context->bridge->primary_retry_sock = INVALID_SOCKET;
						context->bridge->primary_retry = now+5;
					}
				}
			}
		}

		if(context->sock == INVALID_SOCKET){
			/* Want to try to restart the bridge connection */
			if(!context->bridge->restart_t){
				context->bridge->restart_t = now+context->bridge->restart_timeout;
				context->bridge->cur_address++;
				if(context->bridge->cur_address == context->bridge->address_count){
					context->bridge->cur_address = 0;
				}
			}else{
				if((context->bridge->start_type == bst_lazy && context->bridge->lazy_reconnect)
						|| (context->bridge->start_type == bst_automatic && now > context->bridge->restart_t)){
					rc = bridge__connect(db, context);
					if(rc == MOSQ_ERR_DNS_RESOLVE_PENDING){
						/* Just keep on waiting */
					}else if(rc == MOSQ_ERR_SUCCESS){
#ifdef WITH_EPOLL
						ev.data.fd = context->sock;
						ev.events = EPOLLIN;
						if(context_want_write(context)){
							ev.events |= EPOLLOUT;
						}
						if(epoll_ctl(db->epollfd, EPOLL_CTL_ADD, context->sock, &ev) == -1) {
							if((errno != EEXIST)||(epoll_ctl(db->epollfd, EPOLL_CTL_MOD, context->sock, &ev) == -1)) {
									log__printf(NULL, MOSQ_LOG_DEBUG, "Error in epoll re-registering bridge: %s", strerror(errno));
							}
						}else{
							context->events = ev.events;
						}
#else
						pollfds[*pollfd_index].fd = context->sock;
						pollfds[*pollfd_index].events = POLLIN;
						pollfds[*pollfd_index].revents = 0;
						if(context_want_write(context)){
							pollfds[*pollfd_index].events |= POLLOUT;
						}
						context->pollfd_index = *pollfd_index;
						(*pollfd_index)++;
#endif
					}else{
						context->bridge->cur_address++;
						if(context->bridge->cur_address == context->bridge->address_count){
							context->bridge->cur_address = 0;
						}
						context->bridge->restart_t = 0;
						do_disconnect(db, context, rc);
					}
				}
			}
		}
	}
}

#endif
