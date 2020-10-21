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
   Tatsuzo Osawa - Add epoll.
*/

#include "config.h"

#ifndef WIN32
#  define _GNU_SOURCE
#endif

#include <assert.h>
#ifndef WIN32
#include <unistd.h>
#else
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#  include <sys/socket.h>
#endif
#include <time.h>
#include <utlist.h>

#ifdef WITH_WEBSOCKETS
#  include <libwebsockets.h>
#endif

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "send_mosq.h"
#include "sys_tree.h"
#include "time_mosq.h"
#include "util_mosq.h"

extern bool flag_reload;
#ifdef WITH_PERSISTENCE
extern bool flag_db_backup;
#endif
extern bool flag_tree_print;
extern int run;

#if defined(WITH_WEBSOCKETS) && LWS_LIBRARY_VERSION_NUMBER == 3002000
void lws__sul_callback(struct lws_sorted_usec_list *l)
{
}

static struct lws_sorted_usec_list sul;
#endif

static int single_publish(struct mosquitto_db *db, struct mosquitto *context, struct mosquitto_message_v5 *msg)
{
	struct mosquitto_msg_store *stored;
	uint16_t mid;

	stored = mosquitto__calloc(1, sizeof(struct mosquitto_msg_store));
	if(stored == NULL) return MOSQ_ERR_NOMEM;

	stored->topic = msg->topic;
	msg->topic = NULL;
	stored->retain = 0;
	stored->payloadlen = (uint32_t)msg->payloadlen;
	if(UHPA_ALLOC(stored->payload, stored->payloadlen) == 0){
		db__msg_store_free(stored);
		return MOSQ_ERR_NOMEM;
	}
	memcpy(UHPA_ACCESS(stored->payload, stored->payloadlen), msg->payload, stored->payloadlen);

	if(msg->properties){
		stored->properties = msg->properties;
		msg->properties = NULL;
	}

	if(db__message_store(db, context, stored, 0, 0, mosq_mo_broker)) return 1;

	if(msg->qos){
		mid = mosquitto__mid_generate(context);
	}else{
		mid = 0;
	}
	return db__message_insert(db, context, mid, mosq_md_out, (uint8_t)msg->qos, 0, stored, msg->properties, true);
}


void queue_plugin_msgs(struct mosquitto_db *db)
{
	struct mosquitto_message_v5 *msg, *tmp;
	struct mosquitto *context;

	DL_FOREACH_SAFE(db->plugin_msgs, msg, tmp){
		DL_DELETE(db->plugin_msgs, msg);
		if(msg->clientid){
			HASH_FIND(hh_id, db->contexts_by_id, msg->clientid, strlen(msg->clientid), context);
			if(context){
				single_publish(db, context, msg);
			}
		}else{
			db__messages_easy_queue(db, NULL, msg->topic, (uint8_t)msg->qos, (uint32_t)msg->payloadlen, msg->payload, msg->retain, 0, &msg->properties);
		}
		mosquitto__free(msg->topic);
		mosquitto__free(msg->payload);
		mosquitto_property_free_all(&msg->properties);
		mosquitto__free(msg->clientid);
		mosquitto__free(msg);
	}
}


int mosquitto_main_loop(struct mosquitto_db *db, mosq_sock_t *listensock, int listensock_count)
{
#ifdef WITH_SYS_TREE
	time_t start_time = mosquitto_time();
#endif
#ifdef WITH_PERSISTENCE
	time_t last_backup = mosquitto_time();
#endif
	time_t now = 0;
#ifdef WITH_WEBSOCKETS
	int i;
#endif
	int rc;


#if defined(WITH_WEBSOCKETS) && LWS_LIBRARY_VERSION_NUMBER == 3002000
	memset(&sul, 0, sizeof(struct lws_sorted_usec_list));
#endif

	rc = mux__init(db, listensock, listensock_count);
	if(rc) return rc;

#ifdef WITH_BRIDGE
	rc = bridge__register_local_connections(db);
	if(rc) return rc;
#endif

	while(run){
		queue_plugin_msgs(db);
		context__free_disused(db);
#ifdef WITH_SYS_TREE
		if(db->config->sys_interval > 0){
			sys_tree__update(db, db->config->sys_interval, start_time);
		}
#endif

		now = mosquitto_time();
		keepalive__check(db, now);

#ifdef WITH_BRIDGE
		bridge_check(db);
#endif

		rc = mux__handle(db, listensock, listensock_count);
		if(rc) return rc;

		now = time(NULL);
		session_expiry__check(db, now);
		will_delay__check(db, now);
#ifdef WITH_PERSISTENCE
		if(db->config->persistence && db->config->autosave_interval){
			if(db->config->autosave_on_changes){
				if(db->persistence_changes >= db->config->autosave_interval){
					persist__backup(db, false);
					db->persistence_changes = 0;
				}
			}else{
				if(last_backup + db->config->autosave_interval < mosquitto_time()){
					persist__backup(db, false);
					last_backup = mosquitto_time();
				}
			}
		}
#endif

#ifdef WITH_PERSISTENCE
		if(flag_db_backup){
			persist__backup(db, false);
			flag_db_backup = false;
		}
#endif
		if(flag_reload){
			log__printf(NULL, MOSQ_LOG_INFO, "Reloading config.");
			config__read(db, db->config, true);
			mosquitto_security_cleanup(db, true);
			mosquitto_security_init(db, true);
			mosquitto_security_apply(db);
			log__close(db->config);
			log__init(db->config);
			flag_reload = false;
		}
		if(flag_tree_print){
			sub__tree_print(db->subs, 0);
			flag_tree_print = false;
		}
#ifdef WITH_WEBSOCKETS
		for(i=0; i<db->config->listener_count; i++){
			/* Extremely hacky, should be using the lws provided external poll
			 * interface, but their interface has changed recently and ours
			 * will soon, so for now websockets clients are second class
			 * citizens. */
			if(db->config->listeners[i].ws_context){
#if LWS_LIBRARY_VERSION_NUMBER > 3002000
				libwebsocket_service(db->config->listeners[i].ws_context, -1);
#elif LWS_LIBRARY_VERSION_NUMBER == 3002000
				lws_sul_schedule(db->config->listeners[i].ws_context, 0, &sul, lws__sul_callback, 10);
				libwebsocket_service(db->config->listeners[i].ws_context, 0);
#else
				libwebsocket_service(db->config->listeners[i].ws_context, 0);
#endif

			}
		}
#endif
	}

	mux__cleanup(db);

	return MOSQ_ERR_SUCCESS;
}

void do_disconnect(struct mosquitto_db *db, struct mosquitto *context, int reason)
{
	char *id;
#ifdef WITH_WEBSOCKETS
	bool is_duplicate = false;
#endif

	if(context->state == mosq_cs_disconnected){
		return;
	}
#ifdef WITH_WEBSOCKETS
	if(context->wsi){
		if(context->state == mosq_cs_duplicate){
			is_duplicate = true;
		}

		if(context->state != mosq_cs_disconnecting && context->state != mosq_cs_disconnect_with_will){
			mosquitto__set_state(context, mosq_cs_disconnect_ws);
		}
		if(context->wsi){
			libwebsocket_callback_on_writable(context->ws_context, context->wsi);
		}
		if(context->sock != INVALID_SOCKET){
			HASH_DELETE(hh_sock, db->contexts_by_sock, context);
			mux__delete(db, context);
			context->sock = INVALID_SOCKET;
		}
		if(is_duplicate){
			/* This occurs if another client is taking over the same client id.
			 * It is important to remove this from the by_id hash here, so it
			 * doesn't leave us with multiple clients in the hash with the same
			 * id. Websockets doesn't actually close the connection here,
			 * unlike for normal clients, which means there is extra time when
			 * there could be two clients with the same id in the hash. */
			context__remove_from_by_id(db, context);
		}
	}else
#endif
	{
		if(db->config->connection_messages == true){
			if(context->id){
				id = context->id;
			}else{
				id = "<unknown>";
			}
			if(context->state != mosq_cs_disconnecting && context->state != mosq_cs_disconnect_with_will){
				switch(reason){
					case MOSQ_ERR_SUCCESS:
						break;
					case MOSQ_ERR_MALFORMED_PACKET:
						log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected due to malformed packet.", id);
						break;
					case MOSQ_ERR_PROTOCOL:
						log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected due to protocol error.", id);
						break;
					case MOSQ_ERR_CONN_LOST:
						log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s closed its connection.", id);
						break;
					case MOSQ_ERR_AUTH:
						log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected, no longer authorised.", id);
						break;
					case MOSQ_ERR_KEEPALIVE:
						log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s has exceeded timeout, disconnecting.", id);
						break;
					case MOSQ_ERR_ADMINISTRATIVE_ACTION:
						log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s been disconnected by administrative action.", id);
						break;
					default:
						log__printf(NULL, MOSQ_LOG_NOTICE, "Socket error on client %s, disconnecting.", id);
						break;
				}
			}else{
				if(reason == MOSQ_ERR_ADMINISTRATIVE_ACTION){
					log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s been disconnected by administrative action.", id);
				}else{
					log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected.", id);
				}
			}
		}
		mux__delete(db, context);
		context__disconnect(db, context);
	}
}


