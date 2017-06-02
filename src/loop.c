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

#define _GNU_SOURCE

#include <config.h>

#include <assert.h>
#ifndef WIN32
#include <poll.h>
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

static void loop_handle_reads_writes(struct mosquitto_db *db, struct pollfd *pollfds);

#ifdef WITH_WEBSOCKETS
static void temp__expire_websockets_clients(struct mosquitto_db *db)
{
	struct mosquitto *context, *ctxt_tmp;
	static time_t last_check = 0;
	time_t now = mosquitto_time();
	char *id;

	if(now - last_check > 60){
		HASH_ITER(hh_id, db->contexts_by_id, context, ctxt_tmp){
			if(context->wsi && context->sock != INVALID_SOCKET){
				if(context->keepalive && now - context->last_msg_in > (time_t)(context->keepalive)*3/2){
					if(db->config->connection_messages == true){
						if(context->id){
							id = context->id;
						}else{
							id = "<unknown>";
						}
						log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s has exceeded timeout, disconnecting.", id);
					}
					/* Client has exceeded keepalive*1.5 */
					do_disconnect(db, context);
				}
			}
		}
		last_check = mosquitto_time();
	}
}
#endif

int mosquitto_main_loop(struct mosquitto_db *db, mosq_sock_t *listensock, int listensock_count, int listener_max)
{
#ifdef WITH_SYS_TREE
	time_t start_time = mosquitto_time();
#endif
#ifdef WITH_PERSISTENCE
	time_t last_backup = mosquitto_time();
#endif
	time_t now = 0;
	time_t now_time;
	int time_count;
	int fdcount;
	struct mosquitto *context, *ctxt_tmp;
#ifndef WIN32
	sigset_t sigblock, origsig;
#endif
	int i;
	struct pollfd *pollfds = NULL;
	int pollfd_count = 0;
	int pollfd_index;
#ifdef WITH_BRIDGE
	mosq_sock_t bridge_sock;
	int rc;
#endif
	int context_count;
	time_t expiration_check_time = 0;
	char *id;

#ifndef WIN32
	sigemptyset(&sigblock);
	sigaddset(&sigblock, SIGINT);
	sigaddset(&sigblock, SIGTERM);
	sigaddset(&sigblock, SIGUSR1);
	sigaddset(&sigblock, SIGUSR2);
#endif

	if(db->config->persistent_client_expiration > 0){
		expiration_check_time = time(NULL) + 3600;
	}

	while(run){
		context__free_disused(db);
#ifdef WITH_SYS_TREE
		if(db->config->sys_interval > 0){
			sys_tree__update(db, db->config->sys_interval, start_time);
		}
#endif

		context_count = HASH_CNT(hh_sock, db->contexts_by_sock);
#ifdef WITH_BRIDGE
		context_count += db->bridge_count;
#endif
#ifdef WITH_KAFKA_BRIDGE
		context_count += db->kafka_bridge_count;
#endif

		if(listensock_count + context_count > pollfd_count || !pollfds){
			pollfd_count = listensock_count + context_count;
			pollfds = mosquitto__realloc(pollfds, sizeof(struct pollfd)*pollfd_count);
			if(!pollfds){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				return MOSQ_ERR_NOMEM;
			}
		}

		memset(pollfds, -1, sizeof(struct pollfd)*pollfd_count);

		pollfd_index = 0;
		for(i=0; i<listensock_count; i++){
			pollfds[pollfd_index].fd = listensock[i];
			pollfds[pollfd_index].events = POLLIN;
			pollfds[pollfd_index].revents = 0;
			pollfd_index++;
		}

		now_time = time(NULL);

		time_count = 0;
		HASH_ITER(hh_sock, db->contexts_by_sock, context, ctxt_tmp){
			if(time_count > 0){
				time_count--;
			}else{
				time_count = 1000;
				now = mosquitto_time();
			}
			context->pollfd_index = -1;

			if(context->sock != INVALID_SOCKET){
#ifdef WITH_BRIDGE
				if(context->bridge){
					mosquitto__check_keepalive(db, context);
					if(context->bridge->round_robin == false
							&& context->bridge->cur_address != 0
							&& now > context->bridge->primary_retry){

						if(net__try_connect(context, context->bridge->addresses[0].address, context->bridge->addresses[0].port, &bridge_sock, NULL, false) <= 0){
							COMPAT_CLOSE(bridge_sock);
							net__socket_close(db, context);
							context->bridge->cur_address = context->bridge->address_count-1;
						}
					}
				}
#endif

				/* Local bridges never time out in this fashion. */
				if(!(context->keepalive)
						|| context->bridge
						|| now - context->last_msg_in < (time_t)(context->keepalive)*3/2){

					if(db__message_write(db, context) == MOSQ_ERR_SUCCESS){
						pollfds[pollfd_index].fd = context->sock;
						pollfds[pollfd_index].events = POLLIN;
						pollfds[pollfd_index].revents = 0;
						if(context->current_out_packet || context->state == mosq_cs_connect_pending){
							pollfds[pollfd_index].events |= POLLOUT;
						}
						context->pollfd_index = pollfd_index;
						pollfd_index++;
					}else{
						do_disconnect(db, context);
					}
				}else{
					if(db->config->connection_messages == true){
						if(context->id){
							id = context->id;
						}else{
							id = "<unknown>";
						}
						log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s has exceeded timeout, disconnecting.", id);
					}
					/* Client has exceeded keepalive*1.5 */
					do_disconnect(db, context);
				}
			}
		}

#ifdef WITH_BRIDGE
		time_count = 0;
		for(i=0; i<db->bridge_count; i++){
			if(!db->bridges[i]) continue;

			context = db->bridges[i];

			if(context->sock == INVALID_SOCKET){
				if(time_count > 0){
					time_count--;
				}else{
					time_count = 1000;
					now = mosquitto_time();
				}
				/* Want to try to restart the bridge connection */
				if(!context->bridge->restart_t){
					context->bridge->restart_t = now+context->bridge->restart_timeout;
					context->bridge->cur_address++;
					if(context->bridge->cur_address == context->bridge->address_count){
						context->bridge->cur_address = 0;
					}
					if(context->bridge->round_robin == false && context->bridge->cur_address != 0){
						context->bridge->primary_retry = now + 5;
					}
				}else{
					if((context->bridge->start_type == bst_lazy && context->bridge->lazy_reconnect)
							|| (context->bridge->start_type == bst_automatic && now > context->bridge->restart_t)){
						context->bridge->restart_t = 0;
#if defined(__GLIBC__) && defined(WITH_ADNS)
						if(context->adns){
							/* Waiting on DNS lookup */
							rc = gai_error(context->adns);
							if(rc == EAI_INPROGRESS){
								/* Just keep on waiting */
							}else if(rc == 0){
								rc = bridge__connect_step2(db, context);
								if(rc == MOSQ_ERR_SUCCESS){
									pollfds[pollfd_index].fd = context->sock;
									pollfds[pollfd_index].events = POLLIN;
									pollfds[pollfd_index].revents = 0;
									if(context->current_out_packet){
										pollfds[pollfd_index].events |= POLLOUT;
									}
									context->pollfd_index = pollfd_index;
									pollfd_index++;
								}else{
									context->bridge->cur_address++;
									if(context->bridge->cur_address == context->bridge->address_count){
										context->bridge->cur_address = 0;
									}
								}
							}else{
								/* Need to retry */
								if(context->adns->ar_result){
									freeaddrinfo(context->adns->ar_result);
								}
								_mosquitto_free(context->adns);
								context->adns = NULL;
							}
						}else{
							rc = bridge__connect_step1(db, context);
							if(rc){
								context->bridge->cur_address++;
								if(context->bridge->cur_address == context->bridge->address_count){
									context->bridge->cur_address = 0;
								}
							}
						}
#else
						{
							rc = bridge__connect(db, context);
							if(rc == MOSQ_ERR_SUCCESS){
								pollfds[pollfd_index].fd = context->sock;
								pollfds[pollfd_index].events = POLLIN;
								pollfds[pollfd_index].revents = 0;
								if(context->current_out_packet){
									pollfds[pollfd_index].events |= POLLOUT;
								}
								context->pollfd_index = pollfd_index;
								pollfd_index++;
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
#endif
		now_time = time(NULL);
		if(db->config->persistent_client_expiration > 0 && now_time > expiration_check_time){
			HASH_ITER(hh_id, db->contexts_by_id, context, ctxt_tmp){
				if(context->sock == INVALID_SOCKET && context->clean_session == 0){
					/* This is a persistent client, check to see if the
					 * last time it connected was longer than
					 * persistent_client_expiration seconds ago. If so,
					 * expire it and clean up.
					 */
					if(now_time > context->disconnect_t+db->config->persistent_client_expiration){
						if(context->id){
							id = context->id;
						}else{
							id = "<unknown>";
						}
						log__printf(NULL, MOSQ_LOG_NOTICE, "Expiring persistent client %s due to timeout.", id);
						G_CLIENTS_EXPIRED_INC();
						context->clean_session = true;
						context->state = mosq_cs_expiring;
						do_disconnect(db, context);
					}
				}
			}
			expiration_check_time = time(NULL) + 3600;
		}

#ifndef WIN32
		sigprocmask(SIG_SETMASK, &sigblock, &origsig);
		fdcount = poll(pollfds, pollfd_index, 100);
		sigprocmask(SIG_SETMASK, &origsig, NULL);
#else
		fdcount = WSAPoll(pollfds, pollfd_index, 100);
#endif
		if(fdcount == -1){
			log__printf(NULL, MOSQ_LOG_ERR, "Error in poll: %s.", strerror(errno));
		}else{
			loop_handle_reads_writes(db, pollfds);

			for(i=0; i<listensock_count; i++){
				if(pollfds[i].revents & (POLLIN | POLLPRI)){
					while(net__socket_accept(db, listensock[i]) != -1){
					}
				}
			}
		}
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
			config__read(db->config, true);
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
				libwebsocket_service(db->config->listeners[i].ws_context, 0);
			}
		}
		if(db->config->have_websockets_listener){
			temp__expire_websockets_clients(db);
		}
#endif
	}

	mosquitto__free(pollfds);
	return MOSQ_ERR_SUCCESS;
}

void do_disconnect(struct mosquitto_db *db, struct mosquitto *context)
{
	char *id;

	if(context->state == mosq_cs_disconnected){
		return;
	}
#ifdef WITH_WEBSOCKETS
	if(context->wsi){
		if(context->state != mosq_cs_disconnecting){
			context->state = mosq_cs_disconnect_ws;
		}
		if(context->wsi){
			libwebsocket_callback_on_writable(context->ws_context, context->wsi);
		}
		context->sock = INVALID_SOCKET;
	}else
#endif
	{
		if(db->config->connection_messages == true){
			if(context->id){
				id = context->id;
			}else{
				id = "<unknown>";
			}
			if(context->state != mosq_cs_disconnecting){
				log__printf(NULL, MOSQ_LOG_NOTICE, "Socket error on client %s, disconnecting.", id);
			}else{
				log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected.", id);
			}
		}
		context__disconnect(db, context);
#ifdef WITH_BRIDGE
		if(context->clean_session && !context->bridge){
#else
		if(context->clean_session){
#endif
			context__add_to_disused(db, context);
			if(context->id){
				HASH_DELETE(hh_id, db->contexts_by_id, context);
				mosquitto__free(context->id);
				context->id = NULL;
			}
		}
		context->state = mosq_cs_disconnected;
	}
}


static void loop_handle_reads_writes(struct mosquitto_db *db, struct pollfd *pollfds)
{
	struct mosquitto *context, *ctxt_tmp;
	int err;
	socklen_t len;

	HASH_ITER(hh_sock, db->contexts_by_sock, context, ctxt_tmp){
		if(context->pollfd_index < 0){
			continue;
		}

		assert(pollfds[context->pollfd_index].fd == context->sock);
#ifdef WITH_TLS
		if(pollfds[context->pollfd_index].revents & POLLOUT ||
				context->want_write ||
				(context->ssl && context->state == mosq_cs_new)){
#else
		if(pollfds[context->pollfd_index].revents & POLLOUT){
#endif
			if(context->state == mosq_cs_connect_pending){
				len = sizeof(int);
				if(!getsockopt(context->sock, SOL_SOCKET, SO_ERROR, (char *)&err, &len)){
					if(err == 0){
						context->state = mosq_cs_new;
					}
				}else{
					do_disconnect(db, context);
					continue;
				}
			}
			if(packet__write(context)){
				do_disconnect(db, context);
				continue;
			}
		}
	}

	HASH_ITER(hh_sock, db->contexts_by_sock, context, ctxt_tmp){
		if(context->pollfd_index < 0){
			continue;
		}

#ifdef WITH_TLS
		if(pollfds[context->pollfd_index].revents & POLLIN ||
				(context->ssl && context->state == mosq_cs_new)){
#else
		if(pollfds[context->pollfd_index].revents & POLLIN){
#endif
			do{
				if(packet__read(db, context)){
					do_disconnect(db, context);
					continue;
				}
			}while(SSL_DATA_PENDING(context));
		}
		if(pollfds[context->pollfd_index].revents & (POLLERR | POLLNVAL | POLLHUP)){
			do_disconnect(db, context);
			continue;
		}
	}
}

