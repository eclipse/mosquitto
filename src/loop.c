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
#ifdef WITH_EPOLL
#include <sys/epoll.h>
#define MAX_EVENTS 1000
#endif
#include <poll.h>
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

#ifdef WITH_EPOLL
static void loop_handle_reads_writes(struct mosquitto_db *db, mosq_sock_t sock, uint32_t events);
#else
static void loop_handle_reads_writes(struct mosquitto_db *db, struct pollfd *pollfds);
#endif

bool context_want_write(struct mosquitto *context)
{
	bool result = false;
	if(context->current_out_packet || context->want_write || context->ws_want_write){
		result = true;
	}
	
#ifdef WITH_TLS
	if (context->want_read) {
		/* 
		 * SSL want read, disable want write until read completed.
		 * To avoid ssl handshake cannot completed since alway call SSL_write when need read.
		 */
		result = false;
	}
#endif
	/*
	** log__printf(NULL, MOSQ_LOG_DEBUG, "Context[%s] result:%d, r:%d, w:%d, ws:%d, c:%p",
	** 			context->id ? context->id : "Unknown", result, context->want_read,
	** 			context->want_write, context->ws_want_write, context->current_out_packet);
	*/
	return result;
}


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
						if(db->config->connection_messages == true){
							log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s has exceeded timeout, disconnecting.", id);
						}
					}
					/* Client has exceeded keepalive*1.5 */
					do_disconnect(db, context, MOSQ_ERR_KEEPALIVE);
				}
			}
		}
		last_check = mosquitto_time();
	}
}
#endif

#if defined(WITH_WEBSOCKETS) && LWS_LIBRARY_VERSION_NUMBER == 3002000
void lws__sul_callback(struct lws_sorted_usec_list *l)
{
}

static struct lws_sorted_usec_list sul;
#endif

int mosquitto_main_loop(struct mosquitto_db *db, mosq_sock_t *listensock, int listensock_count)
{
#ifdef WITH_SYS_TREE
	time_t start_time = mosquitto_time();
#endif
#ifdef WITH_PERSISTENCE
	time_t last_backup = mosquitto_time();
#endif
	time_t now = 0;
	int time_count;
	int fdcount;
	struct mosquitto *context, *ctxt_tmp;
#ifndef WIN32
	sigset_t sigblock, origsig;
#endif
	int i;
#ifdef WITH_EPOLL
	int j;
	struct epoll_event ev, events[MAX_EVENTS];
#else
	struct pollfd *pollfds = NULL;
	int pollfd_index;
	int pollfd_max;
#endif
#ifdef WITH_BRIDGE
	int rc;
#endif


#if defined(WITH_WEBSOCKETS) && LWS_LIBRARY_VERSION_NUMBER == 3002000
	memset(&sul, 0, sizeof(struct lws_sorted_usec_list));
#endif

#ifndef WIN32
	sigemptyset(&sigblock);
	sigaddset(&sigblock, SIGINT);
	sigaddset(&sigblock, SIGTERM);
	sigaddset(&sigblock, SIGUSR1);
	sigaddset(&sigblock, SIGUSR2);
	sigaddset(&sigblock, SIGHUP);
#endif

#ifndef WITH_EPOLL
#ifdef WIN32
	pollfd_max = _getmaxstdio();
#else
	pollfd_max = sysconf(_SC_OPEN_MAX);
#endif

	pollfds = mosquitto__malloc(sizeof(struct pollfd)*pollfd_max);
	if(!pollfds){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}
#endif

#ifdef WITH_EPOLL
	db->epollfd = 0;
	if ((db->epollfd = epoll_create(MAX_EVENTS)) == -1) {
		log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll creating: %s", strerror(errno));
		return MOSQ_ERR_UNKNOWN;
	}
	memset(&ev, 0, sizeof(struct epoll_event));
	memset(&events, 0, sizeof(struct epoll_event)*MAX_EVENTS);
	for(i=0; i<listensock_count; i++){
		ev.data.fd = listensock[i];
		ev.events = EPOLLIN;
		if (epoll_ctl(db->epollfd, EPOLL_CTL_ADD, listensock[i], &ev) == -1) {
			log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll initial registering: %s", strerror(errno));
			(void)close(db->epollfd);
			db->epollfd = 0;
			return MOSQ_ERR_UNKNOWN;
		}
	}
#  ifdef WITH_BRIDGE
	rc = bridge__register_local_connections(db);
	if(rc) return rc;
#  endif
#endif

	while(run){
		context__free_disused(db);
#ifdef WITH_SYS_TREE
		if(db->config->sys_interval > 0){
			sys_tree__update(db, db->config->sys_interval, start_time);
		}
#endif

#ifndef WITH_EPOLL
		memset(pollfds, -1, sizeof(struct pollfd)*pollfd_max);

		pollfd_index = 0;
		for(i=0; i<listensock_count; i++){
			pollfds[pollfd_index].fd = listensock[i];
			pollfds[pollfd_index].events = POLLIN;
			pollfds[pollfd_index].revents = 0;
			pollfd_index++;
		}
#endif

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
				/* Local bridges never time out in this fashion. */
				if(!(context->keepalive)
						|| context->bridge
						|| now - context->last_msg_in <= (time_t)(context->keepalive)*3/2){

					if(db__message_write(db, context) == MOSQ_ERR_SUCCESS){
#ifdef WITH_EPOLL
						if(context_want_write(context)){
							if(!(context->events & EPOLLOUT)) {
								ev.data.fd = context->sock;
								ev.events = EPOLLIN | EPOLLOUT;
								if(epoll_ctl(db->epollfd, EPOLL_CTL_ADD, context->sock, &ev) == -1) {
									if((errno != EEXIST)||(epoll_ctl(db->epollfd, EPOLL_CTL_MOD, context->sock, &ev) == -1)) {
											log__printf(NULL, MOSQ_LOG_DEBUG, "Error in epoll re-registering to EPOLLOUT: %s", strerror(errno));
									}
								}
								context->events = EPOLLIN | EPOLLOUT;
							}
							context->ws_want_write = false;
						}else{
							if(context->events & EPOLLOUT) {
								ev.data.fd = context->sock;
								ev.events = EPOLLIN;
								if(epoll_ctl(db->epollfd, EPOLL_CTL_ADD, context->sock, &ev) == -1) {
									if((errno != EEXIST)||(epoll_ctl(db->epollfd, EPOLL_CTL_MOD, context->sock, &ev) == -1)) {
											log__printf(NULL, MOSQ_LOG_DEBUG, "Error in epoll re-registering to EPOLLIN: %s", strerror(errno));
									}
								}
								context->events = EPOLLIN;
							}
						}
#else
						pollfds[pollfd_index].fd = context->sock;
						pollfds[pollfd_index].events = POLLIN;
						pollfds[pollfd_index].revents = 0;
						if(context_want_write(context)){
							pollfds[pollfd_index].events |= POLLOUT;
							context->ws_want_write = false;
						}
						context->pollfd_index = pollfd_index;
						pollfd_index++;
#endif
					}else{
						do_disconnect(db, context, MOSQ_ERR_CONN_LOST);
					}
				}else{
					/* Client has exceeded keepalive*1.5 */
					do_disconnect(db, context, MOSQ_ERR_KEEPALIVE);
				}
			}
		}


#ifdef WITH_BRIDGE
#  ifdef WITH_EPOLL
		bridge_check(db);
#  else
		bridge_check(db, pollfds, &pollfd_index);
#  endif
#endif

#ifndef WIN32
		sigprocmask(SIG_SETMASK, &sigblock, &origsig);
#ifdef WITH_EPOLL
		fdcount = epoll_wait(db->epollfd, events, MAX_EVENTS, 100);
#else
		fdcount = poll(pollfds, pollfd_index, 100);
#endif
		sigprocmask(SIG_SETMASK, &origsig, NULL);
#else
		fdcount = WSAPoll(pollfds, pollfd_index, 100);
#endif
#ifdef WITH_EPOLL
		switch(fdcount){
		case -1:
			if(errno != EINTR){
				log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll waiting: %s.", strerror(errno));
			}
			break;
		case 0:
			break;
		default:
			for(i=0; i<fdcount; i++){
				for(j=0; j<listensock_count; j++){
					if (events[i].data.fd == listensock[j]) {
						if (events[i].events & (EPOLLIN | EPOLLPRI)){
							while((ev.data.fd = net__socket_accept(db, listensock[j])) != -1){
								ev.events = EPOLLIN;
								if (epoll_ctl(db->epollfd, EPOLL_CTL_ADD, ev.data.fd, &ev) == -1) {
									log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll accepting: %s", strerror(errno));
								}
								context = NULL;
								HASH_FIND(hh_sock, db->contexts_by_sock, &(ev.data.fd), sizeof(mosq_sock_t), context);
								if(context){
									context->events = EPOLLIN;
								}else{
									log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll accepting: no context");
								}
							}
						}
						break;
					}
				}
				if (j == listensock_count) {
					loop_handle_reads_writes(db, events[i].data.fd, events[i].events);
				}
			}
		}
#else
		if(fdcount == -1){
#  ifdef WIN32
			if(pollfd_index == 0 && WSAGetLastError() == WSAEINVAL){
				/* WSAPoll() immediately returns an error if it is not given
				 * any sockets to wait on. This can happen if we only have
				 * websockets listeners. Sleep a little to prevent a busy loop.
				 */
				Sleep(10);
			}else
#  endif
			{
				log__printf(NULL, MOSQ_LOG_ERR, "Error in poll: %s.", strerror(errno));
			}
		}else{
			loop_handle_reads_writes(db, pollfds);

			for(i=0; i<listensock_count; i++){
				if(pollfds[i].revents & (POLLIN | POLLPRI)){
					while(net__socket_accept(db, listensock[i]) != -1){
					}
				}
			}
		}
#endif
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
		if(db->config->have_websockets_listener){
			temp__expire_websockets_clients(db);
		}
#endif
	}

#ifdef WITH_EPOLL
	(void) close(db->epollfd);
	db->epollfd = 0;
#else
	mosquitto__free(pollfds);
#endif
	return MOSQ_ERR_SUCCESS;
}

void do_disconnect(struct mosquitto_db *db, struct mosquitto *context, int reason)
{
	char *id;
#ifdef WITH_EPOLL
	struct epoll_event ev;
#endif
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
#ifdef WITH_EPOLL
			if (epoll_ctl(db->epollfd, EPOLL_CTL_DEL, context->sock, &ev) == -1) {
				log__printf(NULL, MOSQ_LOG_DEBUG, "Error in epoll disconnecting websockets: %s", strerror(errno));
			}
#endif		
			context->sock = INVALID_SOCKET;
			context->pollfd_index = -1;
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
					case MOSQ_ERR_PROTOCOL:
						log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected due to protocol error.", id);
						break;
					case MOSQ_ERR_CONN_LOST:
						log__printf(NULL, MOSQ_LOG_NOTICE, "Socket error on client %s, disconnecting.", id);
						break;
					case MOSQ_ERR_AUTH:
						log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected, no longer authorised.", id);
						break;
					case MOSQ_ERR_KEEPALIVE:
						log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s has exceeded timeout, disconnecting.", id);
						break;
					default:
						log__printf(NULL, MOSQ_LOG_NOTICE, "Socket error on client %s, disconnecting.", id);
						break;
				}
			}else{
				log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected.", id);
			}
		}
#ifdef WITH_EPOLL
		if (context->sock != INVALID_SOCKET && epoll_ctl(db->epollfd, EPOLL_CTL_DEL, context->sock, &ev) == -1) {
			if(db->config->connection_messages == true){
				log__printf(NULL, MOSQ_LOG_DEBUG, "Error in epoll disconnecting: %s", strerror(errno));
			}
		}
#endif
		context__disconnect(db, context);
	}
}


#ifdef WITH_EPOLL
static void loop_handle_reads_writes(struct mosquitto_db *db, mosq_sock_t sock, uint32_t events)
#else
static void loop_handle_reads_writes(struct mosquitto_db *db, struct pollfd *pollfds)
#endif
{
	struct mosquitto *context;
#ifndef WITH_EPOLL
	struct mosquitto *ctxt_tmp;
#endif
	int rc;

#ifdef WITH_EPOLL
	int i;
	context = NULL;
	HASH_FIND(hh_sock, db->contexts_by_sock, &sock, sizeof(mosq_sock_t), context);
	if(!context) {
		return;
	}
	for (i=0;i<1;i++) {
#else
	HASH_ITER(hh_sock, db->contexts_by_sock, context, ctxt_tmp){
		if(context->pollfd_index < 0){
			continue;
		}

		assert(pollfds[context->pollfd_index].fd == context->sock);
#endif

#ifdef WITH_WEBSOCKETS
		if(context->wsi){
			struct lws_pollfd wspoll;
#ifdef WITH_EPOLL
			wspoll.fd = context->sock;
			wspoll.events = context->events;
			wspoll.revents = events;
#else
			wspoll.fd = pollfds[context->pollfd_index].fd;
			wspoll.events = pollfds[context->pollfd_index].events;
			wspoll.revents = pollfds[context->pollfd_index].revents;
#endif
#ifdef LWS_LIBRARY_VERSION_NUMBER
			lws_service_fd(lws_get_context(context->wsi), &wspoll);
#else
			lws_service_fd(context->ws_context, &wspoll);
#endif
			continue;
		}
#endif


#ifdef WITH_EPOLL
		if(events & EPOLLOUT){
#else			
		if(pollfds[context->pollfd_index].revents & POLLOUT){
#endif
#if defined(WITH_BRIDGE)
			if((context->state == mosq_cs_connect_pending) && (context->bridge)){
				rc = net__socket_nonblock_connected(context, context->sock);
				if (rc == MOSQ_ERR_CONN_PENDING) {
					/* Check next time */
					continue;
				} else if(rc == MOSQ_ERR_SUCCESS){
					mosquitto__set_state(context, mosq_cs_ssl_connect_pending);
				} else {
					context->bridge->restart_t = 0;
					mosquitto__set_state(context, mosq_cs_new);
					do_disconnect(db, context, MOSQ_ERR_CONN_LOST);
					continue;
				}
			}
			if((context->state == mosq_cs_ssl_connect_pending) && (context->bridge)){
				rc = bridge__connect_step3(db, context);
				if (rc == MOSQ_ERR_SSL_CONN_PENDING) {
					/* try again later. */
				} else if (rc != MOSQ_ERR_SUCCESS) {
					context->bridge->restart_t = 0;
					mosquitto__set_state(context, mosq_cs_new);
					do_disconnect(db, context, rc);
				}
				continue;
			}
#endif

			rc = packet__write(context);
			if(rc){
				do_disconnect(db, context, rc);
				continue;
			}
		}
	}

#ifdef WITH_EPOLL
	context = NULL;
	HASH_FIND(hh_sock, db->contexts_by_sock, &sock, sizeof(mosq_sock_t), context);
	if(!context) {
		return;
	}
	for (i=0;i<1;i++) {
#else
	HASH_ITER(hh_sock, db->contexts_by_sock, context, ctxt_tmp){
		if(context->pollfd_index < 0){
			continue;
		}
#endif
#ifdef WITH_WEBSOCKETS
		if(context->wsi){
			// Websocket are already handled above
			continue;
		}
#endif

#ifdef WITH_EPOLL
		if(events & EPOLLIN){
#else
		if(pollfds[context->pollfd_index].revents & POLLIN){
#endif

#if defined(WITH_BRIDGE)
			if((context->state == mosq_cs_ssl_connect_pending) && (context->bridge)){
				rc = bridge__connect_step3(db, context);
				if (rc == MOSQ_ERR_SSL_CONN_PENDING) {
					/* try again later. */
				} else if (rc != MOSQ_ERR_SUCCESS) {
					context->bridge->restart_t = 0;
					mosquitto__set_state(context, mosq_cs_new);
					do_disconnect(db, context, rc);
				}
				continue;
			}
#endif

			do{
				rc = packet__read(db, context);
				if(rc){
					do_disconnect(db, context, rc);
					continue;
				}
			}while(SSL_DATA_PENDING(context));
		}else{
#ifdef WITH_EPOLL
			if(events & (EPOLLERR | EPOLLHUP)){
#else
			if(context->pollfd_index >= 0 && pollfds[context->pollfd_index].revents & (POLLERR | POLLNVAL | POLLHUP)){
#endif
				do_disconnect(db, context, MOSQ_ERR_CONN_LOST);
				continue;
			}
		}
	}
}



