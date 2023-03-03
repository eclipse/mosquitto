/*
Copyright (c) 2009-2021 Roger Light <roger@atchoo.org>

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

#if !defined(WITH_EPOLL) && !defined(WITH_KQUEUE)

#ifndef WIN32
#  define _GNU_SOURCE
#endif

#include <assert.h>
#ifndef WIN32
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

#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_LWS
#  include <libwebsockets.h>
#endif

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "send_mosq.h"
#include "sys_tree.h"
#include "time_mosq.h"
#include "util_mosq.h"
#include "mux.h"

static void loop_handle_reads_writes(void);

static struct pollfd *pollfds = NULL;
static size_t pollfd_max, pollfd_current_max = 0;

int mux_poll__init(void)
{
	size_t i;

#ifdef WIN32
	pollfd_max = (size_t)_getmaxstdio();
#else
	pollfd_max = (size_t)sysconf(_SC_OPEN_MAX);
#endif

	pollfds = mosquitto__calloc(pollfd_max, sizeof(struct pollfd));
	if(!pollfds){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}
	memset(pollfds, 0, sizeof(struct pollfd)*pollfd_max);
	for(i=0; i<pollfd_max; i++) {
		pollfds[i].fd = INVALID_SOCKET;
	}

	return MOSQ_ERR_SUCCESS;
}


int mux_poll__add_listeners(struct mosquitto__listener_sock *listensock, int listensock_count)
{
	size_t i;
	size_t pollfd_index = 0;

	for(i=0; i<(size_t )listensock_count; i++){
		pollfds[pollfd_index].fd = listensock[i].sock;
		pollfds[pollfd_index].events = POLLIN;
		pollfds[pollfd_index].revents = 0;
		pollfd_index++;
	}

	if(pollfd_current_max == 0){
		pollfd_current_max = pollfd_index-1;
	}
	return MOSQ_ERR_SUCCESS;
}


int mux_poll__delete_listeners(struct mosquitto__listener_sock *listensock, int listensock_count)
{
	size_t i;
	size_t pollfd_index = 0;

	UNUSED(listensock);

	for(i=0; i<(size_t )listensock_count; i++){
		pollfds[pollfd_index].fd = INVALID_SOCKET;
		pollfds[pollfd_index].events = 0;
		pollfds[pollfd_index].revents = 0;
		pollfd_index++;
	}

	return MOSQ_ERR_SUCCESS;
}


static int mux_poll__add(struct mosquitto* context, uint16_t evt)
{
	size_t i;

	if(context->events == evt){
		return MOSQ_ERR_SUCCESS;
	}

	if(context->pollfd_index != -1){
		pollfds[context->pollfd_index].fd = context->sock;
		pollfds[context->pollfd_index].events = (short int)evt;
		pollfds[context->pollfd_index].revents = 0;
	}else{
		for(i=0; i<pollfd_max; i++) {
			if(pollfds[i].fd == INVALID_SOCKET){
				pollfds[i].fd = context->sock;
				pollfds[i].events = POLLIN;
				pollfds[i].revents = 0;
				context->pollfd_index = (int)i;
				if(i > pollfd_current_max){
					pollfd_current_max = i;
				}
				break;
			}
		}
	}
	context->events = evt;

	return MOSQ_ERR_SUCCESS;
}


int mux_poll__add_out(struct mosquitto *context)
{
	return mux_poll__add(context, POLLIN | POLLOUT);
}


int mux_poll__remove_out(struct mosquitto *context)
{
	if(context->events & POLLOUT) {
		return mux_poll__new(context);
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}


int mux_poll__new(struct mosquitto *context)
{
	return mux_poll__add(context, POLLIN);
}

int mux_poll__delete(struct mosquitto *context)
{
	size_t pollfd_index;

	if(context->pollfd_index != -1){
		pollfds[context->pollfd_index].fd = INVALID_SOCKET;
		pollfds[context->pollfd_index].events = 0;
		pollfds[context->pollfd_index].revents = 0;
		pollfd_index = (size_t )context->pollfd_index;
		context->pollfd_index = -1;

		/* If this is the highest index, reduce the current max until we find
		 * the next highest in use index. */
		while(pollfd_index == pollfd_current_max
				&& pollfd_index > 0
				&& pollfds[pollfd_index].fd == INVALID_SOCKET){

			pollfd_index--;
			pollfd_current_max--;
		}
	}

	return MOSQ_ERR_SUCCESS;
}




int mux_poll__handle(struct mosquitto__listener_sock *listensock, int listensock_count)
{
	struct mosquitto *context;
	int i;
	int fdcount;
	int timeout;

#ifdef WITH_WEBSOCKETS
	timeout = 100;
#else
	timeout = db.next_event_ms;
#endif

#ifndef WIN32
	fdcount = poll(pollfds, pollfd_current_max+1, timeout);
#else
	fdcount = WSAPoll(pollfds, pollfd_current_max+1, timeout);
#endif

	db.now_s = mosquitto_time();
	db.now_real_s = time(NULL);

	if(fdcount == -1){
#  ifdef WIN32
		if(WSAGetLastError() == WSAEINVAL){
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
		loop_handle_reads_writes();

		for(i=0; i<listensock_count; i++){
			if(pollfds[i].revents & POLLIN){
#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_LWS
				if(listensock[i].listener->ws_context){
					/* Nothing needs to happen here, because we always call lws_service in the loop.
					 * The important point is we've been woken up for this listener. */
				}else
#endif
				{
					while((context = net__socket_accept(&listensock[i])) != NULL){
					}
				}
			}
		}
	}
	return MOSQ_ERR_SUCCESS;
}


int mux_poll__cleanup(void)
{
	mosquitto__FREE(pollfds);

	return MOSQ_ERR_SUCCESS;
}


static void loop_handle_reads_writes(void)
{
	struct mosquitto *context, *ctxt_tmp;
	int err;
	socklen_t len;
	int rc;

	HASH_ITER(hh_sock, db.contexts_by_sock, context, ctxt_tmp){
		if(context->pollfd_index < 0){
			continue;
		}

		if(pollfds[context->pollfd_index].fd == INVALID_SOCKET){
			continue;
		}

		assert(pollfds[context->pollfd_index].fd == context->sock);

#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_LWS
		if(context->wsi){
			struct lws_pollfd wspoll;
			wspoll.fd = pollfds[context->pollfd_index].fd;
			wspoll.events = pollfds[context->pollfd_index].events;
			wspoll.revents = pollfds[context->pollfd_index].revents;
			lws_service_fd(lws_get_context(context->wsi), &wspoll);
			continue;
		}
#endif

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
						mosquitto__set_state(context, mosq_cs_new);
#if defined(WITH_ADNS) && defined(WITH_BRIDGE)
						if(context->bridge){
							bridge__connect_step3(context);
							continue;
						}
#endif
					}
				}else{
					do_disconnect(context, MOSQ_ERR_CONN_LOST);
					continue;
				}
			}
			switch(context->transport){
				case mosq_t_tcp:
					rc = packet__write(context);
					break;
#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_BUILTIN
				case mosq_t_ws:
					rc = packet__write(context);
					break;
				case mosq_t_http:
					rc = http__write(context);
					break;
#endif
				default:
					rc = MOSQ_ERR_INVAL;
					break;
			}
			if(rc){
				do_disconnect(context, rc);
				continue;
			}
		}
	}

	HASH_ITER(hh_sock, db.contexts_by_sock, context, ctxt_tmp){
		if(context->pollfd_index < 0){
			continue;
		}
#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_LWS
		if(context->wsi){
			// Websocket are already handled above
			continue;
		}
#endif

#ifdef WITH_TLS
		if(pollfds[context->pollfd_index].revents & POLLIN ||
				(context->ssl && context->state == mosq_cs_new)){
#else
		if(pollfds[context->pollfd_index].revents & POLLIN){
#endif
			do{
				switch(context->transport){
					case mosq_t_tcp:
					case mosq_t_ws:
						rc = packet__read(context);
						break;
#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_BUILTIN
					case mosq_t_http:
						rc = http__read(context);
						break;
#endif
					default:
						rc = MOSQ_ERR_INVAL;
						break;
				}
				if(rc){
					do_disconnect(context, rc);
					continue;
				}
			}while(SSL_DATA_PENDING(context));
		}else{
			if(context->pollfd_index >= 0 && pollfds[context->pollfd_index].revents & (POLLERR | POLLNVAL | POLLHUP)){
				do_disconnect(context, MOSQ_ERR_CONN_LOST);
				continue;
			}
		}
	}
}


#endif
