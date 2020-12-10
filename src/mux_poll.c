/*
Copyright (c) 2009-2019 Roger Light <roger@atchoo.org>

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

#ifndef WITH_EPOLL

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
#include "mux.h"

static void loop_handle_reads_writes(struct pollfd *pollfds);

static struct pollfd *pollfds = NULL;
static size_t pollfd_max;
#ifndef WIN32
static sigset_t my_sigblock;
#endif

int mux_poll__init(struct mosquitto__listener_sock *listensock, int listensock_count)
{
	int i;
	int pollfd_index = 0;

#ifndef WIN32
	sigemptyset(&my_sigblock);
	sigaddset(&my_sigblock, SIGINT);
	sigaddset(&my_sigblock, SIGTERM);
	sigaddset(&my_sigblock, SIGUSR1);
	sigaddset(&my_sigblock, SIGUSR2);
	sigaddset(&my_sigblock, SIGHUP);
#endif

#ifdef WIN32
	pollfd_max = (size_t)_getmaxstdio();
#else
	pollfd_max = (size_t)sysconf(_SC_OPEN_MAX);
#endif

	pollfds = mosquitto__malloc(sizeof(struct pollfd)*pollfd_max);
	if(!pollfds){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}
	memset(pollfds, 0, sizeof(struct pollfd)*pollfd_max);
	for(i=0; i<pollfd_max; i++) {
		pollfds[i].fd = INVALID_SOCKET;
	}

	for(i=0; i<listensock_count; i++){
		pollfds[pollfd_index].fd = listensock[i].sock;
		pollfds[pollfd_index].events = POLLIN;
		pollfds[pollfd_index].revents = 0;
		pollfd_index++;
	}

	return MOSQ_ERR_SUCCESS;
}


int mux_poll__add_out(struct mosquitto *context)
{
	int i;

	if(context->pollfd_index != -1){
		pollfds[context->pollfd_index].fd = context->sock;
		pollfds[context->pollfd_index].events = POLLIN | POLLOUT;
		pollfds[context->pollfd_index].revents = 0;
	}else{
		for(i=0; i<pollfd_max; i++){
			if(pollfds[i].fd == INVALID_SOCKET){
				pollfds[i].fd = context->sock;
				pollfds[i].events = POLLIN | POLLOUT;
				pollfds[i].revents = 0;
				context->pollfd_index = i;
				break;
			}
		}
	}

	return MOSQ_ERR_SUCCESS;
}


int mux_poll__remove_out(struct mosquitto *context)
{
	return mux_poll__add_in(context);
}


int mux_poll__add_in(struct mosquitto *context)
{
	int i;

	if(context->pollfd_index != -1){
		pollfds[context->pollfd_index].fd = context->sock;
		pollfds[context->pollfd_index].events = POLLIN | POLLPRI;
		pollfds[context->pollfd_index].revents = 0;
	}else{
		for(i=0; i<pollfd_max; i++){
			if(pollfds[i].fd == INVALID_SOCKET){
				pollfds[i].fd = context->sock;
				pollfds[i].events = POLLIN;
				pollfds[i].revents = 0;
				context->pollfd_index = i;
				break;
			}
		}
	}

	return MOSQ_ERR_SUCCESS;
}

int mux_poll__delete(struct mosquitto *context)
{
	if(context->pollfd_index != -1){
		pollfds[context->pollfd_index].fd = INVALID_SOCKET;
		pollfds[context->pollfd_index].events = 0;
		pollfds[context->pollfd_index].revents = 0;
		context->pollfd_index = -1;
	}

	return MOSQ_ERR_SUCCESS;
}




int mux_poll__handle(struct mosquitto__listener_sock *listensock, int listensock_count)
{
	struct mosquitto *context;
	int i;
	int fdcount;
#ifndef WIN32
	sigset_t origsig;
#endif

#ifndef WIN32
	sigprocmask(SIG_SETMASK, &my_sigblock, &origsig);
	fdcount = poll(pollfds, pollfd_max, 100);
	sigprocmask(SIG_SETMASK, &origsig, NULL);
#else
	fdcount = WSAPoll(pollfds, pollfd_max, 100);
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
		loop_handle_reads_writes(pollfds);

		for(i=0; i<listensock_count; i++){
			if(pollfds[i].revents & (POLLIN | POLLPRI)){
#ifdef WITH_WEBSOCKETS
				if(listensock[i]->listener.ws_context){
					/* Nothing needs to happen here, because we always call lws_service in the loop.
					 * The important point is we've been woken up for this listener. */
				}else
#endif
				{
					while((context = net__socket_accept(&listensock[i])) != NULL){
						context->pollfd_index = -1;
						mux__add_in(context);
					}
				}
			}
		}
	}
	return MOSQ_ERR_SUCCESS;
}


int mux_poll__cleanup(void)
{
	mosquitto__free(pollfds);
	pollfds = NULL;

	return MOSQ_ERR_SUCCESS;
}


static void loop_handle_reads_writes(struct pollfd *pollfds)
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

#ifdef WITH_WEBSOCKETS
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
			rc = packet__write(context);
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
#ifdef WITH_WEBSOCKETS
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
				rc = packet__read(context);
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
