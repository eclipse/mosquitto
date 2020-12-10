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
   Tatsuzo Osawa - Add epoll.
*/

#include "config.h"

#ifdef WITH_EPOLL

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

#ifdef WIN32
#  error "epoll not supported on WIN32"
#endif

static void loop_handle_reads_writes(struct mosquitto *context, uint32_t events);

static sigset_t my_sigblock;
static struct epoll_event ep_events[MAX_EVENTS];

int mux_epoll__init(struct mosquitto__listener_sock *listensock, int listensock_count)
{
	struct epoll_event ev;
	int i;

#ifndef WIN32
	sigemptyset(&my_sigblock);
	sigaddset(&my_sigblock, SIGINT);
	sigaddset(&my_sigblock, SIGTERM);
	sigaddset(&my_sigblock, SIGUSR1);
	sigaddset(&my_sigblock, SIGUSR2);
	sigaddset(&my_sigblock, SIGHUP);
#endif

	memset(&ep_events, 0, sizeof(struct epoll_event)*MAX_EVENTS);

	db.epollfd = 0;
	if ((db.epollfd = epoll_create(MAX_EVENTS)) == -1) {
		log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll creating: %s", strerror(errno));
		return MOSQ_ERR_UNKNOWN;
	}
	memset(&ev, 0, sizeof(struct epoll_event));
	for(i=0; i<listensock_count; i++){
		ev.data.ptr = &listensock[i];
		ev.events = EPOLLIN;
		if (epoll_ctl(db.epollfd, EPOLL_CTL_ADD, listensock[i].sock, &ev) == -1) {
			log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll initial registering: %s", strerror(errno));
			(void)close(db.epollfd);
			db.epollfd = 0;
			return MOSQ_ERR_UNKNOWN;
		}
	}

	return MOSQ_ERR_SUCCESS;
}

int mux_epoll__loop_setup(void)
{
	return MOSQ_ERR_SUCCESS;
}


int mux_epoll__add_out(struct mosquitto *context)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(struct epoll_event));
	if(!(context->events & EPOLLOUT)) {
		ev.data.ptr = context;
		ev.events = EPOLLIN | EPOLLOUT;
		if(epoll_ctl(db.epollfd, EPOLL_CTL_ADD, context->sock, &ev) == -1) {
			if((errno != EEXIST)||(epoll_ctl(db.epollfd, EPOLL_CTL_MOD, context->sock, &ev) == -1)) {
				log__printf(NULL, MOSQ_LOG_DEBUG, "Error in epoll re-registering to EPOLLOUT: %s", strerror(errno));
			}
		}
		context->events = EPOLLIN | EPOLLOUT;
	}
	return MOSQ_ERR_SUCCESS;
}


int mux_epoll__remove_out(struct mosquitto *context)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(struct epoll_event));
	if(context->events & EPOLLOUT) {
		ev.data.ptr = context;
		ev.events = EPOLLIN;
		if(epoll_ctl(db.epollfd, EPOLL_CTL_ADD, context->sock, &ev) == -1) {
			if((errno != EEXIST)||(epoll_ctl(db.epollfd, EPOLL_CTL_MOD, context->sock, &ev) == -1)) {
					log__printf(NULL, MOSQ_LOG_DEBUG, "Error in epoll re-registering to EPOLLIN: %s", strerror(errno));
			}
		}
		context->events = EPOLLIN;
	}
	return MOSQ_ERR_SUCCESS;
}


int mux_epoll__add_in(struct mosquitto *context)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.ptr = context;
	if (epoll_ctl(db.epollfd, EPOLL_CTL_ADD, context->sock, &ev) == -1) {
		log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll accepting: %s", strerror(errno));
	}
	context->events = EPOLLIN;
	return MOSQ_ERR_SUCCESS;
}


int mux_epoll__delete(struct mosquitto *context)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(struct epoll_event));
	if(context->sock != INVALID_SOCKET){
		if(epoll_ctl(db.epollfd, EPOLL_CTL_DEL, context->sock, &ev) == -1){
			return 1;
		}
	}
	return 0;
}


int mux_epoll__handle(void)
{
	int i;
	struct epoll_event ev;
	sigset_t origsig;
	struct mosquitto *context;
	struct mosquitto__listener_sock *listensock;
	int event_count;

	memset(&ev, 0, sizeof(struct epoll_event));
	sigprocmask(SIG_SETMASK, &my_sigblock, &origsig);
	event_count = epoll_wait(db.epollfd, ep_events, MAX_EVENTS, 100);
	sigprocmask(SIG_SETMASK, &origsig, NULL);

	db.now_s = mosquitto_time();
	db.now_real_s = time(NULL);

	switch(event_count){
	case -1:
		if(errno != EINTR){
			log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll waiting: %s.", strerror(errno));
		}
		break;
	case 0:
		break;
	default:
		for(i=0; i<event_count; i++){
			context = ep_events[i].data.ptr;
			if(context->ident == id_client){
				loop_handle_reads_writes(context, ep_events[i].events);
			}else if(context->ident == id_listener){
				listensock = ep_events[i].data.ptr;

				if (ep_events[i].events & (EPOLLIN | EPOLLPRI)){
					while((context = net__socket_accept(listensock)) != NULL){
						context->events = EPOLLIN;
						mux__add_in(context);
					}
				}
#ifdef WITH_WEBSOCKETS
			}else if(context->ident == id_listener_ws){
				/* Nothing needs to happen here, because we always call lws_service in the loop.
				 * The important point is we've been woken up for this listener. */
#endif
			}
		}
	}
	return MOSQ_ERR_SUCCESS;
}


int mux_epoll__cleanup(void)
{
	(void)close(db.epollfd);
	db.epollfd = 0;
	return MOSQ_ERR_SUCCESS;
}


static void loop_handle_reads_writes(struct mosquitto *context, uint32_t events)
{
	int err;
	socklen_t len;
	int rc;

	if(context->sock == INVALID_SOCKET){
		return;
	}

#ifdef WITH_WEBSOCKETS
	if(context->wsi){
		struct lws_pollfd wspoll;
		wspoll.fd = context->sock;
		wspoll.events = (int16_t)context->events;
		wspoll.revents = (int16_t)events;
		lws_service_fd(lws_get_context(context->wsi), &wspoll);
		return;
	}
#endif

	if(events & EPOLLOUT
#ifdef WITH_TLS
			|| context->want_write
			|| (context->ssl && context->state == mosq_cs_new)
#endif
			){

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
				}
			}else{
				do_disconnect(context, MOSQ_ERR_CONN_LOST);
				return;
			}
		}
		rc = packet__write(context);
		if(rc){
			do_disconnect(context, rc);
			return;
		}
	}

	if(events & EPOLLIN
#ifdef WITH_TLS
			|| (context->ssl && context->state == mosq_cs_new)
#endif
			){

		do{
			rc = packet__read(context);
			if(rc){
				do_disconnect(context, rc);
				return;
			}
		}while(SSL_DATA_PENDING(context));
	}else{
		if(events & (EPOLLERR | EPOLLHUP)){
			do_disconnect(context, MOSQ_ERR_CONN_LOST);
			return;
		}
	}
}
#endif
