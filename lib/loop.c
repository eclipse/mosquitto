/*
Copyright (c) 2010-2020 Roger Light <roger@atchoo.org>

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

#include <errno.h>
#ifndef WIN32
#include <sys/select.h>
#include <time.h>
#endif

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "socks_mosq.h"
#include "tls_mosq.h"
#include "util_mosq.h"

#if !defined(WIN32) && !defined(__SYMBIAN32__) && !defined(__QNX__)
#define HAVE_PSELECT
#endif

int mosquitto_loop(struct mosquitto *mosq, int timeout, int max_packets)
{
#ifdef HAVE_PSELECT
	struct timespec local_timeout;
#else
	struct timeval local_timeout;
#endif
	fd_set readfds, writefds;
	int fdcount;
	int rc;
	char pairbuf;
	int maxfd = 0;
	time_t now;
	time_t timeout_ms;

	if(!mosq || max_packets < 1) return MOSQ_ERR_INVAL;
#ifndef WIN32
	if(mosq->sock >= FD_SETSIZE || mosq->sockpairR >= FD_SETSIZE){
		return MOSQ_ERR_INVAL;
	}
#endif

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	if(mosq->sock != INVALID_SOCKET){
		maxfd = mosq->sock;
		FD_SET(mosq->sock, &readfds);
		pthread_mutex_lock(&mosq->current_out_packet_mutex);
		pthread_mutex_lock(&mosq->out_packet_mutex);
		if(mosq->out_packet || mosq->current_out_packet){
			FD_SET(mosq->sock, &writefds);
		}
#ifdef WITH_TLS
		if(mosq->ssl){
			if(mosq->want_write){
				FD_SET(mosq->sock, &writefds);
			}else if(mosq->want_connect){
				/* Remove possible FD_SET from above, we don't want to check
				 * for writing if we are still connecting, unless want_write is
				 * definitely set. The presence of outgoing packets does not
				 * matter yet. */
				FD_CLR(mosq->sock, &writefds);
			}
		}
#endif
		pthread_mutex_unlock(&mosq->out_packet_mutex);
		pthread_mutex_unlock(&mosq->current_out_packet_mutex);
	}else{
#ifdef WITH_SRV
		if(mosq->achan){
			if(mosquitto__get_state(mosq) == mosq_cs_connect_srv){
				rc = ares_fds(mosq->achan, &readfds, &writefds);
				if(rc > maxfd){
					maxfd = rc;
				}
			}else{
				return MOSQ_ERR_NO_CONN;
			}
		}
#else
		return MOSQ_ERR_NO_CONN;
#endif
	}
	if(mosq->sockpairR != INVALID_SOCKET){
		/* sockpairR is used to break out of select() before the timeout, on a
		 * call to publish() etc. */
		FD_SET(mosq->sockpairR, &readfds);
		if((int)mosq->sockpairR > maxfd){
			maxfd = mosq->sockpairR;
		}
	}

	timeout_ms = timeout;
	if(timeout_ms < 0){
		timeout_ms = 1000;
	}

	now = mosquitto_time();
	if(mosq->next_msg_out && now + timeout_ms/1000 > mosq->next_msg_out){
		timeout_ms = (mosq->next_msg_out - now)*1000;
	}

	if(timeout_ms < 0){
		/* There has been a delay somewhere which means we should have already
		 * sent a message. */
		timeout_ms = 0;
	}

	local_timeout.tv_sec = timeout_ms/1000;
#ifdef HAVE_PSELECT
	local_timeout.tv_nsec = (timeout_ms-local_timeout.tv_sec*1000)*1000000;
#else
	local_timeout.tv_usec = (timeout_ms-local_timeout.tv_sec*1000)*1000;
#endif

#ifdef HAVE_PSELECT
	fdcount = pselect(maxfd+1, &readfds, &writefds, NULL, &local_timeout, NULL);
#else
	fdcount = select(maxfd+1, &readfds, &writefds, NULL, &local_timeout);
#endif
	if(fdcount == -1){
#ifdef WIN32
		errno = WSAGetLastError();
#endif
		if(errno == EINTR){
			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_ERRNO;
		}
	}else{
		if(mosq->sock != INVALID_SOCKET){
			if(FD_ISSET(mosq->sock, &readfds)){
				rc = mosquitto_loop_read(mosq, max_packets);
				if(rc || mosq->sock == INVALID_SOCKET){
					return rc;
				}
			}
			if(mosq->sockpairR != INVALID_SOCKET && FD_ISSET(mosq->sockpairR, &readfds)){
#ifndef WIN32
				if(read(mosq->sockpairR, &pairbuf, 1) == 0){
				}
#else
				recv(mosq->sockpairR, &pairbuf, 1, 0);
#endif
				/* Fake write possible, to stimulate output write even though
				 * we didn't ask for it, because at that point the publish or
				 * other command wasn't present. */
				if(mosq->sock != INVALID_SOCKET)
					FD_SET(mosq->sock, &writefds);
			}
			if(mosq->sock != INVALID_SOCKET && FD_ISSET(mosq->sock, &writefds)){
#ifdef WITH_TLS
				if(mosq->want_connect){
					rc = net__socket_connect_tls(mosq);
					if(rc) return rc;
				}else
#endif
				{
					rc = mosquitto_loop_write(mosq, max_packets);
					if(rc || mosq->sock == INVALID_SOCKET){
						return rc;
					}
				}
			}
		}
#ifdef WITH_SRV
		if(mosq->achan){
			ares_process(mosq->achan, &readfds, &writefds);
		}
#endif
	}
	return mosquitto_loop_misc(mosq);
}


static int interruptible_sleep(struct mosquitto *mosq, time_t reconnect_delay)
{
#ifdef HAVE_PSELECT
	struct timespec local_timeout;
#else
	struct timeval local_timeout;
#endif
	fd_set readfds;
	int fdcount;
	char pairbuf;
	int maxfd = 0;

	local_timeout.tv_sec = reconnect_delay;
#ifdef HAVE_PSELECT
	local_timeout.tv_nsec = 0;
#else
	local_timeout.tv_usec = 0;
#endif
	FD_ZERO(&readfds);
	maxfd = 0;
	if(mosq->sockpairR != INVALID_SOCKET){
		/* sockpairR is used to break out of select() before the
		 * timeout, when mosquitto_loop_stop() is called */
		FD_SET(mosq->sockpairR, &readfds);
		maxfd = mosq->sockpairR;
	}
#ifdef HAVE_PSELECT
	fdcount = pselect(maxfd+1, &readfds, NULL, NULL, &local_timeout, NULL);
#else
	fdcount = select(maxfd+1, &readfds, NULL, NULL, &local_timeout);
#endif
	if(fdcount == -1){
#ifdef WIN32
		errno = WSAGetLastError();
#endif
		if(errno == EINTR){
			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_ERRNO;
		}
	}else if(mosq->sockpairR != INVALID_SOCKET && FD_ISSET(mosq->sockpairR, &readfds)){
#ifndef WIN32
		if(read(mosq->sockpairR, &pairbuf, 1) == 0){
		}
#else
		recv(mosq->sockpairR, &pairbuf, 1, 0);
#endif
	}
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_loop_forever(struct mosquitto *mosq, int timeout, int max_packets)
{
	int run = 1;
	int rc = MOSQ_ERR_SUCCESS;
	unsigned long reconnect_delay;
	enum mosquitto_client_state state;

	if(!mosq) return MOSQ_ERR_INVAL;

	mosq->reconnects = 0;

	while(run){
		do{
#ifdef HAVE_PTHREAD_CANCEL
			pthread_testcancel();
#endif
			rc = mosquitto_loop(mosq, timeout, max_packets);
		}while(run && rc == MOSQ_ERR_SUCCESS);
		/* Quit after fatal errors. */
		switch(rc){
			case MOSQ_ERR_NOMEM:
			case MOSQ_ERR_PROTOCOL:
			case MOSQ_ERR_INVAL:
			case MOSQ_ERR_NOT_FOUND:
			case MOSQ_ERR_TLS:
			case MOSQ_ERR_PAYLOAD_SIZE:
			case MOSQ_ERR_NOT_SUPPORTED:
			case MOSQ_ERR_AUTH:
			case MOSQ_ERR_ACL_DENIED:
			case MOSQ_ERR_UNKNOWN:
			case MOSQ_ERR_EAI:
			case MOSQ_ERR_PROXY:
				return rc;
			case MOSQ_ERR_ERRNO:
				break;
		}
		if(errno == EPROTO){
			return rc;
		}
		do{
#ifdef HAVE_PTHREAD_CANCEL
			pthread_testcancel();
#endif
			rc = MOSQ_ERR_SUCCESS;
			state = mosquitto__get_state(mosq);
			if(state == mosq_cs_disconnecting || state == mosq_cs_disconnected){
				run = 0;
			}else{
				if(mosq->reconnect_delay_max > mosq->reconnect_delay){
					if(mosq->reconnect_exponential_backoff){
						reconnect_delay = mosq->reconnect_delay*(mosq->reconnects+1)*(mosq->reconnects+1);
					}else{
						reconnect_delay = mosq->reconnect_delay*(mosq->reconnects+1);
					}
				}else{
					reconnect_delay = mosq->reconnect_delay;
				}

				if(reconnect_delay > mosq->reconnect_delay_max){
					reconnect_delay = mosq->reconnect_delay_max;
				}else{
					mosq->reconnects++;
				}

				rc = interruptible_sleep(mosq, (time_t)reconnect_delay);
				if(rc) return rc;

				state = mosquitto__get_state(mosq);
				if(state == mosq_cs_disconnecting || state == mosq_cs_disconnected){
					run = 0;
				}else{
					rc = mosquitto_reconnect(mosq);
				}
			}
		}while(run && rc != MOSQ_ERR_SUCCESS);
	}
	return rc;
}


int mosquitto_loop_misc(struct mosquitto *mosq)
{
	if(!mosq) return MOSQ_ERR_INVAL;
	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;

	return mosquitto__check_keepalive(mosq);
}


static int mosquitto__loop_rc_handle(struct mosquitto *mosq, int rc)
{
	enum mosquitto_client_state state;

	if(rc){
		net__socket_close(mosq);
		state = mosquitto__get_state(mosq);
		if(state == mosq_cs_disconnecting || state == mosq_cs_disconnected){
			rc = MOSQ_ERR_SUCCESS;
		}
		pthread_mutex_lock(&mosq->callback_mutex);
		if(mosq->on_disconnect){
			mosq->in_callback = true;
			mosq->on_disconnect(mosq, mosq->userdata, rc);
			mosq->in_callback = false;
		}
		if(mosq->on_disconnect_v5){
			mosq->in_callback = true;
			mosq->on_disconnect_v5(mosq, mosq->userdata, rc, NULL);
			mosq->in_callback = false;
		}
		pthread_mutex_unlock(&mosq->callback_mutex);
	}
	return rc;
}


int mosquitto_loop_read(struct mosquitto *mosq, int max_packets)
{
	int rc = MOSQ_ERR_SUCCESS;
	int i;
	if(max_packets < 1) return MOSQ_ERR_INVAL;

#ifdef WITH_TLS
	if(mosq->want_connect){
		return net__socket_connect_tls(mosq);
	}
#endif

	pthread_mutex_lock(&mosq->msgs_out.mutex);
	max_packets = mosq->msgs_out.queue_len;
	pthread_mutex_unlock(&mosq->msgs_out.mutex);

	pthread_mutex_lock(&mosq->msgs_in.mutex);
	max_packets += mosq->msgs_in.queue_len;
	pthread_mutex_unlock(&mosq->msgs_in.mutex);

	if(max_packets < 1) max_packets = 1;
	/* Queue len here tells us how many messages are awaiting processing and
	 * have QoS > 0. We should try to deal with that many in this loop in order
	 * to keep up. */
	for(i=0; i<max_packets || SSL_DATA_PENDING(mosq); i++){
#ifdef WITH_SOCKS
		if(mosq->socks5_host){
			rc = socks5__read(mosq);
		}else
#endif
		{
			rc = packet__read(mosq);
		}
		if(rc || errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
			return mosquitto__loop_rc_handle(mosq, rc);
		}
	}
	return rc;
}


int mosquitto_loop_write(struct mosquitto *mosq, int max_packets)
{
	int rc = MOSQ_ERR_SUCCESS;
	int i;
	if(max_packets < 1) return MOSQ_ERR_INVAL;

	for(i=0; i<max_packets; i++){
		rc = packet__write(mosq);
		if(rc || errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
			return mosquitto__loop_rc_handle(mosq, rc);
		}
	}
	return rc;
}

