/*
Copyright (c) 2010-2018 Roger Light <roger@atchoo.org>

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

#if !defined(WIN32) && !defined(__SYMBIAN32__)
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
			pthread_mutex_lock(&mosq->state_mutex);
			if(mosq->state == mosq_cs_connect_srv){
				rc = ares_fds(mosq->achan, &readfds, &writefds);
				if(rc > maxfd){
					maxfd = rc;
				}
			}else{
				pthread_mutex_unlock(&mosq->state_mutex);
				return MOSQ_ERR_NO_CONN;
			}
			pthread_mutex_unlock(&mosq->state_mutex);
		}
#else
		return MOSQ_ERR_NO_CONN;
#endif
	}
	if(mosq->sockpairR != INVALID_SOCKET){
		/* sockpairR is used to break out of select() before the timeout, on a
		 * call to publish() etc. */
		FD_SET(mosq->sockpairR, &readfds);
		if(mosq->sockpairR > maxfd){
			maxfd = mosq->sockpairR;
		}
	}

	if(timeout < 0){
		timeout = 1000;
	}

	now = mosquitto_time();
	if(mosq->next_msg_out && now + timeout/1000 > mosq->next_msg_out){
		timeout = (mosq->next_msg_out - now)*1000;
	}

	if(timeout < 0){
		/* There has been a delay somewhere which means we should have already
		 * sent a message. */
		timeout = 0;
	}

	local_timeout.tv_sec = timeout/1000;
#ifdef HAVE_PSELECT
	local_timeout.tv_nsec = (timeout-local_timeout.tv_sec*1000)*1e6;
#else
	local_timeout.tv_usec = (timeout-local_timeout.tv_sec*1000)*1000;
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


int mosquitto_loop_forever(struct mosquitto *mosq, int timeout, int max_packets)
{
	int run = 1;
	int rc;
	unsigned int reconnects = 0;
	unsigned long reconnect_delay;
#ifndef WIN32
	struct timespec req, rem;
#endif

	if(!mosq) return MOSQ_ERR_INVAL;

	if(mosq->state == mosq_cs_connect_async){
		mosquitto_reconnect(mosq);
	}

	while(run){
		do{
			rc = mosquitto_loop(mosq, timeout, max_packets);
			if (reconnects !=0 && rc == MOSQ_ERR_SUCCESS){
				reconnects = 0;
			}
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
			rc = MOSQ_ERR_SUCCESS;
			pthread_mutex_lock(&mosq->state_mutex);
			if(mosq->state == mosq_cs_disconnecting){
				run = 0;
				pthread_mutex_unlock(&mosq->state_mutex);
			}else{
				pthread_mutex_unlock(&mosq->state_mutex);

				if(mosq->reconnect_delay > 0 && mosq->reconnect_exponential_backoff){
					reconnect_delay = mosq->reconnect_delay*reconnects*reconnects;
				}else{
					reconnect_delay = mosq->reconnect_delay;
				}

				if(reconnect_delay > mosq->reconnect_delay_max){
					reconnect_delay = mosq->reconnect_delay_max;
				}else{
					reconnects++;
				}

#ifdef WIN32
				Sleep(reconnect_delay*1000);
#else
				req.tv_sec = reconnect_delay;
				req.tv_nsec = 0;
				while(nanosleep(&req, &rem) == -1 && errno == EINTR){
					req = rem;
				}
#endif

				pthread_mutex_lock(&mosq->state_mutex);
				if(mosq->state == mosq_cs_disconnecting){
					run = 0;
					pthread_mutex_unlock(&mosq->state_mutex);
				}else{
					pthread_mutex_unlock(&mosq->state_mutex);
					rc = mosquitto_reconnect(mosq);
				}
			}
		}while(run && rc != MOSQ_ERR_SUCCESS);
	}
	return rc;
}


int mosquitto_loop_misc(struct mosquitto *mosq)
{
	time_t now;
	int rc;

	if(!mosq) return MOSQ_ERR_INVAL;
	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;

	mosquitto__check_keepalive(mosq);
	now = mosquitto_time();

	if(mosq->ping_t && now - mosq->ping_t >= mosq->keepalive){
		/* mosq->ping_t != 0 means we are waiting for a pingresp.
		 * This hasn't happened in the keepalive time so we should disconnect.
		 */
		net__socket_close(mosq);
		pthread_mutex_lock(&mosq->state_mutex);
		if(mosq->state == mosq_cs_disconnecting){
			rc = MOSQ_ERR_SUCCESS;
		}else{
			rc = MOSQ_ERR_KEEPALIVE;
		}
		pthread_mutex_unlock(&mosq->state_mutex);
		pthread_mutex_lock(&mosq->callback_mutex);
		if(mosq->on_disconnect){
			mosq->in_callback = true;
			mosq->on_disconnect(mosq, mosq->userdata, rc);
			mosq->in_callback = false;
		}
		pthread_mutex_unlock(&mosq->callback_mutex);
		return MOSQ_ERR_CONN_LOST;
	}
	return MOSQ_ERR_SUCCESS;
}


static int mosquitto__loop_rc_handle(struct mosquitto *mosq, int rc)
{
	if(rc){
		net__socket_close(mosq);
		pthread_mutex_lock(&mosq->state_mutex);
		if(mosq->state == mosq_cs_disconnecting){
			rc = MOSQ_ERR_SUCCESS;
		}
		pthread_mutex_unlock(&mosq->state_mutex);
		pthread_mutex_lock(&mosq->callback_mutex);
		if(mosq->on_disconnect){
			mosq->in_callback = true;
			mosq->on_disconnect(mosq, mosq->userdata, rc);
			mosq->in_callback = false;
		}
		pthread_mutex_unlock(&mosq->callback_mutex);
		return rc;
	}
	return rc;
}


int mosquitto_loop_read(struct mosquitto *mosq, int max_packets)
{
	int rc;
	int i;
	if(max_packets < 1) return MOSQ_ERR_INVAL;

#ifdef WITH_TLS
	if(mosq->want_connect){
		return net__socket_connect_tls(mosq);
	}
#endif

	pthread_mutex_lock(&mosq->out_message_mutex);
	max_packets = mosq->out_queue_len;
	pthread_mutex_unlock(&mosq->out_message_mutex);

	pthread_mutex_lock(&mosq->in_message_mutex);
	max_packets += mosq->in_queue_len;
	pthread_mutex_unlock(&mosq->in_message_mutex);

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
	int rc;
	int i;
	if(max_packets < 1) return MOSQ_ERR_INVAL;

	pthread_mutex_lock(&mosq->out_message_mutex);
	max_packets = mosq->out_queue_len;
	pthread_mutex_unlock(&mosq->out_message_mutex);

	pthread_mutex_lock(&mosq->in_message_mutex);
	max_packets += mosq->in_queue_len;
	pthread_mutex_unlock(&mosq->in_message_mutex);

	if(max_packets < 1) max_packets = 1;
	/* Queue len here tells us how many messages are awaiting processing and
	 * have QoS > 0. We should try to deal with that many in this loop in order
	 * to keep up. */
	for(i=0; i<max_packets; i++){
		rc = packet__write(mosq);
		if(rc || errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
			return mosquitto__loop_rc_handle(mosq, rc);
		}
	}
	return rc;
}

