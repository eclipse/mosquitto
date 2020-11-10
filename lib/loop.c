/*
Copyright (c) 2010-2020 Roger Light <roger@atchoo.org>

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

/*
 * this should be set my cmake, not just defined here
 */
#define HAVE_PPOLL 1

#include <errno.h>

#ifndef HAVE_PPOLL
#ifndef WIN32
#include <sys/select.h>
#include <time.h>
#endif
#else
#include <sys/poll.h>
#include <time.h>
#endif

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "socks_mosq.h"
#include "tls_mosq.h"
#include "util_mosq.h"

#ifndef HAVE_PPOLL
#if !defined(WIN32) && !defined(__SYMBIAN32__)
#define HAVE_PSELECT
#endif
#endif

int mosquitto_loop(struct mosquitto *mosq, int timeout, int max_packets)
{
#if defined(HAVE_PSELECT) || defined(HAVE_PPOLL)
	struct timespec local_timeout;
#else
	struct timeval local_timeout;
#endif
#ifndef HAVE_PPOLL
	fd_set readfds, writefds;
#else
	int sockR, sockW, sockRr;
	int readyR, readyW, readyRr; 
	struct pollfd   pfd[3];	
#endif
	int fdcount;
	int rc;
	char pairbuf;
	int maxfd = 0;
	time_t now;
#ifdef WITH_SRV
	int state;
#endif

	if(!mosq || max_packets < 1) return MOSQ_ERR_INVAL;
#ifndef HAVE_PPOLL
#ifndef WIN32
	if(mosq->sock >= FD_SETSIZE || mosq->sockpairR >= FD_SETSIZE){
		return MOSQ_ERR_INVAL;
	}
#endif
#endif

#ifdef HAVE_PPOLL
	sockR = sockW = sockRr = 0;
	readyR = readyW = readyRr = 0; 
#else
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
#endif
	
	if(mosq->sock != INVALID_SOCKET){
#ifdef HAVE_PPOLL
		sockR = mosq->sock;
#else
		maxfd = mosq->sock;
		FD_SET(mosq->sock, &readfds);
#endif
		pthread_mutex_lock(&mosq->current_out_packet_mutex);
		pthread_mutex_lock(&mosq->out_packet_mutex);
		if(mosq->out_packet || mosq->current_out_packet){
#ifdef HAVE_PPOLL
		  sockW = mosq->sock;
#else
		  FD_SET(mosq->sock, &writefds);
#endif
		}
#ifdef WITH_TLS
		if(mosq->ssl){
			if(mosq->want_write){
#ifdef HAVE_PPOLL
   			        sockW = mosq->sock;
#else
				FD_SET(mosq->sock, &writefds);
#endif
			}else if(mosq->want_connect){
				/* Remove possible FD_SET from above, we don't want to check
				 * for writing if we are still connecting, unless want_write is
				 * definitely set. The presence of outgoing packets does not
				 * matter yet. */
#ifdef HAVE_PPOLL
			  sockW = 0;
#else
			  FD_CLR(mosq->sock, &writefds);
#endif
			}
		}
#endif
		pthread_mutex_unlock(&mosq->out_packet_mutex);
		pthread_mutex_unlock(&mosq->current_out_packet_mutex);
	}else{
#ifdef WITH_SRV
		if(mosq->achan){
			state = mosquitto__get_state(mosq);
			if(state == mosq_cs_connect_srv){
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
#ifdef HAVE_PPOLL
	        sockRr = mosq->sockpairR;
#else
	        FD_SET(mosq->sockpairR, &readfds);
		if(mosq->sockpairR > maxfd){
			maxfd = mosq->sockpairR;
		}
#endif
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
#if defined(HAVE_PSELECT) || defined(HAVE_PPOLL)
	local_timeout.tv_nsec = (timeout-local_timeout.tv_sec*1000)*1e6;
#else
	local_timeout.tv_usec = (timeout-local_timeout.tv_sec*1000)*1000;
#endif

#ifdef HAVE_PPOLL
	maxfd = 0; 
	if (sockR)  { pfd[maxfd].fd = sockR;  pfd[maxfd].events = POLLIN;  pfd[maxfd].revents = 0; maxfd++; }
	if (sockW)  { pfd[maxfd].fd = sockW;  pfd[maxfd].events = POLLOUT; pfd[maxfd].revents = 0; maxfd++; }
	if (sockRr) { pfd[maxfd].fd = sockRr; pfd[maxfd].events = POLLIN;  pfd[maxfd].revents = 0; maxfd++; }
	fdcount = ppoll(pfd,maxfd,&local_timeout, NULL);
	int i;
	for (i=0; i<maxfd; i++) {
	  if ((pfd[i].fd == sockR) &&
	      (pfd[i].revents & (POLLRDNORM|POLLRDBAND|POLLIN|POLLHUP|POLLERR)))
	    readyR = 1;
	  if ((pfd[i].fd == sockRr) &&
	      (pfd[i].revents & (POLLRDNORM|POLLRDBAND|POLLIN|POLLHUP|POLLERR)))
	    readyRr = 1;
	  if ((pfd[i].fd == sockW) &&
	      (pfd[i].revents & (POLLWRNORM|POLLWRBAND|POLLOUT|POLLERR)))
	    readyW = 1; 
	}	    
#else
#ifdef HAVE_PSELECT
	fdcount = pselect(maxfd+1, &readfds, &writefds, NULL, &local_timeout, NULL);
#else
	fdcount = select(maxfd+1, &readfds, &writefds, NULL, &local_timeout);
#endif
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
#ifdef HAVE_PPOLL
		  if(readyR){
#else
		  if(FD_ISSET(mosq->sock, &readfds)){
#endif
				rc = mosquitto_loop_read(mosq, max_packets);
				if(rc || mosq->sock == INVALID_SOCKET){
					return rc;
				}
			}
#ifdef HAVE_PPOLL
   		    if(mosq->sockpairR != INVALID_SOCKET && readyRr){
#else
		    if(mosq->sockpairR != INVALID_SOCKET && FD_ISSET(mosq->sockpairR, &readfds)){
#endif
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
#ifdef HAVE_PPOLL
				  readyW = 1;
#else
				  FD_SET(mosq->sock, &writefds);
#endif
			}
#ifdef HAVE_PPOLL
   		        if(mosq->sock != INVALID_SOCKET && readyW){
#else
			if(mosq->sock != INVALID_SOCKET && FD_ISSET(mosq->sock, &writefds)){
#endif
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


static int interruptible_sleep(struct mosquitto *mosq, unsigned long reconnect_delay)
{
#if defined(HAVE_PSELECT) || defined(HAVE_PPOLL)
	struct timespec local_timeout;
#else
	struct timeval local_timeout;
#endif
#ifdef HAVE_PPOLL
	struct pollfd   pfd[1];
#else
	fd_set readfds;
#endif
	int fdcount;
	char pairbuf;
	int maxfd = 0;

	local_timeout.tv_sec = reconnect_delay;
#if defined(HAVE_PSELECT) || defined(HAVE_PPOLL)
	local_timeout.tv_nsec = 0;
#else
	local_timeout.tv_usec = 0;
#endif

#ifndef HAVE_PPOLL
	FD_ZERO(&readfds);
#endif
	maxfd = 0;
	if(mosq->sockpairR != INVALID_SOCKET){
		/* sockpairR is used to break out of select() before the
		 * timeout, when mosquitto_loop_stop() is called */
#ifdef HAVE_PPOLL
                pfd[0].fd = mosq->sockpairR;
                pfd[0].events = POLLIN;
	        maxfd = 1;
#else
	        FD_SET(mosq->sockpairR, &readfds);
		maxfd = mosq->sockpairR;
#endif
	}
#ifdef HAVE_PPOLL
	fdcount = ppoll(pfd,maxfd,&local_timeout, NULL);
#else
#ifdef HAVE_PSELECT
	fdcount = pselect(maxfd+1, &readfds, NULL, NULL, &local_timeout, NULL);
#else
	fdcount = select(maxfd+1, &readfds, NULL, NULL, &local_timeout);
#endif
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
#ifdef HAVE_PPOLL
	}else if(mosq->sockpairR != INVALID_SOCKET && (pfd[0].revents & (POLLRDNORM|POLLRDBAND|POLLIN|POLLHUP|POLLERR))){
#else
	}else if(mosq->sockpairR != INVALID_SOCKET && FD_ISSET(mosq->sockpairR, &readfds)){
#endif
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
	int rc;
	unsigned long reconnect_delay;
	int state;

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

				rc = interruptible_sleep(mosq, reconnect_delay);
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
	int state;

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
	int rc;
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
	int rc;
	int i;
	if(max_packets < 1) return MOSQ_ERR_INVAL;

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
	for(i=0; i<max_packets; i++){
		rc = packet__write(mosq);
		if(rc || errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
			return mosquitto__loop_rc_handle(mosq, rc);
		}
	}
	return rc;
}

