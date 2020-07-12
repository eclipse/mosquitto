/*
Copyright (c) 2011-2020 Roger Light <roger@atchoo.org>

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

#ifndef WIN32
#include <time.h>
#endif

#include "mosquitto_internal.h"
#include "net_mosq.h"
#include "util_mosq.h"

void *mosquitto__thread_main(void *obj);

int mosquitto_loop_start(struct mosquitto *mosq)
{
#if defined(WITH_THREADING) && defined(HAVE_PTHREAD_CANCEL)
	if(!mosq || mosq->threaded != mosq_ts_none) return MOSQ_ERR_INVAL;

	mosq->threaded = mosq_ts_self;
	if(!pthread_create(&mosq->thread_id, NULL, mosquitto__thread_main, mosq)){
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_ERRNO;
	}
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}

int mosquitto_loop_stop(struct mosquitto *mosq, bool force)
{
#if defined(WITH_THREADING) && defined(HAVE_PTHREAD_CANCEL)
#  ifndef WITH_BROKER
	char sockpair_data = 0;
#  endif

	if(!mosq || mosq->threaded != mosq_ts_self) return MOSQ_ERR_INVAL;


	/* Write a single byte to sockpairW (connected to sockpairR) to break out
	 * of select() if in threaded mode. */
	if(mosq->sockpairW != INVALID_SOCKET){
#ifndef WIN32
		if(write(mosq->sockpairW, &sockpair_data, 1)){
		}
#else
		send(mosq->sockpairW, &sockpair_data, 1, 0);
#endif
	}
	
	if(force){
		pthread_cancel(mosq->thread_id);
	}
	pthread_join(mosq->thread_id, NULL);
	mosq->thread_id = pthread_self();
	mosq->threaded = mosq_ts_none;

	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}

#ifdef WITH_THREADING
int mosquitto__loop_forever(struct mosquitto *mosq, int timeout, int max_packets, bool explicit_cancellation_points);

void *mosquitto__thread_main(void *obj)
{
	struct mosquitto *mosq = obj;
	int state;
#ifndef WIN32
	bool explicit_cancellation_points = false;
	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 10000000;
#else
	bool explicit_cancellation_points = true;
#endif

	if(!mosq) return NULL;

	do{
		state = mosquitto__get_state(mosq);
		if(state == mosq_cs_new){
#ifdef WIN32
			Sleep(10);
#else
			nanosleep(&ts, NULL);
#endif
		}else{
			break;
		}
	}while(1);

	if(!mosq->keepalive){
		/* Sleep for a day if keepalive disabled. */
		mosquitto__loop_forever(mosq, 1000*86400, 1, explicit_cancellation_points);
	}else{
		/* Sleep for our keepalive value. publish() etc. will wake us up. */
		mosquitto__loop_forever(mosq, mosq->keepalive*1000, 1, explicit_cancellation_points);
	}

	return obj;
}
#endif

int mosquitto_threaded_set(struct mosquitto *mosq, bool threaded)
{
	if(!mosq) return MOSQ_ERR_INVAL;

	if(threaded){
		mosq->threaded = mosq_ts_external;
	}else{
		mosq->threaded = mosq_ts_none;
	}

	return MOSQ_ERR_SUCCESS;
}
