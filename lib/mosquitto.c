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
#include <signal.h>
#include <string.h>
#ifndef WIN32
#include <sys/time.h>
#include <strings.h>
#endif

#if defined(__APPLE__)
#  include <mach/mach_time.h>
#endif

#include "logging_mosq.h"
#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "will_mosq.h"

static unsigned int init_refcount = 0;

void mosquitto__destroy(struct mosquitto *mosq);

int mosquitto_lib_version(int *major, int *minor, int *revision)
{
	if(major) *major = LIBMOSQUITTO_MAJOR;
	if(minor) *minor = LIBMOSQUITTO_MINOR;
	if(revision) *revision = LIBMOSQUITTO_REVISION;
	return LIBMOSQUITTO_VERSION_NUMBER;
}

int mosquitto_lib_init(void)
{
	int rc;

	if (init_refcount == 0) {
#ifdef WIN32
		srand((unsigned int)GetTickCount64());
#elif _POSIX_TIMERS>0 && defined(_POSIX_MONOTONIC_CLOCK)
		struct timespec tp;

		clock_gettime(CLOCK_MONOTONIC, &tp);
		srand((unsigned int)tp.tv_nsec);
#elif defined(__APPLE__)
		uint64_t ticks;

		ticks = mach_absolute_time();
		srand((unsigned int)ticks);
#else
		struct timeval tv;

		gettimeofday(&tv, NULL);
		srand(tv.tv_sec*1000 + tv.tv_usec/1000);
#endif

		rc = net__init();
		if (rc != MOSQ_ERR_SUCCESS) {
			return rc;
		}
	}

	init_refcount++;
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_lib_cleanup(void)
{
	if (init_refcount == 1) {
		net__cleanup();
	}

	if (init_refcount > 0) {
		--init_refcount;
	}

	return MOSQ_ERR_SUCCESS;
}

struct mosquitto *mosquitto_new(const char *id, bool clean_start, void *userdata)
{
	struct mosquitto *mosq = NULL;
	int rc;

	if(clean_start == false && id == NULL){
		errno = EINVAL;
		return NULL;
	}

#ifndef WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	mosq = (struct mosquitto *)mosquitto__calloc(1, sizeof(struct mosquitto));
	if(mosq){
		mosq->sock = INVALID_SOCKET;
#ifdef WITH_THREADING
		mosq->thread_id = pthread_self();
#endif
		mosq->sockpairR = INVALID_SOCKET;
		mosq->sockpairW = INVALID_SOCKET;
		rc = mosquitto_reinitialise(mosq, id, clean_start, userdata);
		if(rc){
			mosquitto_destroy(mosq);
			if(rc == MOSQ_ERR_INVAL){
				errno = EINVAL;
			}else if(rc == MOSQ_ERR_NOMEM){
				errno = ENOMEM;
			}
			return NULL;
		}
	}else{
		errno = ENOMEM;
	}
	return mosq;
}

int mosquitto_reinitialise(struct mosquitto *mosq, const char *id, bool clean_start, void *userdata)
{
	if(!mosq) return MOSQ_ERR_INVAL;

	if(clean_start == false && id == NULL){
		return MOSQ_ERR_INVAL;
	}

	mosquitto__destroy(mosq);
	memset(mosq, 0, sizeof(struct mosquitto));

	if(userdata){
		mosq->userdata = userdata;
	}else{
		mosq->userdata = mosq;
	}
	mosq->protocol = mosq_p_mqtt311;
	mosq->sock = INVALID_SOCKET;
	mosq->keepalive = 60;
	mosq->clean_start = clean_start;
	if(id){
		if(STREMPTY(id)){
			return MOSQ_ERR_INVAL;
		}
		if(mosquitto_validate_utf8(id, (int)strlen(id))){
			return MOSQ_ERR_MALFORMED_UTF8;
		}
		mosq->id = mosquitto__strdup(id);
	}
	mosq->in_packet.payload = NULL;
	packet__cleanup(&mosq->in_packet);
	mosq->out_packet = NULL;
	mosq->current_out_packet = NULL;
	mosq->last_msg_in = mosquitto_time();
	mosq->next_msg_out = mosquitto_time() + mosq->keepalive;
	mosq->ping_t = 0;
	mosq->last_mid = 0;
	mosq->state = mosq_cs_new;
	mosq->max_qos = 2;
	mosq->msgs_in.inflight_maximum = 20;
	mosq->msgs_out.inflight_maximum = 20;
	mosq->msgs_in.inflight_quota = 20;
	mosq->msgs_out.inflight_quota = 20;
	mosq->will = NULL;
	mosq->on_connect = NULL;
	mosq->on_publish = NULL;
	mosq->on_message = NULL;
	mosq->on_subscribe = NULL;
	mosq->on_unsubscribe = NULL;
	mosq->host = NULL;
	mosq->port = 1883;
	mosq->in_callback = false;
	mosq->reconnect_delay = 1;
	mosq->reconnect_delay_max = 1;
	mosq->reconnect_exponential_backoff = false;
	mosq->threaded = mosq_ts_none;
#ifdef WITH_TLS
	mosq->ssl = NULL;
	mosq->ssl_ctx = NULL;
	mosq->tls_cert_reqs = SSL_VERIFY_PEER;
	mosq->tls_insecure = false;
	mosq->want_write = false;
	mosq->tls_ocsp_required = false;
#endif
#ifdef WITH_THREADING
	pthread_mutex_init(&mosq->callback_mutex, NULL);
	pthread_mutex_init(&mosq->log_callback_mutex, NULL);
	pthread_mutex_init(&mosq->state_mutex, NULL);
	pthread_mutex_init(&mosq->out_packet_mutex, NULL);
	pthread_mutex_init(&mosq->current_out_packet_mutex, NULL);
	pthread_mutex_init(&mosq->msgtime_mutex, NULL);
	pthread_mutex_init(&mosq->msgs_in.mutex, NULL);
	pthread_mutex_init(&mosq->msgs_out.mutex, NULL);
	pthread_mutex_init(&mosq->mid_mutex, NULL);
	mosq->thread_id = pthread_self();
#endif
	/* This must be after pthread_mutex_init(), otherwise the log mutex may be
	 * used before being initialised. */
	if(net__socketpair(&mosq->sockpairR, &mosq->sockpairW)){
		log__printf(mosq, MOSQ_LOG_WARNING,
				"Warning: Unable to open socket pair, outgoing publish commands may be delayed.");
	}

	return MOSQ_ERR_SUCCESS;
}


void mosquitto__destroy(struct mosquitto *mosq)
{
	if(!mosq) return;

#ifdef WITH_THREADING
#  ifdef HAVE_PTHREAD_CANCEL
	if(mosq->threaded == mosq_ts_self && !pthread_equal(mosq->thread_id, pthread_self())){
		pthread_cancel(mosq->thread_id);
		pthread_join(mosq->thread_id, NULL);
		mosq->threaded = mosq_ts_none;
	}
#  endif

	if(mosq->id){
		/* If mosq->id is not NULL then the client has already been initialised
		 * and so the mutexes need destroying. If mosq->id is NULL, the mutexes
		 * haven't been initialised. */
		pthread_mutex_destroy(&mosq->callback_mutex);
		pthread_mutex_destroy(&mosq->log_callback_mutex);
		pthread_mutex_destroy(&mosq->state_mutex);
		pthread_mutex_destroy(&mosq->out_packet_mutex);
		pthread_mutex_destroy(&mosq->current_out_packet_mutex);
		pthread_mutex_destroy(&mosq->msgtime_mutex);
		pthread_mutex_destroy(&mosq->msgs_in.mutex);
		pthread_mutex_destroy(&mosq->msgs_out.mutex);
		pthread_mutex_destroy(&mosq->mid_mutex);
	}
#endif
	if(mosq->sock != INVALID_SOCKET){
		net__socket_close(mosq);
	}
	message__cleanup_all(mosq);
	will__clear(mosq);
#ifdef WITH_TLS
	if(mosq->ssl){
		SSL_free(mosq->ssl);
	}
	if(mosq->ssl_ctx){
		SSL_CTX_free(mosq->ssl_ctx);
	}
	mosquitto__free(mosq->tls_cafile);
	mosquitto__free(mosq->tls_capath);
	mosquitto__free(mosq->tls_certfile);
	mosquitto__free(mosq->tls_keyfile);
	if(mosq->tls_pw_callback) mosq->tls_pw_callback = NULL;
	mosquitto__free(mosq->tls_version);
	mosquitto__free(mosq->tls_ciphers);
	mosquitto__free(mosq->tls_psk);
	mosquitto__free(mosq->tls_psk_identity);
	mosquitto__free(mosq->tls_alpn);
#endif

	mosquitto__free(mosq->address);
	mosq->address = NULL;

	mosquitto__free(mosq->id);
	mosq->id = NULL;

	mosquitto__free(mosq->username);
	mosq->username = NULL;

	mosquitto__free(mosq->password);
	mosq->password = NULL;

	mosquitto__free(mosq->host);
	mosq->host = NULL;

	mosquitto__free(mosq->bind_address);
	mosq->bind_address = NULL;

	mosquitto_property_free_all(&mosq->connect_properties);

	packet__cleanup_all_no_locks(mosq);

	packet__cleanup(&mosq->in_packet);
	if(mosq->sockpairR != INVALID_SOCKET){
		COMPAT_CLOSE(mosq->sockpairR);
		mosq->sockpairR = INVALID_SOCKET;
	}
	if(mosq->sockpairW != INVALID_SOCKET){
		COMPAT_CLOSE(mosq->sockpairW);
		mosq->sockpairW = INVALID_SOCKET;
	}
}

void mosquitto_destroy(struct mosquitto *mosq)
{
	if(!mosq) return;

	mosquitto__destroy(mosq);
	mosquitto__free(mosq);
}

int mosquitto_socket(struct mosquitto *mosq)
{
	if(!mosq) return INVALID_SOCKET;
	return mosq->sock;
}


bool mosquitto_want_write(struct mosquitto *mosq)
{
	bool result = false;
	if(mosq->out_packet || mosq->current_out_packet){
		result = true;
	}
#ifdef WITH_TLS
	if(mosq->ssl){
		if (mosq->want_write) {
			result = true;
		}else if(mosq->want_connect){
			result = false;
		}
	}
#endif
	return result;
}


int mosquitto_sub_topic_tokenise(const char *subtopic, char ***topics, int *count)
{
	size_t len;
	size_t hier_count = 1;
	size_t start, stop;
	size_t hier;
	size_t tlen;
	size_t i, j;

	if(!subtopic || !topics || !count) return MOSQ_ERR_INVAL;

	len = strlen(subtopic);

	for(i=0; i<len; i++){
		if(subtopic[i] == '/'){
			if(i > len-1){
				/* Separator at end of line */
			}else{
				hier_count++;
			}
		}
	}

	(*topics) = mosquitto__calloc(hier_count, sizeof(char *));
	if(!(*topics)) return MOSQ_ERR_NOMEM;

	start = 0;
	hier = 0;

	for(i=0; i<len+1; i++){
		if(subtopic[i] == '/' || subtopic[i] == '\0'){
			stop = i;
			if(start != stop){
				tlen = stop-start + 1;
				(*topics)[hier] = mosquitto__calloc(tlen, sizeof(char));
				if(!(*topics)[hier]){
					for(j=0; j<hier; j++){
						mosquitto__free((*topics)[j]);
					}
					mosquitto__free((*topics));
					return MOSQ_ERR_NOMEM;
				}
				for(j=start; j<stop; j++){
					(*topics)[hier][j-start] = subtopic[j];
				}
			}
			start = i+1;
			hier++;
		}
	}

	*count = (int)hier_count;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_sub_topic_tokens_free(char ***topics, int count)
{
	int i;

	if(!topics || !(*topics) || count<1) return MOSQ_ERR_INVAL;

	for(i=0; i<count; i++){
		mosquitto__free((*topics)[i]);
	}
	mosquitto__free(*topics);

	return MOSQ_ERR_SUCCESS;
}

