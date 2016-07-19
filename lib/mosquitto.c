/*
Copyright (c) 2010-2015 Roger Light <roger@atchoo.org>

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

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <windows.h>
typedef int ssize_t;
#endif

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "logging_mosq.h"
#include "messages_mosq.h"
#include "memory_mosq.h"
#include "mqtt3_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "socks_mosq.h"
#include "time_mosq.h"
#include "tls_mosq.h"
#include "util_mosq.h"
#include "will_mosq.h"

#include "config.h"

#if !defined(WIN32) && !defined(__SYMBIAN32__)
#define HAVE_PSELECT
#endif

void mosquitto__destroy(struct mosquitto *mosq);
static int mosquitto__reconnect(struct mosquitto *mosq, bool blocking);
static int mosquitto__connect_init(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address);

int mosquitto_lib_version(int *major, int *minor, int *revision)
{
	if(major) *major = LIBMOSQUITTO_MAJOR;
	if(minor) *minor = LIBMOSQUITTO_MINOR;
	if(revision) *revision = LIBMOSQUITTO_REVISION;
	return LIBMOSQUITTO_VERSION_NUMBER;
}

int mosquitto_lib_init(void)
{
#ifdef WIN32
	srand(GetTickCount64());
#else
	struct timeval tv;

	gettimeofday(&tv, NULL);
	srand(tv.tv_sec*1000 + tv.tv_usec/1000);
#endif

	return net__init();
}

int mosquitto_lib_cleanup(void)
{
	net__cleanup();

	return MOSQ_ERR_SUCCESS;
}

struct mosquitto *mosquitto_new(const char *id, bool clean_session, void *userdata)
{
	struct mosquitto *mosq = NULL;
	int rc;

	if(clean_session == false && id == NULL){
		errno = EINVAL;
		return NULL;
	}

#ifndef WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	mosq = (struct mosquitto *)mosquitto__calloc(1, sizeof(struct mosquitto));
	if(mosq){
		mosq->sock = INVALID_SOCKET;
		mosq->sockpairR = INVALID_SOCKET;
		mosq->sockpairW = INVALID_SOCKET;
#ifdef WITH_THREADING
		mosq->thread_id = pthread_self();
#endif
		rc = mosquitto_reinitialise(mosq, id, clean_session, userdata);
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

int mosquitto_reinitialise(struct mosquitto *mosq, const char *id, bool clean_session, void *userdata)
{
	int i;

	if(!mosq) return MOSQ_ERR_INVAL;

	if(clean_session == false && id == NULL){
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
	mosq->sockpairR = INVALID_SOCKET;
	mosq->sockpairW = INVALID_SOCKET;
	mosq->keepalive = 60;
	mosq->clean_session = clean_session;
	if(id){
		if(STREMPTY(id)){
			return MOSQ_ERR_INVAL;
		}
		mosq->id = mosquitto__strdup(id);
	}else{
		mosq->id = (char *)mosquitto__calloc(24, sizeof(char));
		if(!mosq->id){
			return MOSQ_ERR_NOMEM;
		}
		mosq->id[0] = 'm';
		mosq->id[1] = 'o';
		mosq->id[2] = 's';
		mosq->id[3] = 'q';
		mosq->id[4] = '/';

		for(i=5; i<23; i++){
			mosq->id[i] = (rand()%73)+48;
		}
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
	mosq->in_messages = NULL;
	mosq->in_messages_last = NULL;
	mosq->out_messages = NULL;
	mosq->out_messages_last = NULL;
	mosq->max_inflight_messages = 20;
	mosq->will = NULL;
	mosq->on_connect = NULL;
	mosq->on_publish = NULL;
	mosq->on_message = NULL;
	mosq->on_subscribe = NULL;
	mosq->on_unsubscribe = NULL;
	mosq->host = NULL;
	mosq->port = 1883;
	mosq->in_callback = false;
	mosq->in_queue_len = 0;
	mosq->out_queue_len = 0;
	mosq->reconnect_delay = 1;
	mosq->reconnect_delay_max = 1;
	mosq->reconnect_exponential_backoff = false;
	mosq->threaded = mosq_ts_none;
#ifdef WITH_TLS
	mosq->ssl = NULL;
	mosq->tls_cert_reqs = SSL_VERIFY_PEER;
	mosq->tls_server_name = NULL;
	mosq->tls_insecure = false;
	mosq->want_write = false;
#endif
#ifdef WITH_THREADING
	pthread_mutex_init(&mosq->callback_mutex, NULL);
	pthread_mutex_init(&mosq->log_callback_mutex, NULL);
	pthread_mutex_init(&mosq->state_mutex, NULL);
	pthread_mutex_init(&mosq->out_packet_mutex, NULL);
	pthread_mutex_init(&mosq->current_out_packet_mutex, NULL);
	pthread_mutex_init(&mosq->msgtime_mutex, NULL);
	pthread_mutex_init(&mosq->in_message_mutex, NULL);
	pthread_mutex_init(&mosq->out_message_mutex, NULL);
	pthread_mutex_init(&mosq->mid_mutex, NULL);
	mosq->thread_id = pthread_self();
#endif

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_will_set(struct mosquitto *mosq, const char *topic, int payloadlen, const void *payload, int qos, bool retain)
{
	if(!mosq) return MOSQ_ERR_INVAL;
	return will__set(mosq, topic, payloadlen, payload, qos, retain);
}

int mosquitto_will_clear(struct mosquitto *mosq)
{
	if(!mosq) return MOSQ_ERR_INVAL;
	return will__clear(mosq);
}

int mosquitto_username_pw_set(struct mosquitto *mosq, const char *username, const char *password)
{
	if(!mosq) return MOSQ_ERR_INVAL;

	mosquitto__free(mosq->username);
	mosq->username = NULL;

	mosquitto__free(mosq->password);
	mosq->password = NULL;

	if(username){
		mosq->username = mosquitto__strdup(username);
		if(!mosq->username) return MOSQ_ERR_NOMEM;
		if(password){
			mosq->password = mosquitto__strdup(password);
			if(!mosq->password){
				mosquitto__free(mosq->username);
				mosq->username = NULL;
				return MOSQ_ERR_NOMEM;
			}
		}
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_reconnect_delay_set(struct mosquitto *mosq, unsigned int reconnect_delay, unsigned int reconnect_delay_max, bool reconnect_exponential_backoff)
{
	if(!mosq) return MOSQ_ERR_INVAL;
	
	mosq->reconnect_delay = reconnect_delay;
	mosq->reconnect_delay_max = reconnect_delay_max;
	mosq->reconnect_exponential_backoff = reconnect_exponential_backoff;
	
	return MOSQ_ERR_SUCCESS;
	
}

void mosquitto__destroy(struct mosquitto *mosq)
{
	struct mosquitto__packet *packet;
	if(!mosq) return;

#ifdef WITH_THREADING
	if(mosq->threaded == mosq_ts_self && !pthread_equal(mosq->thread_id, pthread_self())){
		pthread_cancel(mosq->thread_id);
		pthread_join(mosq->thread_id, NULL);
		mosq->threaded = mosq_ts_none;
	}

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
		pthread_mutex_destroy(&mosq->in_message_mutex);
		pthread_mutex_destroy(&mosq->out_message_mutex);
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
	mosquitto__free(mosq->tls_server_name);
	if(mosq->tls_pw_callback) mosq->tls_pw_callback = NULL;
	mosquitto__free(mosq->tls_version);
	mosquitto__free(mosq->tls_ciphers);
	mosquitto__free(mosq->tls_psk);
	mosquitto__free(mosq->tls_psk_identity);
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

	/* Out packet cleanup */
	if(mosq->out_packet && !mosq->current_out_packet){
		mosq->current_out_packet = mosq->out_packet;
		mosq->out_packet = mosq->out_packet->next;
	}
	while(mosq->current_out_packet){
		packet = mosq->current_out_packet;
		/* Free data and reset values */
		mosq->current_out_packet = mosq->out_packet;
		if(mosq->out_packet){
			mosq->out_packet = mosq->out_packet->next;
		}

		packet__cleanup(packet);
		mosquitto__free(packet);
	}

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

static int mosquitto__connect_init(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address)
{
	if(!mosq) return MOSQ_ERR_INVAL;
	if(!host || port <= 0) return MOSQ_ERR_INVAL;

	mosquitto__free(mosq->host);
	mosq->host = mosquitto__strdup(host);
	if(!mosq->host) return MOSQ_ERR_NOMEM;
	mosq->port = port;

	mosquitto__free(mosq->bind_address);
	if(bind_address){
		mosq->bind_address = mosquitto__strdup(bind_address);
		if(!mosq->bind_address) return MOSQ_ERR_NOMEM;
	}

	mosq->keepalive = keepalive;

	if(mosq->sockpairR != INVALID_SOCKET){
		COMPAT_CLOSE(mosq->sockpairR);
		mosq->sockpairR = INVALID_SOCKET;
	}
	if(mosq->sockpairW != INVALID_SOCKET){
		COMPAT_CLOSE(mosq->sockpairW);
		mosq->sockpairW = INVALID_SOCKET;
	}

	if(net__socketpair(&mosq->sockpairR, &mosq->sockpairW)){
		log__printf(mosq, MOSQ_LOG_WARNING,
				"Warning: Unable to open socket pair, outgoing publish commands may be delayed.");
	}

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_connect(struct mosquitto *mosq, const char *host, int port, int keepalive)
{
	return mosquitto_connect_bind(mosq, host, port, keepalive, NULL);
}

int mosquitto_connect_bind(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address)
{
	int rc;
	rc = mosquitto__connect_init(mosq, host, port, keepalive, bind_address);
	if(rc) return rc;

	pthread_mutex_lock(&mosq->state_mutex);
	mosq->state = mosq_cs_new;
	pthread_mutex_unlock(&mosq->state_mutex);

	return mosquitto__reconnect(mosq, true);
}

int mosquitto_connect_async(struct mosquitto *mosq, const char *host, int port, int keepalive)
{
	return mosquitto_connect_bind_async(mosq, host, port, keepalive, NULL);
}

int mosquitto_connect_bind_async(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address)
{
	int rc = mosquitto__connect_init(mosq, host, port, keepalive, bind_address);
	if(rc) return rc;

	pthread_mutex_lock(&mosq->state_mutex);
	mosq->state = mosq_cs_connect_async;
	pthread_mutex_unlock(&mosq->state_mutex);

	return mosquitto__reconnect(mosq, false);
}

int mosquitto_reconnect_async(struct mosquitto *mosq)
{
	return mosquitto__reconnect(mosq, false);
}

int mosquitto_reconnect(struct mosquitto *mosq)
{
	return mosquitto__reconnect(mosq, true);
}

static int mosquitto__reconnect(struct mosquitto *mosq, bool blocking)
{
	int rc;
	struct mosquitto__packet *packet;
	if(!mosq) return MOSQ_ERR_INVAL;
	if(!mosq->host || mosq->port <= 0) return MOSQ_ERR_INVAL;

	pthread_mutex_lock(&mosq->state_mutex);
#ifdef WITH_SOCKS
	if(mosq->socks5_host){
		mosq->state = mosq_cs_socks5_new;
	}else
#endif
	{
		mosq->state = mosq_cs_new;
	}
	pthread_mutex_unlock(&mosq->state_mutex);

	pthread_mutex_lock(&mosq->msgtime_mutex);
	mosq->last_msg_in = mosquitto_time();
	mosq->next_msg_out = mosq->last_msg_in + mosq->keepalive;
	pthread_mutex_unlock(&mosq->msgtime_mutex);

	mosq->ping_t = 0;

	packet__cleanup(&mosq->in_packet);
		
	pthread_mutex_lock(&mosq->current_out_packet_mutex);
	pthread_mutex_lock(&mosq->out_packet_mutex);

	if(mosq->out_packet && !mosq->current_out_packet){
		mosq->current_out_packet = mosq->out_packet;
		mosq->out_packet = mosq->out_packet->next;
	}

	while(mosq->current_out_packet){
		packet = mosq->current_out_packet;
		/* Free data and reset values */
		mosq->current_out_packet = mosq->out_packet;
		if(mosq->out_packet){
			mosq->out_packet = mosq->out_packet->next;
		}

		packet__cleanup(packet);
		mosquitto__free(packet);
	}
	pthread_mutex_unlock(&mosq->out_packet_mutex);
	pthread_mutex_unlock(&mosq->current_out_packet_mutex);

	message__reconnect_reset(mosq);

#ifdef WITH_SOCKS
	if(mosq->socks5_host){
		rc = net__socket_connect(mosq, mosq->socks5_host, mosq->socks5_port, mosq->bind_address, blocking);
	}else
#endif
	{
		rc = net__socket_connect(mosq, mosq->host, mosq->port, mosq->bind_address, blocking);
	}
	if(rc>0){
		return rc;
	}

#ifdef WITH_SOCKS
	if(mosq->socks5_host){
		return socks5__send(mosq);
	}else
#endif
	{
		return send__connect(mosq, mosq->keepalive, mosq->clean_session);
	}
}

int mosquitto_disconnect(struct mosquitto *mosq)
{
	if(!mosq) return MOSQ_ERR_INVAL;

	pthread_mutex_lock(&mosq->state_mutex);
	mosq->state = mosq_cs_disconnecting;
	pthread_mutex_unlock(&mosq->state_mutex);

	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;
	return send__disconnect(mosq);
}

int mosquitto_publish(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain)
{
	struct mosquitto_message_all *message;
	uint16_t local_mid;
	int queue_status;

	if(!mosq || !topic || qos<0 || qos>2) return MOSQ_ERR_INVAL;
	if(STREMPTY(topic)) return MOSQ_ERR_INVAL;
	if(mosquitto_validate_utf8(topic, strlen(topic))) return MOSQ_ERR_MALFORMED_UTF8;
	if(payloadlen < 0 || payloadlen > MQTT_MAX_PAYLOAD) return MOSQ_ERR_PAYLOAD_SIZE;

	if(mosquitto_pub_topic_check(topic) != MOSQ_ERR_SUCCESS){
		return MOSQ_ERR_INVAL;
	}

	local_mid = mosquitto__mid_generate(mosq);
	if(mid){
		*mid = local_mid;
	}

	if(qos == 0){
		return send__publish(mosq, local_mid, topic, payloadlen, payload, qos, retain, false);
	}else{
		message = mosquitto__calloc(1, sizeof(struct mosquitto_message_all));
		if(!message) return MOSQ_ERR_NOMEM;

		message->next = NULL;
		message->timestamp = mosquitto_time();
		message->msg.mid = local_mid;
		message->msg.topic = mosquitto__strdup(topic);
		if(!message->msg.topic){
			message__cleanup(&message);
			return MOSQ_ERR_NOMEM;
		}
		if(payloadlen){
			message->msg.payloadlen = payloadlen;
			message->msg.payload = mosquitto__malloc(payloadlen*sizeof(uint8_t));
			if(!message->msg.payload){
				message__cleanup(&message);
				return MOSQ_ERR_NOMEM;
			}
			memcpy(message->msg.payload, payload, payloadlen*sizeof(uint8_t));
		}else{
			message->msg.payloadlen = 0;
			message->msg.payload = NULL;
		}
		message->msg.qos = qos;
		message->msg.retain = retain;
		message->dup = false;

		pthread_mutex_lock(&mosq->out_message_mutex);
		queue_status = message__queue(mosq, message, mosq_md_out);
		if(queue_status == 0){
			if(qos == 1){
				message->state = mosq_ms_wait_for_puback;
			}else if(qos == 2){
				message->state = mosq_ms_wait_for_pubrec;
			}
			pthread_mutex_unlock(&mosq->out_message_mutex);
			return send__publish(mosq, message->msg.mid, message->msg.topic, message->msg.payloadlen, message->msg.payload, message->msg.qos, message->msg.retain, message->dup);
		}else{
			message->state = mosq_ms_invalid;
			pthread_mutex_unlock(&mosq->out_message_mutex);
			return MOSQ_ERR_SUCCESS;
		}
	}
}

int mosquitto_subscribe(struct mosquitto *mosq, int *mid, const char *sub, int qos)
{
	if(!mosq) return MOSQ_ERR_INVAL;
	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;

	if(mosquitto_sub_topic_check(sub)) return MOSQ_ERR_INVAL;
	if(mosquitto_validate_utf8(sub, strlen(sub))) return MOSQ_ERR_MALFORMED_UTF8;

	return send__subscribe(mosq, mid, sub, qos);
}

int mosquitto_unsubscribe(struct mosquitto *mosq, int *mid, const char *sub)
{
	if(!mosq) return MOSQ_ERR_INVAL;
	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;

	if(mosquitto_sub_topic_check(sub)) return MOSQ_ERR_INVAL;
	if(mosquitto_validate_utf8(sub, strlen(sub))) return MOSQ_ERR_MALFORMED_UTF8;

	return send__unsubscribe(mosq, mid, sub);
}

int mosquitto_tls_set(struct mosquitto *mosq, const char *cafile, const char *capath, const char *certfile, const char *keyfile, int (*pw_callback)(char *buf, int size, int rwflag, void *userdata))
{
#ifdef WITH_TLS
	FILE *fptr;

	if(!mosq || (!cafile && !capath) || (certfile && !keyfile) || (!certfile && keyfile)) return MOSQ_ERR_INVAL;

	mosquitto__free(mosq->tls_cafile);
	mosq->tls_cafile = NULL;
	if(cafile){
		fptr = mosquitto__fopen(cafile, "rt");
		if(fptr){
			fclose(fptr);
		}else{
			return MOSQ_ERR_INVAL;
		}
		mosq->tls_cafile = mosquitto__strdup(cafile);

		if(!mosq->tls_cafile){
			return MOSQ_ERR_NOMEM;
		}
	}

	mosquitto__free(mosq->tls_capath);
	mosq->tls_capath = NULL;
	if(capath){
		mosq->tls_capath = mosquitto__strdup(capath);
		if(!mosq->tls_capath){
			return MOSQ_ERR_NOMEM;
		}
	}

	mosquitto__free(mosq->tls_certfile);
	mosq->tls_certfile = NULL;
	if(certfile){
		fptr = mosquitto__fopen(certfile, "rt");
		if(fptr){
			fclose(fptr);
		}else{
			mosquitto__free(mosq->tls_cafile);
			mosq->tls_cafile = NULL;

			mosquitto__free(mosq->tls_capath);
			mosq->tls_capath = NULL;
			return MOSQ_ERR_INVAL;
		}
		mosq->tls_certfile = mosquitto__strdup(certfile);
		if(!mosq->tls_certfile){
			return MOSQ_ERR_NOMEM;
		}
	}

	mosquitto__free(mosq->tls_keyfile);
	mosq->tls_keyfile = NULL;
	if(keyfile){
		fptr = mosquitto__fopen(keyfile, "rt");
		if(fptr){
			fclose(fptr);
		}else{
			mosquitto__free(mosq->tls_cafile);
			mosq->tls_cafile = NULL;

			mosquitto__free(mosq->tls_capath);
			mosq->tls_capath = NULL;

			mosquitto__free(mosq->tls_certfile);
			mosq->tls_certfile = NULL;
			return MOSQ_ERR_INVAL;
		}
		mosq->tls_keyfile = mosquitto__strdup(keyfile);
		if(!mosq->tls_keyfile){
			return MOSQ_ERR_NOMEM;
		}
	}

	mosq->tls_pw_callback = pw_callback;


	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;

#endif
}

int mosquitto_tls_opts_set(struct mosquitto *mosq, int cert_reqs, const char *tls_version, const char *ciphers)
{
#ifdef WITH_TLS
	if(!mosq) return MOSQ_ERR_INVAL;

	mosq->tls_cert_reqs = cert_reqs;
	if(tls_version){
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
		if(!strcasecmp(tls_version, "tlsv1.2")
				|| !strcasecmp(tls_version, "tlsv1.1")
				|| !strcasecmp(tls_version, "tlsv1")){

			mosq->tls_version = mosquitto__strdup(tls_version);
			if(!mosq->tls_version) return MOSQ_ERR_NOMEM;
		}else{
			return MOSQ_ERR_INVAL;
		}
#else
		if(!strcasecmp(tls_version, "tlsv1")){
			mosq->tls_version = mosquitto__strdup(tls_version);
			if(!mosq->tls_version) return MOSQ_ERR_NOMEM;
		}else{
			return MOSQ_ERR_INVAL;
		}
#endif
	}else{
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
		mosq->tls_version = mosquitto__strdup("tlsv1.2");
#else
		mosq->tls_version = mosquitto__strdup("tlsv1");
#endif
		if(!mosq->tls_version) return MOSQ_ERR_NOMEM;
	}
	if(ciphers){
		mosq->tls_ciphers = mosquitto__strdup(ciphers);
		if(!mosq->tls_ciphers) return MOSQ_ERR_NOMEM;
	}else{
		mosq->tls_ciphers = NULL;
	}


	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;

#endif
}


int mosquitto_tls_server_name_set(struct mosquitto *mosq, const char *server_name)
{
#ifdef WITH_TLS
	if(!mosq) return MOSQ_ERR_INVAL;
	if(mosq->tls_server_name) mosquitto__free(mosq->tls_server_name);
	mosq->tls_server_name = mosquitto__strdup(server_name);
	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}


int mosquitto_tls_insecure_set(struct mosquitto *mosq, bool value)
{
#ifdef WITH_TLS
	if(!mosq) return MOSQ_ERR_INVAL;
	mosq->tls_insecure = value;
	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}


int mosquitto_tls_psk_set(struct mosquitto *mosq, const char *psk, const char *identity, const char *ciphers)
{
#ifdef REAL_WITH_TLS_PSK
	if(!mosq || !psk || !identity) return MOSQ_ERR_INVAL;

	/* Check for hex only digits */
	if(strspn(psk, "0123456789abcdefABCDEF") < strlen(psk)){
		return MOSQ_ERR_INVAL;
	}
	mosq->tls_psk = mosquitto__strdup(psk);
	if(!mosq->tls_psk) return MOSQ_ERR_NOMEM;

	mosq->tls_psk_identity = mosquitto__strdup(identity);
	if(!mosq->tls_psk_identity){
		mosquitto__free(mosq->tls_psk);
		return MOSQ_ERR_NOMEM;
	}
	if(ciphers){
		mosq->tls_ciphers = mosquitto__strdup(ciphers);
		if(!mosq->tls_ciphers) return MOSQ_ERR_NOMEM;
	}else{
		mosq->tls_ciphers = NULL;
	}

	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}


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
#ifdef WITH_TLS
				if(mosq->want_connect){
					rc = net__socket_connect_tls(mosq);
					if(rc) return rc;
				}else
#endif
				{
					do{
						rc = mosquitto_loop_read(mosq, max_packets);
						if(rc || mosq->sock == INVALID_SOCKET){
							return rc;
						}
					}while(SSL_DATA_PENDING(mosq));
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
				FD_SET(mosq->sock, &writefds);
			}
			if(FD_ISSET(mosq->sock, &writefds)){
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
				sleep(reconnect_delay);
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
			rc = 1;
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

bool mosquitto_want_write(struct mosquitto *mosq)
{
	if(mosq->out_packet || mosq->current_out_packet){
		return true;
#ifdef WITH_TLS
	}else if(mosq->ssl && mosq->want_write){
		return true;
#endif
	}else{
		return false;
	}
}

int mosquitto_opts_set(struct mosquitto *mosq, enum mosq_opt_t option, void *value)
{
	int ival;

	if(!mosq || !value) return MOSQ_ERR_INVAL;

	switch(option){
		case MOSQ_OPT_PROTOCOL_VERSION:
			ival = *((int *)value);
			if(ival == MQTT_PROTOCOL_V31){
				mosq->protocol = mosq_p_mqtt31;
			}else if(ival == MQTT_PROTOCOL_V311){
				mosq->protocol = mosq_p_mqtt311;
			}else{
				return MOSQ_ERR_INVAL;
			}
			break;
		default:
			return MOSQ_ERR_INVAL;
	}
	return MOSQ_ERR_SUCCESS;
}


void mosquitto_connect_callback_set(struct mosquitto *mosq, void (*on_connect)(struct mosquitto *, void *, int))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_connect = on_connect;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_disconnect_callback_set(struct mosquitto *mosq, void (*on_disconnect)(struct mosquitto *, void *, int))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_disconnect = on_disconnect;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_publish_callback_set(struct mosquitto *mosq, void (*on_publish)(struct mosquitto *, void *, int))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_publish = on_publish;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_message_callback_set(struct mosquitto *mosq, void (*on_message)(struct mosquitto *, void *, const struct mosquitto_message *))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_message = on_message;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_subscribe_callback_set(struct mosquitto *mosq, void (*on_subscribe)(struct mosquitto *, void *, int, int, const int *))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_subscribe = on_subscribe;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_unsubscribe_callback_set(struct mosquitto *mosq, void (*on_unsubscribe)(struct mosquitto *, void *, int))
{
	pthread_mutex_lock(&mosq->callback_mutex);
	mosq->on_unsubscribe = on_unsubscribe;
	pthread_mutex_unlock(&mosq->callback_mutex);
}

void mosquitto_log_callback_set(struct mosquitto *mosq, void (*on_log)(struct mosquitto *, void *, int, const char *))
{
	pthread_mutex_lock(&mosq->log_callback_mutex);
	mosq->on_log = on_log;
	pthread_mutex_unlock(&mosq->log_callback_mutex);
}

void mosquitto_user_data_set(struct mosquitto *mosq, void *userdata)
{
	if(mosq){
		mosq->userdata = userdata;
	}
}

const char *mosquitto_strerror(int mosq_errno)
{
	switch(mosq_errno){
		case MOSQ_ERR_CONN_PENDING:
			return "Connection pending.";
		case MOSQ_ERR_SUCCESS:
			return "No error.";
		case MOSQ_ERR_NOMEM:
			return "Out of memory.";
		case MOSQ_ERR_PROTOCOL:
			return "A network protocol error occurred when communicating with the broker.";
		case MOSQ_ERR_INVAL:
			return "Invalid function arguments provided.";
		case MOSQ_ERR_NO_CONN:
			return "The client is not currently connected.";
		case MOSQ_ERR_CONN_REFUSED:
			return "The connection was refused.";
		case MOSQ_ERR_NOT_FOUND:
			return "Message not found (internal error).";
		case MOSQ_ERR_CONN_LOST:
			return "The connection was lost.";
		case MOSQ_ERR_TLS:
			return "A TLS error occurred.";
		case MOSQ_ERR_PAYLOAD_SIZE:
			return "Payload too large.";
		case MOSQ_ERR_NOT_SUPPORTED:
			return "This feature is not supported.";
		case MOSQ_ERR_AUTH:
			return "Authorisation failed.";
		case MOSQ_ERR_ACL_DENIED:
			return "Access denied by ACL.";
		case MOSQ_ERR_UNKNOWN:
			return "Unknown error.";
		case MOSQ_ERR_ERRNO:
			return strerror(errno);
		case MOSQ_ERR_EAI:
			return "Lookup error.";
		case MOSQ_ERR_PROXY:
			return "Proxy error.";
		case MOSQ_ERR_MALFORMED_UTF8:
			return "Malformed UTF-8";
		default:
			return "Unknown error.";
	}
}

const char *mosquitto_connack_string(int connack_code)
{
	switch(connack_code){
		case 0:
			return "Connection Accepted.";
		case 1:
			return "Connection Refused: unacceptable protocol version.";
		case 2:
			return "Connection Refused: identifier rejected.";
		case 3:
			return "Connection Refused: broker unavailable.";
		case 4:
			return "Connection Refused: bad user name or password.";
		case 5:
			return "Connection Refused: not authorised.";
		default:
			return "Connection Refused: unknown reason.";
	}
}

int mosquitto_sub_topic_tokenise(const char *subtopic, char ***topics, int *count)
{
	int len;
	int hier_count = 1;
	int start, stop;
	int hier;
	int tlen;
	int i, j;

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
	stop = 0;
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

	*count = hier_count;

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

