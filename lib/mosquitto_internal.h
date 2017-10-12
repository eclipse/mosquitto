/*
Copyright (c) 2010-2014 Roger Light <roger@atchoo.org>

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

#ifndef _MOSQUITTO_INTERNAL_H_
#define _MOSQUITTO_INTERNAL_H_

#include <config.h>

#ifdef WIN32
#  include <winsock2.h>
#endif

#ifdef WITH_TLS
#  include <openssl/ssl.h>
#else
#  include <time.h>
#endif
#include <stdlib.h>

#if defined(WITH_THREADING) && !defined(WITH_BROKER)
#  include <pthread.h>
#else
#  include <dummypthread.h>
#endif

#ifdef WITH_SRV
#  include <ares.h>
#endif

#ifdef WIN32
#	if _MSC_VER < 1600
		typedef unsigned char uint8_t;
		typedef unsigned short uint16_t;
		typedef unsigned int uint32_t;
		typedef unsigned long long uint64_t;
#	else
#		include <stdint.h>
#	endif
#else
#	include <stdint.h>
#endif

#include "mosquitto.h"
#include "time_mosq.h"
#ifdef WITH_BROKER
#  ifdef __linux__
#    include <netdb.h>
#  endif
#  include "uthash.h"
struct mosquitto_client_msg;
#endif

#ifdef WIN32
typedef SOCKET mosq_sock_t;
#else
typedef int mosq_sock_t;
#endif

enum mosquitto_msg_direction {
	mosq_md_in = 0,
	mosq_md_out = 1
};

enum mosquitto_msg_state {
	mosq_ms_invalid = 0,
	mosq_ms_publish_qos0 = 1,
	mosq_ms_publish_qos1 = 2,
	mosq_ms_wait_for_puback = 3,
	mosq_ms_publish_qos2 = 4,
	mosq_ms_wait_for_pubrec = 5,
	mosq_ms_resend_pubrel = 6,
	mosq_ms_wait_for_pubrel = 7,
	mosq_ms_resend_pubcomp = 8,
	mosq_ms_wait_for_pubcomp = 9,
	mosq_ms_send_pubrec = 10,
	mosq_ms_queued = 11
};

enum mosquitto_client_state {
	mosq_cs_new = 0,
	mosq_cs_connected = 1,
	mosq_cs_disconnecting = 2,
	mosq_cs_connect_async = 3,
	mosq_cs_connect_pending = 4,
	mosq_cs_connect_srv = 5,
	mosq_cs_disconnect_ws = 6,
	mosq_cs_disconnected = 7,
	mosq_cs_socks5_new = 8,
	mosq_cs_socks5_start = 9,
	mosq_cs_socks5_request = 10,
	mosq_cs_socks5_reply = 11,
	mosq_cs_socks5_auth_ok = 12,
	mosq_cs_socks5_userpass_reply = 13,
	mosq_cs_socks5_send_userpass = 14,
	mosq_cs_expiring = 15,
};

enum _mosquitto_protocol {
	mosq_p_invalid = 0,
	mosq_p_mqtt31 = 1,
	mosq_p_mqtt311 = 2,
	mosq_p_mqtts = 3
};

enum mosquitto__threaded_state {
	mosq_ts_none,		/* No threads in use */
	mosq_ts_self,		/* Threads started by libmosquitto */
	mosq_ts_external	/* Threads started by external code */
};

enum _mosquitto_transport {
	mosq_t_invalid = 0,
	mosq_t_tcp = 1,
	mosq_t_ws = 2,
	mosq_t_sctp = 3
};

struct _mosquitto_packet{
	uint8_t *payload;
	struct _mosquitto_packet *next;
	uint32_t remaining_mult;
	uint32_t remaining_length;
	uint32_t packet_length;
	uint32_t to_process;
	uint32_t pos;
	uint16_t mid;
	uint8_t command;
	int8_t remaining_count;
};

struct mosquitto_message_all{
	struct mosquitto_message_all *next;
	time_t timestamp;
	//enum mosquitto_msg_direction direction;
	enum mosquitto_msg_state state;
	bool dup;
	struct mosquitto_message msg;
};

struct mosquitto {
	mosq_sock_t sock;
#ifndef WITH_BROKER
	mosq_sock_t sockpairR, sockpairW;
#endif
#if defined(__GLIBC__) && defined(WITH_ADNS)
	struct gaicb *adns; /* For getaddrinfo_a */
#endif
	enum _mosquitto_protocol protocol;
	char *address;
	char *id;
	char *username;
	char *password;
	uint16_t keepalive;
	uint16_t last_mid;
	enum mosquitto_client_state state;
	time_t last_msg_in;
	time_t next_msg_out;
	time_t ping_t;
	struct _mosquitto_packet in_packet;
	struct _mosquitto_packet *current_out_packet;
	struct _mosquitto_packet *out_packet;
	struct mosquitto_message *will;
#ifdef WITH_TLS
	SSL *ssl;
	SSL_CTX *ssl_ctx;
	char *tls_cafile;
	char *tls_capath;
	char *tls_certfile;
	char *tls_keyfile;
	int (*tls_pw_callback)(char *buf, int size, int rwflag, void *userdata);
	char *tls_version;
	char *tls_ciphers;
	char *tls_psk;
	char *tls_psk_identity;
	int tls_cert_reqs;
	bool tls_insecure;
#endif
	bool want_write;
	bool want_connect;
#if defined(WITH_THREADING) && !defined(WITH_BROKER)
	pthread_mutex_t callback_mutex;
	pthread_mutex_t log_callback_mutex;
	pthread_mutex_t msgtime_mutex;
	pthread_mutex_t out_packet_mutex;
	pthread_mutex_t current_out_packet_mutex;
	pthread_mutex_t state_mutex;
	pthread_mutex_t in_message_mutex;
	pthread_mutex_t out_message_mutex;
	pthread_mutex_t mid_mutex;
	pthread_t thread_id;
#endif
	bool clean_session;
#ifdef WITH_BROKER
	bool is_dropping;
	bool is_bridge;
	struct _mqtt3_bridge *bridge;
	struct mosquitto_client_msg *msgs;
	struct mosquitto_client_msg *last_msg;
	int msg_count;
	int msg_count12;
	struct _mosquitto_acl_user *acl_list;
	struct _mqtt3_listener *listener;
	time_t disconnect_t;
	struct _mosquitto_packet *out_packet_last;
	struct _mosquitto_subhier **subs;
	int sub_count;
	int pollfd_index;
#  ifdef WITH_WEBSOCKETS
#    if defined(LWS_LIBRARY_VERSION_NUMBER)
	struct lws *wsi;
#    else
	struct libwebsocket_context *ws_context;
	struct libwebsocket *wsi;
#    endif
#  endif
	bool ws_want_write;
#else
#  ifdef WITH_SOCKS
	char *socks5_host;
	int socks5_port;
	char *socks5_username;
	char *socks5_password;
#  endif
	void *userdata;
	bool in_callback;
	unsigned int message_retry;
	time_t last_retry_check;
	struct mosquitto_message_all *in_messages;
	struct mosquitto_message_all *in_messages_last;
	struct mosquitto_message_all *out_messages;
	struct mosquitto_message_all *out_messages_last;
	void (*on_connect)(struct mosquitto *, void *userdata, int rc);
	void (*on_disconnect)(struct mosquitto *, void *userdata, int rc);
	void (*on_publish)(struct mosquitto *, void *userdata, int mid);
	void (*on_message)(struct mosquitto *, void *userdata, const struct mosquitto_message *message);
	void (*on_subscribe)(struct mosquitto *, void *userdata, int mid, int qos_count, const int *granted_qos);
	void (*on_unsubscribe)(struct mosquitto *, void *userdata, int mid);
	void (*on_log)(struct mosquitto *, void *userdata, int level, const char *str);
	//void (*on_error)();
	char *host;
	int port;
	int in_queue_len;
	int out_queue_len;
	char *bind_address;
	unsigned int reconnect_delay;
	unsigned int reconnect_delay_max;
	bool reconnect_exponential_backoff;
	char threaded;
	struct _mosquitto_packet *out_packet_last;
	int inflight_messages;
	int max_inflight_messages;
#  ifdef WITH_SRV
	ares_channel achan;
#  endif
#endif

#ifdef WITH_BROKER
	UT_hash_handle hh_id;
	UT_hash_handle hh_sock;
	struct mosquitto *for_free_next;
#endif
};

#define STREMPTY(str) (str[0] == '\0')

#endif
