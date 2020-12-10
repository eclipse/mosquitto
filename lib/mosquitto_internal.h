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
   Tatsuzo Osawa - Add epoll.
*/

#ifndef MOSQUITTO_INTERNAL_H
#define MOSQUITTO_INTERNAL_H

#include "config.h"

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
	mosq_cs_active = 3,
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
	mosq_cs_duplicate = 17, /* client that has been taken over by another with the same id */
	mosq_cs_disconnect_with_will = 18,
	mosq_cs_disused = 19, /* client that has been added to the disused list to be freed */
	mosq_cs_authenticating = 20, /* Client has sent CONNECT but is still undergoing extended authentication */
	mosq_cs_reauthenticating = 21, /* Client is undergoing reauthentication and shouldn't do anything else until complete */
};

enum mosquitto__protocol {
	mosq_p_invalid = 0,
	mosq_p_mqtt31 = 1,
	mosq_p_mqtt311 = 2,
	mosq_p_mqtts = 3,
	mosq_p_mqtt5 = 5,
};

enum mosquitto__threaded_state {
	mosq_ts_none,		/* No threads in use */
	mosq_ts_self,		/* Threads started by libmosquitto */
	mosq_ts_external	/* Threads started by external code */
};

enum mosquitto__transport {
	mosq_t_invalid = 0,
	mosq_t_tcp = 1,
	mosq_t_ws = 2,
	mosq_t_sctp = 3
};


struct mosquitto__alias{
	char *topic;
	uint16_t alias;
};

struct session_expiry_list {
	struct mosquitto *context;
	struct session_expiry_list *prev;
	struct session_expiry_list *next;
};

struct mosquitto__packet{
	uint8_t *payload;
	struct mosquitto__packet *next;
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
	struct mosquitto_message_all *prev;
	mosquitto_property *properties;
	time_t timestamp;
	enum mosquitto_msg_state state;
	bool dup;
	struct mosquitto_message msg;
	uint32_t expiry_interval;
};

#ifdef WITH_TLS
enum mosquitto__keyform {
	mosq_k_pem = 0,
	mosq_k_engine = 1,
};
#endif

struct will_delay_list {
	struct mosquitto *context;
	struct will_delay_list *prev;
	struct will_delay_list *next;
};

struct mosquitto_msg_data{
#ifdef WITH_BROKER
	struct mosquitto_client_msg *inflight;
	struct mosquitto_client_msg *queued;
	unsigned long msg_bytes;
	unsigned long msg_bytes12;
	int msg_count;
	int msg_count12;
#else
	struct mosquitto_message_all *inflight;
	int queue_len;
#  ifdef WITH_THREADING
	pthread_mutex_t mutex;
#  endif
#endif
	int inflight_quota;
	uint16_t inflight_maximum;
};


struct mosquitto {
#if defined(WITH_BROKER) && defined(WITH_EPOLL)
	/* This *must* be the first element in the struct. */
	int ident;
#endif
	mosq_sock_t sock;
#ifndef WITH_BROKER
	mosq_sock_t sockpairR, sockpairW;
#endif
	uint32_t maximum_packet_size;
#if defined(__GLIBC__) && defined(WITH_ADNS)
	struct gaicb *adns; /* For getaddrinfo_a */
#endif
	enum mosquitto__protocol protocol;
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
	struct mosquitto__packet in_packet;
	struct mosquitto__packet *current_out_packet;
	struct mosquitto__packet *out_packet;
	struct mosquitto_message_all *will;
	struct mosquitto__alias *aliases;
	struct will_delay_list *will_delay_entry;
	int alias_count;
	uint32_t will_delay_interval;
	time_t will_delay_time;
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
	char *tls_engine;
	char *tls_engine_kpass_sha1;
	char *tls_alpn;
	int tls_cert_reqs;
	bool tls_insecure;
	bool ssl_ctx_defaults;
	bool tls_ocsp_required;
	bool tls_use_os_certs;
	enum mosquitto__keyform tls_keyform;
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
	pthread_mutex_t mid_mutex;
	pthread_t thread_id;
#endif
	bool clean_start;
	time_t session_expiry_time;
	uint32_t session_expiry_interval;
#ifdef WITH_BROKER
	bool removed_from_by_id; /* True if removed from by_id hash */
	bool is_dropping;
	bool is_bridge;
	struct mosquitto__bridge *bridge;
	struct mosquitto_msg_data msgs_in;
	struct mosquitto_msg_data msgs_out;
	struct mosquitto__acl_user *acl_list;
	struct mosquitto__listener *listener;
	struct mosquitto__packet *out_packet_last;
	struct mosquitto__subhier **subs;
	struct mosquitto__subshared_ref **shared_subs;
	char *auth_method;
	int sub_count;
	int shared_sub_count;
#  ifndef WITH_EPOLL
	int pollfd_index;
#  endif
#  ifdef WITH_WEBSOCKETS
	struct lws *wsi;
#  endif
	bool ws_want_write;
	bool assigned_id;
#else
#  ifdef WITH_SOCKS
	char *socks5_host;
	uint16_t socks5_port;
	char *socks5_username;
	char *socks5_password;
#  endif
	void *userdata;
	bool in_callback;
	struct mosquitto_msg_data msgs_in;
	struct mosquitto_msg_data msgs_out;
	void (*on_connect)(struct mosquitto *, void *userdata, int rc);
	void (*on_connect_with_flags)(struct mosquitto *, void *userdata, int rc, int flags);
	void (*on_connect_v5)(struct mosquitto *, void *userdata, int rc, int flags, const mosquitto_property *props);
	void (*on_disconnect)(struct mosquitto *, void *userdata, int rc);
	void (*on_disconnect_v5)(struct mosquitto *, void *userdata, int rc, const mosquitto_property *props);
	void (*on_publish)(struct mosquitto *, void *userdata, int mid);
	void (*on_publish_v5)(struct mosquitto *, void *userdata, int mid, int reason_code, const mosquitto_property *props);
	void (*on_message)(struct mosquitto *, void *userdata, const struct mosquitto_message *message);
	void (*on_message_v5)(struct mosquitto *, void *userdata, const struct mosquitto_message *message, const mosquitto_property *props);
	void (*on_subscribe)(struct mosquitto *, void *userdata, int mid, int qos_count, const int *granted_qos);
	void (*on_subscribe_v5)(struct mosquitto *, void *userdata, int mid, int qos_count, const int *granted_qos, const mosquitto_property *props);
	void (*on_unsubscribe)(struct mosquitto *, void *userdata, int mid);
	void (*on_unsubscribe_v5)(struct mosquitto *, void *userdata, int mid, const mosquitto_property *props);
	void (*on_log)(struct mosquitto *, void *userdata, int level, const char *str);
	/*void (*on_error)();*/
	char *host;
	uint16_t port;
	char *bind_address;
	unsigned int reconnects;
	unsigned int reconnect_delay;
	unsigned int reconnect_delay_max;
	bool reconnect_exponential_backoff;
	char threaded;
	struct mosquitto__packet *out_packet_last;
	mosquitto_property *connect_properties;
#  ifdef WITH_SRV
	ares_channel achan;
#  endif
#endif
	uint8_t max_qos;
	uint8_t retain_available;
	bool tcp_nodelay;

#ifdef WITH_BROKER
	UT_hash_handle hh_id;
	UT_hash_handle hh_sock;
	struct mosquitto *for_free_next;
	struct session_expiry_list *expiry_list_item;
	uint16_t remote_port;
#endif
#ifdef WITH_EPOLL
	uint32_t events;
#endif
};

#define STREMPTY(str) (str[0] == '\0')

void do_client_disconnect(struct mosquitto *mosq, int reason_code, const mosquitto_property *properties);

#endif

