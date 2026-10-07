/*
Copyright (c) 2010-2021 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

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

#include <pthread_compat.h>

#ifdef WITH_SRV
#  include <ares.h>
#endif

#ifdef WIN32
#   if _MSC_VER < 1600
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#   else
#       include <stdint.h>
#   endif
#else
#   include <stdint.h>
#endif

#include "mosquitto.h"
#include "mosquitto/libcommon_time.h"
#ifdef WITH_BROKER
#  ifdef __linux__
#    include <netdb.h>
#  endif
#  include "uthash.h"
struct mosquitto__client_msg;
#endif

#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_LWS
#  include <libwebsockets.h>
#  define WS_PACKET_OFFSET LWS_PRE
#else
#  define WS_PACKET_OFFSET 16
#endif

#ifdef WIN32
typedef SOCKET mosq_sock_t;
#else
typedef int mosq_sock_t;
#endif

#ifdef WIN32
#  define WINDOWS_SET_ERRNO() \
		do{ \
			errno = WSAGetLastError(); \
		}while(0)
#  define WINDOWS_SET_ERRNO_RW() \
		if(errno != EAGAIN){ \
			errno = WSAGetLastError(); \
		}
#else
#  define WINDOWS_SET_ERRNO()
#  define WINDOWS_SET_ERRNO_RW()
#endif

#define SAFE_PRINT(A) (A)?(A):"null"
#define SAFE_FREE(A) do{ free(A); (A) = NULL;}while(0)

#define MSG_EXPIRY_INFINITE UINT32_MAX

enum mosquitto_msg_direction {
	mosq_md_in = 0,
	mosq_md_out = 1,
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
	mosq_ms_queued = 11,

	mosq_ms_any = 255,
	/* max value allowed is 255 */
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
	mosq_cs_delayed_auth = 22, /* Client is awaiting an authentication result from a plugin */
};

enum mosquitto__protocol {
	mosq_p_invalid = 0,
	mosq_p_mqtts = 1,
	mosq_p_mqtt31 = 3,
	mosq_p_mqtt311 = 4,
	mosq_p_mqtt5 = 5,
};

enum mosquitto__threaded_state {
	mosq_ts_none,       /* No threads in use */
	mosq_ts_self,       /* Threads started by libmosquitto */
	mosq_ts_external,   /* Threads started by external code */
};

enum mosquitto__transport {
	mosq_t_invalid = 0,
	mosq_t_tcp = 1,
	mosq_t_ws = 2,
	mosq_t_sctp = 3,
	mosq_t_http = 4, /* not valid for MQTT, just as a ws precursor */
	mosq_t_proxy_v2 = 5, /* not valid for MQTT, just as a PROXY protocol v2 precursor */
	mosq_t_proxy_v1 = 6, /* not valid for MQTT, just as a PROXY protocol v1 precursor */
};

/* Alias direction - local <-> remote */
#define ALIAS_DIR_L2R 1
#define ALIAS_DIR_R2L 2

struct mosquitto__alias {
	char *topic;
	uint16_t alias;
};

struct session_expiry_list {
	struct mosquitto *context;
	struct session_expiry_list *prev;
	struct session_expiry_list *next;
};

struct mosquitto__packet {
	struct mosquitto__packet *next;
	uint32_t remaining_length;
	uint32_t packet_length;
	uint32_t to_process;
	uint32_t pos;
	uint16_t mid;
	uint8_t command;
	int8_t remaining_count;
	uint8_t payload[];
};

struct mosquitto__packet_in {
	uint8_t *payload;
	uint32_t remaining_mult;
	uint32_t remaining_length;
	uint32_t packet_length;
	uint32_t to_process;
	uint32_t pos;
	uint16_t packet_buffer_to_process;
	uint16_t packet_buffer_pos;
	uint16_t packet_buffer_size;
	uint8_t command;
	uint8_t *packet_buffer;
	int8_t remaining_count;
};

struct mosquitto_message_all {
	struct mosquitto_message_all *next;
	struct mosquitto_message_all *prev;
	mosquitto_property *properties;
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

struct mosquitto_msg_data {
#ifdef WITH_BROKER
	struct mosquitto__client_msg *inflight;
	struct mosquitto__client_msg *queued;
	long inflight_bytes;
	long inflight_bytes12;
	int inflight_count;
	int inflight_count12;
	long queued_bytes;
	long queued_bytes12;
	int queued_count;
	int queued_count12;
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


#define WS_CONTINUATION 0x00
#define WS_TEXT 0x01
#define WS_BINARY 0x02
#define WS_CLOSE 0x08
#define WS_PING 0x09
#define WS_PONG 0x0A

#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_BUILTIN
struct ws_data {
	struct mosquitto__packet *out_packet;
	char *http_path;
	char *accept_key;
	uint64_t payloadlen;
	ssize_t pos;
	int http_header_size;
	uint8_t maskingkey[4];
	uint8_t disconnect_reason;
	uint8_t opcode;
	uint8_t mask;
	uint8_t mask_bytes;
	uint8_t payloadlen_bytes;
	bool is_client;
};
#endif

struct proxy_data {
	uint8_t *buf;
	char *cipher;
	char *tls_version;
	uint16_t len;
	uint16_t pos;
	int8_t cmd;
	uint8_t fam;
	bool have_tls;
};

struct client_stats {
	uint64_t messages_received;
	uint64_t messages_sent;
	uint64_t messages_dropped;
};

struct mosquitto {
#if defined(WITH_BROKER) && (defined(WITH_EPOLL) || defined(WITH_KQUEUE))
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
	uint64_t last_cmsg_id;
#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_BUILTIN
	struct ws_data wsd;
#endif
	enum mosquitto__protocol protocol;
	char *address;
	char *id;
	char *username;
	char *password;
	unsigned id_hashv;
	uint16_t keepalive;
	uint16_t last_mid;
	uint16_t password_len;
	enum mosquitto_client_state state;
	uint8_t transport;
	time_t last_msg_in;
	time_t next_msg_out;
	time_t ping_t;
	struct mosquitto__packet_in in_packet;
	struct mosquitto__packet *out_packet;
	struct mosquitto_message_all *will;
	struct mosquitto__alias *aliases_l2r;
	struct mosquitto__alias *aliases_r2l;
	struct will_delay_list *will_delay_entry;
	uint16_t alias_count_l2r;
	uint16_t alias_count_r2l;
	uint16_t alias_max_l2r;
	uint32_t will_delay_interval;
	int out_packet_count;
	int64_t out_packet_bytes;
	time_t will_delay_time;
#ifdef WITH_TLS
	SSL *ssl;
	SSL_CTX *ssl_ctx;
#ifndef WITH_BROKER
	SSL_CTX *user_ssl_ctx;
#endif
	char *tls_cafile;
	char *tls_capath;
	char *tls_certfile;
	char *tls_keyfile;
	int (*tls_pw_callback)(char *buf, int size, int rwflag, void *userdata);
	char *tls_version;
	char *tls_ciphers;
	char *tls_13_ciphers;
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
	bool run;
#if defined(WITH_THREADING) && !defined(WITH_BROKER)
	pthread_mutex_t callback_mutex;
	pthread_mutex_t log_callback_mutex;
	pthread_mutex_t msgtime_mutex;
	pthread_mutex_t out_packet_mutex;
	pthread_mutex_t state_mutex;
	pthread_mutex_t mid_mutex;
	pthread_t thread_id;
#endif
	bool clean_start;
	time_t session_expiry_time;
	uint32_t session_expiry_interval;
#ifdef WITH_BROKER
	bool in_by_id;
	bool is_dropping;
	bool is_bridge;
	bool is_persisted;
	struct mosquitto__bridge *bridge;
	struct mosquitto_msg_data msgs_in;
	struct mosquitto_msg_data msgs_out;
	struct mosquitto__acl_user *acl_list;
	struct mosquitto__listener *listener;
	struct mosquitto__packet *out_packet_last;
	struct mosquitto__subleaf **subs;
	char *auth_method;
	int subs_capacity; /* allocated size of the subs instance */
	int subs_count; /* number of currently active subscriptions */
#  ifndef WITH_EPOLL
	int pollfd_index;
#  endif
#  ifdef WITH_WEBSOCKETS
#    if WITH_WEBSOCKETS == WS_IS_LWS
	struct lws *wsi;
#    endif
#  endif
	bool assigned_id;
#else
#  ifdef WITH_SOCKS
	char *socks5_host;
	uint16_t socks5_port;
	char *socks5_username;
	char *socks5_password;
#  endif
	void *userdata;
	struct mosquitto_msg_data msgs_in;
	struct mosquitto_msg_data msgs_out;
	LIBMOSQ_CB_pre_connect on_pre_connect;
	LIBMOSQ_CB_connect on_connect;
	LIBMOSQ_CB_connect_with_flags on_connect_with_flags;
	LIBMOSQ_CB_connect_v5 on_connect_v5;
	LIBMOSQ_CB_disconnect on_disconnect;
	LIBMOSQ_CB_disconnect_v5 on_disconnect_v5;
	LIBMOSQ_CB_publish on_publish;
	LIBMOSQ_CB_publish_v5 on_publish_v5;
	LIBMOSQ_CB_message on_message;
	LIBMOSQ_CB_message_v5 on_message_v5;
	LIBMOSQ_CB_subscribe on_subscribe;
	LIBMOSQ_CB_subscribe_v5 on_subscribe_v5;
	LIBMOSQ_CB_unsubscribe on_unsubscribe;
	LIBMOSQ_CB_unsubscribe_v5 on_unsubscribe_v5;
	LIBMOSQ_CB_unsubscribe2_v5 on_unsubscribe2_v5;
	LIBMOSQ_CB_ext_auth on_ext_auth;
	LIBMOSQ_CB_log on_log;
	/*void (*on_error)();*/
	char *host;
	char *bind_address;
	unsigned int reconnects;
	unsigned int reconnect_delay;
	unsigned int reconnect_delay_max;
	int callback_depth;
	uint16_t port;
	bool disable_socketpair;
	bool reconnect_exponential_backoff;
	bool request_disconnect;
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
#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_BUILTIN
	char *http_request;
#endif

#ifdef WITH_BROKER
	UT_hash_handle hh_id;
	UT_hash_handle hh_sock;
	struct mosquitto *for_free_next;
	struct session_expiry_list *expiry_list_item;
	uint16_t remote_port;
#  ifndef WITH_OLD_KEEPALIVE
	struct mosquitto *keepalive_next;
	struct mosquitto *keepalive_prev;
	time_t keepalive_add_time;
#  endif
	struct client_stats stats;
#endif
#ifdef WITH_EPOLL
	uint32_t events;
#elif defined(WITH_KQUEUE)
	short events;
#else
	uint32_t events;
#endif
	struct proxy_data proxy;
};

#define STREMPTY(str) (str[0] == '\0')

void do_client_disconnect(struct mosquitto *mosq, int reason_code, const mosquitto_property *properties);

#endif
