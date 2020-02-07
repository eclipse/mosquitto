/*
Copyright (c) 2009-2019 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
   Tatsuzo Osawa - Add epoll.
*/

#ifndef MOSQUITTO_BROKER_INTERNAL_H
#define MOSQUITTO_BROKER_INTERNAL_H

#include "config.h"
#include <stdio.h>

#ifdef WITH_WEBSOCKETS
#  include <libwebsockets.h>

#  if defined(LWS_LIBRARY_VERSION_NUMBER)
#    define libwebsocket_callback_on_writable(A, B) lws_callback_on_writable((B))
#    define libwebsocket_service(A, B) lws_service((A), (B))
#    define libwebsocket_create_context(A) lws_create_context((A))
#    define libwebsocket_context_destroy(A) lws_context_destroy((A))
#    define libwebsocket_write(A, B, C, D) lws_write((A), (B), (C), (D))
#    define libwebsocket_get_socket_fd(A) lws_get_socket_fd((A))
#    define libwebsockets_return_http_status(A, B, C, D) lws_return_http_status((B), (C), (D))
#    define libwebsockets_get_protocol(A) lws_get_protocol((A))
#    define libwebsocket_context lws_context
#    define libwebsocket_protocols lws_protocols
#    define libwebsocket_callback_reasons lws_callback_reasons
#    define libwebsocket lws
#  else
#    define lws_pollfd pollfd
#    define lws_service_fd(A, B) libwebsocket_service_fd((A), (B))
#    define lws_pollargs libwebsocket_pollargs
#  endif
#endif

#include "mosquitto_internal.h"
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "tls_mosq.h"
#include "uthash.h"

#define uhpa_malloc(size) mosquitto__malloc(size)
#define uhpa_free(ptr) mosquitto__free(ptr)
#include "uhpa.h"

#ifndef __GNUC__
#define __attribute__(attrib)
#endif

/* Log destinations */
#define MQTT3_LOG_NONE 0x00
#define MQTT3_LOG_SYSLOG 0x01
#define MQTT3_LOG_FILE 0x02
#define MQTT3_LOG_STDOUT 0x04
#define MQTT3_LOG_STDERR 0x08
#define MQTT3_LOG_TOPIC 0x10
#define MQTT3_LOG_ALL 0xFF

#define WEBSOCKET_CLIENT -2


#define TOPIC_HIERARCHY_LIMIT 200

/* ========================================
 * UHPA data types
 * ======================================== */

/* See uhpa.h
 *
 * The idea here is that there is potentially a lot of wasted space (and time)
 * in malloc calls for frequent, small heap allocations. This can happen if
 * small payloads are used by clients or if individual topic elements are
 * small.
 *
 * In both cases, a struct is used that includes a void* or char* pointer to
 * point to the dynamically allocated memory used. To allocate and store a
 * single byte needs the size of the pointer (8 bytes on a 64 bit
 * architecture), the malloc overhead and the memory allocated itself (which
 * will often be larger than the memory requested, on 64 bit Linux this can be
 * a minimum of 24 bytes). To allocate and store 1 byte of heap memory we need
 * in this example 32 bytes.
 *
 * UHPA uses a union to either store data in an array, or to allocate memory on
 * the heap, depending on the size of the data being stored (this does mean
 * that the size of the data must always be known). Setting the size of the
 * array changes the point at which heap allocation starts. Using the example
 * above, this means that an array size of 32 bytes should not result in any
 * wasted space, and should be quicker as well. Certainly in the case of topic
 * elements (e.g. "bar" out of "foo/bar/baz") it is likely that an array size
 * of 32 bytes will mean that the majority of heap allocations are removed.
 *
 * You can change the size of MOSQ_PAYLOAD_UNION_SIZE and
 * MOSQ_TOPIC_ELEMENT_UNION_SIZE to change the size of the uhpa array used for
 * the payload (i.e. the published part of a message) and for topic elements
 * (e.g. "foo", "bar" or "baz" in the topic "foo/bar/baz"), and so control the
 * heap allocation threshold for these data types. You should look at your
 * application to decide what values to set, but don't set them too high
 * otherwise your overall memory usage will increase.
 *
 * You could use something like heaptrack
 * http://milianw.de/blog/heaptrack-a-heap-memory-profiler-for-linux to
 * profile heap allocations.
 *
 * I would suggest that values for MOSQ_PAYLOAD_UNION_SIZE and
 * MOSQ_TOPIC_UNION_SIZE that are equivalent to
 * sizeof(void*)+malloc_usable_size(malloc(1)) are a safe value that should
 * reduce calls to malloc without increasing memory usage at all.
 */
#define MOSQ_PAYLOAD_UNION_SIZE 8
typedef union {
	void *ptr;
	char array[MOSQ_PAYLOAD_UNION_SIZE];
} mosquitto__payload_uhpa;
#define UHPA_ALLOC_PAYLOAD(A) UHPA_ALLOC((A)->payload, (A)->payloadlen)
#define UHPA_ACCESS_PAYLOAD(A) UHPA_ACCESS((A)->payload, (A)->payloadlen)
#define UHPA_FREE_PAYLOAD(A) UHPA_FREE((A)->payload, (A)->payloadlen)
#define UHPA_MOVE_PAYLOAD(DEST, SRC) UHPA_MOVE((DEST)->payload, (SRC)->payload, (SRC)->payloadlen)

/* ========================================
 * End UHPA data types
 * ======================================== */

typedef uint64_t dbid_t;

typedef int (*FUNC_auth_plugin_init_v4)(void **, struct mosquitto_opt *, int);
typedef int (*FUNC_auth_plugin_cleanup_v4)(void *, struct mosquitto_opt *, int);
typedef int (*FUNC_auth_plugin_security_init_v4)(void *, struct mosquitto_opt *, int, bool);
typedef int (*FUNC_auth_plugin_security_cleanup_v4)(void *, struct mosquitto_opt *, int, bool);
typedef int (*FUNC_auth_plugin_acl_check_v4)(void *, int, struct mosquitto *, struct mosquitto_acl_msg *);
typedef int (*FUNC_auth_plugin_unpwd_check_v4)(void *, struct mosquitto *, const char *, const char *);
typedef int (*FUNC_auth_plugin_psk_key_get_v4)(void *, struct mosquitto *, const char *, const char *, char *, int);
typedef int (*FUNC_auth_plugin_auth_start_v4)(void *, struct mosquitto *, const char *, bool, const void *, uint16_t, void **, uint16_t *);
typedef int (*FUNC_auth_plugin_auth_continue_v4)(void *, struct mosquitto *, const char *, const void *, uint16_t, void **, uint16_t *);

typedef int (*FUNC_auth_plugin_init_v3)(void **, struct mosquitto_opt *, int);
typedef int (*FUNC_auth_plugin_cleanup_v3)(void *, struct mosquitto_opt *, int);
typedef int (*FUNC_auth_plugin_security_init_v3)(void *, struct mosquitto_opt *, int, bool);
typedef int (*FUNC_auth_plugin_security_cleanup_v3)(void *, struct mosquitto_opt *, int, bool);
typedef int (*FUNC_auth_plugin_acl_check_v3)(void *, int, const struct mosquitto *, struct mosquitto_acl_msg *);
typedef int (*FUNC_auth_plugin_unpwd_check_v3)(void *, const struct mosquitto *, const char *, const char *);
typedef int (*FUNC_auth_plugin_psk_key_get_v3)(void *, const struct mosquitto *, const char *, const char *, char *, int);

typedef int (*FUNC_auth_plugin_init_v2)(void **, struct mosquitto_auth_opt *, int);
typedef int (*FUNC_auth_plugin_cleanup_v2)(void *, struct mosquitto_auth_opt *, int);
typedef int (*FUNC_auth_plugin_security_init_v2)(void *, struct mosquitto_auth_opt *, int, bool);
typedef int (*FUNC_auth_plugin_security_cleanup_v2)(void *, struct mosquitto_auth_opt *, int, bool);
typedef int (*FUNC_auth_plugin_acl_check_v2)(void *, const char *, const char *, const char *, int);
typedef int (*FUNC_auth_plugin_unpwd_check_v2)(void *, const char *, const char *);
typedef int (*FUNC_auth_plugin_psk_key_get_v2)(void *, const char *, const char *, char *, int);


enum mosquitto_msg_origin{
	mosq_mo_client = 0,
	mosq_mo_broker = 1
};

struct mosquitto__auth_plugin{
	void *lib;
	void *user_data;
	int (*plugin_version)(void);

	FUNC_auth_plugin_init_v4 plugin_init_v4;
	FUNC_auth_plugin_cleanup_v4 plugin_cleanup_v4;
	FUNC_auth_plugin_security_init_v4 security_init_v4;
	FUNC_auth_plugin_security_cleanup_v4 security_cleanup_v4;
	FUNC_auth_plugin_acl_check_v4 acl_check_v4;
	FUNC_auth_plugin_unpwd_check_v4 unpwd_check_v4;
	FUNC_auth_plugin_psk_key_get_v4 psk_key_get_v4;
	FUNC_auth_plugin_auth_start_v4 auth_start_v4;
	FUNC_auth_plugin_auth_continue_v4 auth_continue_v4;

	FUNC_auth_plugin_init_v3 plugin_init_v3;
	FUNC_auth_plugin_cleanup_v3 plugin_cleanup_v3;
	FUNC_auth_plugin_security_init_v3 security_init_v3;
	FUNC_auth_plugin_security_cleanup_v3 security_cleanup_v3;
	FUNC_auth_plugin_acl_check_v3 acl_check_v3;
	FUNC_auth_plugin_unpwd_check_v3 unpwd_check_v3;
	FUNC_auth_plugin_psk_key_get_v3 psk_key_get_v3;

	FUNC_auth_plugin_init_v2 plugin_init_v2;
	FUNC_auth_plugin_cleanup_v2 plugin_cleanup_v2;
	FUNC_auth_plugin_security_init_v2 security_init_v2;
	FUNC_auth_plugin_security_cleanup_v2 security_cleanup_v2;
	FUNC_auth_plugin_acl_check_v2 acl_check_v2;
	FUNC_auth_plugin_unpwd_check_v2 unpwd_check_v2;
	FUNC_auth_plugin_psk_key_get_v2 psk_key_get_v2;
	int version;
};

struct mosquitto__auth_plugin_config
{
	char *path;
	struct mosquitto_opt *options;
	int option_count;
	bool deny_special_chars;

	struct mosquitto__auth_plugin plugin;
};

struct mosquitto__security_options {
	/* Any options that get added here also need considering
	 * in config__read() with regards whether allow_anonymous
	 * should be disabled when these options are set.
	 */
	struct mosquitto__acl_user *acl_list;
	struct mosquitto__acl *acl_patterns;
	char *password_file;
	char *psk_file;
	char *acl_file;
	struct mosquitto__auth_plugin_config *auth_plugin_configs;
	int auth_plugin_config_count;
	int8_t allow_anonymous;
	bool allow_zero_length_clientid;
	char *auto_id_prefix;
	int auto_id_prefix_len;
};

struct mosquitto__listener {
	int fd;
	uint16_t port;
	char *host;
	char *bind_interface;
	int max_connections;
	char *mount_point;
	mosq_sock_t *socks;
	int sock_count;
	int client_count;
	enum mosquitto_protocol protocol;
	int socket_domain;
	bool use_username_as_clientid;
	uint8_t maximum_qos;
	uint16_t max_topic_alias;
#ifdef WITH_TLS
	char *cafile;
	char *capath;
	char *certfile;
	char *keyfile;
	char *tls_engine;
	char *tls_engine_kpass_sha1;
	char *ciphers;
	char *psk_hint;
	SSL_CTX *ssl_ctx;
	char *crlfile;
	char *tls_version;
	char *dhparamfile;
	bool use_identity_as_username;
	bool use_subject_as_username;
	bool require_certificate;
	enum mosquitto__keyform tls_keyform;
#endif
#ifdef WITH_WEBSOCKETS
	struct libwebsocket_context *ws_context;
	char *http_dir;
	struct libwebsocket_protocols *ws_protocol;
#endif
	struct mosquitto__security_options security_options;
	struct mosquitto__unpwd *unpwd;
	struct mosquitto__unpwd *psk_id;
};

struct mosquitto__config {
	bool allow_duplicate_messages;
	int autosave_interval;
	bool autosave_on_changes;
	bool check_retain_source;
	char *clientid_prefixes;
	bool connection_messages;
	bool daemon;
	struct mosquitto__listener default_listener;
	struct mosquitto__listener *listeners;
	int listener_count;
	int log_dest;
	int log_facility;
	unsigned int log_type;
	bool log_timestamp;
	char *log_timestamp_format;
	char *log_file;
	FILE *log_fptr;
	uint16_t max_inflight_messages;
	uint16_t max_keepalive;
	uint32_t max_packet_size;
	uint32_t message_size_limit;
	bool persistence;
	char *persistence_location;
	char *persistence_file;
	char *persistence_filepath;
	time_t persistent_client_expiration;
	char *pid_file;
	bool queue_qos0_messages;
	bool per_listener_settings;
	bool retain_available;
	bool set_tcp_nodelay;
	int sys_interval;
	bool upgrade_outgoing_qos;
	char *user;
#ifdef WITH_WEBSOCKETS
	int websockets_log_level;
	int websockets_headers_size;
	bool have_websockets_listener;
#endif
#ifdef WITH_BRIDGE
	struct mosquitto__bridge *bridges;
	int bridge_count;
#endif
	struct mosquitto__security_options security_options;
};

struct mosquitto__subleaf {
	struct mosquitto__subleaf *prev;
	struct mosquitto__subleaf *next;
	struct mosquitto *context;
	uint32_t identifier;
	uint8_t qos;
	bool no_local;
	bool retain_as_published;
};


struct mosquitto__subshared_ref {
	struct mosquitto__subhier *hier;
	struct mosquitto__subshared *shared;
};


struct mosquitto__subshared {
	UT_hash_handle hh;
	char *name;
	struct mosquitto__subleaf *subs;
};

struct mosquitto__subhier {
	UT_hash_handle hh;
	struct mosquitto__subhier *parent;
	struct mosquitto__subhier *children;
	struct mosquitto__subleaf *subs;
	struct mosquitto__subshared *shared;
	struct mosquitto_msg_store *retained;
	char *topic;
	uint16_t topic_len;
};

struct mosquitto_msg_store_load{
	UT_hash_handle hh;
	dbid_t db_id;
	struct mosquitto_msg_store *store;
};

struct mosquitto_msg_store{
	struct mosquitto_msg_store *next;
	struct mosquitto_msg_store *prev;
	dbid_t db_id;
	char *source_id;
	char *source_username;
	struct mosquitto__listener *source_listener;
	char **dest_ids;
	int dest_id_count;
	int ref_count;
	char* topic;
	mosquitto_property *properties;
	mosquitto__payload_uhpa payload;
	time_t message_expiry_time;
	uint32_t payloadlen;
	uint16_t source_mid;
	uint16_t mid;
	uint8_t qos;
	bool retain;
	uint8_t origin;
};

struct mosquitto_client_msg{
	struct mosquitto_client_msg *prev;
	struct mosquitto_client_msg *next;
	struct mosquitto_msg_store *store;
	mosquitto_property *properties;
	time_t timestamp;
	uint16_t mid;
	uint8_t qos;
	bool retain;
	enum mosquitto_msg_direction direction;
	enum mosquitto_msg_state state;
	bool dup;
};

struct mosquitto__unpwd{
	char *username;
	char *password;
#ifdef WITH_TLS
	unsigned int password_len;
	unsigned int salt_len;
	unsigned char *salt;
#endif
	UT_hash_handle hh;
};

struct mosquitto__acl{
	struct mosquitto__acl *next;
	char *topic;
	int access;
	int ucount;
	int ccount;
};

struct mosquitto__acl_user{
	struct mosquitto__acl_user *next;
	char *username;
	struct mosquitto__acl *acl;
};

struct mosquitto_db{
	dbid_t last_db_id;
	struct mosquitto__subhier *subs;
	struct mosquitto__unpwd *unpwd;
	struct mosquitto__unpwd *psk_id;
	struct mosquitto *contexts_by_id;
	struct mosquitto *contexts_by_sock;
	struct mosquitto *contexts_for_free;
#ifdef WITH_BRIDGE
	struct mosquitto **bridges;
#endif
	struct clientid__index_hash *clientid_index_hash;
	struct mosquitto_msg_store *msg_store;
	struct mosquitto_msg_store_load *msg_store_load;
#ifdef WITH_BRIDGE
	int bridge_count;
#endif
	int msg_store_count;
	unsigned long msg_store_bytes;
	char *config_file;
	struct mosquitto__config *config;
	int auth_plugin_count;
	bool verbose;
#ifdef WITH_SYS_TREE
	int subscription_count;
	int shared_subscription_count;
	int retained_count;
#endif
	int persistence_changes;
	struct mosquitto *ll_for_free;
#ifdef WITH_EPOLL
	int epollfd;
#endif
};

enum mosquitto__bridge_direction{
	bd_out = 0,
	bd_in = 1,
	bd_both = 2
};

enum mosquitto_bridge_start_type{
	bst_automatic = 0,
	bst_lazy = 1,
	bst_manual = 2,
	bst_once = 3
};

struct mosquitto__bridge_topic{
	char *topic;
	int qos;
	enum mosquitto__bridge_direction direction;
	char *local_prefix;
	char *remote_prefix;
	char *local_topic; /* topic prefixed with local_prefix */
	char *remote_topic; /* topic prefixed with remote_prefix */
};

struct bridge_address{
	char *address;
	int port;
	struct addrinfo *ainfo;
};

struct mosquitto__bridge{
	char *name;
	struct bridge_address *addresses;
	int cur_address;
	int address_count;
	time_t primary_retry;
	mosq_sock_t primary_retry_sock;
	bool round_robin;
	bool try_private;
	bool try_private_accepted;
	bool clean_start;
	int keepalive;
	struct mosquitto__bridge_topic *topics;
	int topic_count;
	bool topic_remapping;
	enum mosquitto__protocol protocol_version;
	time_t restart_t;
	char *remote_clientid;
	char *remote_username;
	char *remote_password;
	char *local_clientid;
	char *local_username;
	char *local_password;
	char *notification_topic;
	bool notifications;
	bool notifications_local_only;
	enum mosquitto_bridge_start_type start_type;
	int idle_timeout;
	int restart_timeout;
	int backoff_base;
	int backoff_cap;
	int threshold;
	bool lazy_reconnect;
	bool attempt_unsubscribe;
	bool initial_notification_done;
#ifdef WITH_TLS
	bool tls_insecure;
	bool tls_ocsp_required;
	char *tls_cafile;
	char *tls_capath;
	char *tls_certfile;
	char *tls_keyfile;
	char *tls_version;
	char *tls_alpn;
#  ifdef FINAL_WITH_TLS_PSK
	char *tls_psk_identity;
	char *tls_psk;
#  endif
#endif
};

#ifdef WITH_WEBSOCKETS
struct libws_mqtt_hack {
	char *http_dir;
};

struct libws_mqtt_data {
	struct mosquitto *mosq;
};
#endif

#include <net_mosq.h>

/* ============================================================
 * Main functions
 * ============================================================ */
int mosquitto_main_loop(struct mosquitto_db *db, mosq_sock_t *listensock, int listensock_count);
struct mosquitto_db *mosquitto__get_db(void);

/* ============================================================
 * Config functions
 * ============================================================ */
/* Initialise config struct to default values. */
void config__init(struct mosquitto_db *db, struct mosquitto__config *config);
/* Parse command line options into config. */
int config__parse_args(struct mosquitto_db *db, struct mosquitto__config *config, int argc, char *argv[]);
/* Read configuration data from config->config_file into config.
 * If reload is true, don't process config options that shouldn't be reloaded (listeners etc)
 * Returns 0 on success, 1 if there is a configuration error or if a file cannot be opened.
 */
int config__read(struct mosquitto_db *db, struct mosquitto__config *config, bool reload);
/* Free all config data. */
void config__cleanup(struct mosquitto__config *config);
int config__get_dir_files(const char *include_dir, char ***files, int *file_count);

int drop_privileges(struct mosquitto__config *config, bool temporary);
int restore_privileges(void);

/* ============================================================
 * Server send functions
 * ============================================================ */
int send__connack(struct mosquitto_db *db, struct mosquitto *context, int ack, int reason_code, const mosquitto_property *properties);
int send__suback(struct mosquitto *context, uint16_t mid, uint32_t payloadlen, const void *payload);
int send__unsuback(struct mosquitto *context, uint16_t mid, int reason_code_count, uint8_t *reason_codes, const mosquitto_property *properties);
int send__auth(struct mosquitto_db *db, struct mosquitto *context, int reason_code, const void *auth_data, uint16_t auth_data_len);

/* ============================================================
 * Network functions
 * ============================================================ */
void net__broker_init(void);
void net__broker_cleanup(void);
int net__socket_accept(struct mosquitto_db *db, mosq_sock_t listensock);
int net__socket_listen(struct mosquitto__listener *listener);
int net__socket_get_address(mosq_sock_t sock, char *buf, int len);
int net__tls_load_verify(struct mosquitto__listener *listener);
int net__tls_server_ctx(struct mosquitto__listener *listener);

/* ============================================================
 * Read handling functions
 * ============================================================ */
int handle__packet(struct mosquitto_db *db, struct mosquitto *context);
int handle__connack(struct mosquitto_db *db, struct mosquitto *context);
int handle__connect(struct mosquitto_db *db, struct mosquitto *context);
int handle__disconnect(struct mosquitto_db *db, struct mosquitto *context);
int handle__publish(struct mosquitto_db *db, struct mosquitto *context);
int handle__subscribe(struct mosquitto_db *db, struct mosquitto *context);
int handle__unsubscribe(struct mosquitto_db *db, struct mosquitto *context);
int handle__auth(struct mosquitto_db *db, struct mosquitto *context);

/* ============================================================
 * Database handling
 * ============================================================ */
int db__open(struct mosquitto__config *config, struct mosquitto_db *db);
int db__close(struct mosquitto_db *db);
#ifdef WITH_PERSISTENCE
int persist__backup(struct mosquitto_db *db, bool shutdown);
int persist__restore(struct mosquitto_db *db);
#endif
void db__limits_set(unsigned long inflight_bytes, int queued, unsigned long queued_bytes);
/* Return the number of in-flight messages in count. */
int db__message_count(int *count);
int db__message_delete_outgoing(struct mosquitto_db *db, struct mosquitto *context, uint16_t mid, enum mosquitto_msg_state expect_state, int qos);
int db__message_insert(struct mosquitto_db *db, struct mosquitto *context, uint16_t mid, enum mosquitto_msg_direction dir, int qos, bool retain, struct mosquitto_msg_store *stored, mosquitto_property *properties);
int db__message_release_incoming(struct mosquitto_db *db, struct mosquitto *context, uint16_t mid);
int db__message_update_outgoing(struct mosquitto *context, uint16_t mid, enum mosquitto_msg_state state, int qos);
int db__message_write(struct mosquitto_db *db, struct mosquitto *context);
void db__message_dequeue_first(struct mosquitto *context, struct mosquitto_msg_data *msg_data);
int db__messages_delete(struct mosquitto_db *db, struct mosquitto *context);
int db__messages_easy_queue(struct mosquitto_db *db, struct mosquitto *context, const char *topic, int qos, uint32_t payloadlen, const void *payload, int retain, uint32_t message_expiry_interval, mosquitto_property **properties);
int db__message_store(struct mosquitto_db *db, const struct mosquitto *source, uint16_t source_mid, char *topic, int qos, uint32_t payloadlen, mosquitto__payload_uhpa *payload, int retain, struct mosquitto_msg_store **stored, uint32_t message_expiry_interval, mosquitto_property *properties, dbid_t store_id, enum mosquitto_msg_origin origin);
int db__message_store_find(struct mosquitto *context, uint16_t mid, struct mosquitto_msg_store **stored);
void db__msg_store_add(struct mosquitto_db *db, struct mosquitto_msg_store *store);
void db__msg_store_remove(struct mosquitto_db *db, struct mosquitto_msg_store *store);
void db__msg_store_ref_inc(struct mosquitto_msg_store *store);
void db__msg_store_ref_dec(struct mosquitto_db *db, struct mosquitto_msg_store **store);
void db__msg_store_clean(struct mosquitto_db *db);
void db__msg_store_compact(struct mosquitto_db *db);
int db__message_reconnect_reset(struct mosquitto_db *db, struct mosquitto *context);
void sys_tree__init(struct mosquitto_db *db);
void sys_tree__update(struct mosquitto_db *db, int interval, time_t start_time);

/* ============================================================
 * Subscription functions
 * ============================================================ */
int sub__add(struct mosquitto_db *db, struct mosquitto *context, const char *sub, int qos, uint32_t identifier, int options, struct mosquitto__subhier **root);
struct mosquitto__subhier *sub__add_hier_entry(struct mosquitto__subhier *parent, struct mosquitto__subhier **sibling, const char *topic, size_t len);
int sub__remove(struct mosquitto_db *db, struct mosquitto *context, const char *sub, struct mosquitto__subhier *root, uint8_t *reason);
void sub__tree_print(struct mosquitto__subhier *root, int level);
int sub__clean_session(struct mosquitto_db *db, struct mosquitto *context);
int sub__retain_queue(struct mosquitto_db *db, struct mosquitto *context, const char *sub, int sub_qos, uint32_t subscription_identifier);
int sub__messages_queue(struct mosquitto_db *db, const char *source_id, const char *topic, int qos, int retain, struct mosquitto_msg_store **stored);

/* ============================================================
 * Context functions
 * ============================================================ */
struct mosquitto *context__init(struct mosquitto_db *db, mosq_sock_t sock);
void context__cleanup(struct mosquitto_db *db, struct mosquitto *context, bool do_free);
void context__disconnect(struct mosquitto_db *db, struct mosquitto *context);
void context__add_to_disused(struct mosquitto_db *db, struct mosquitto *context);
void context__free_disused(struct mosquitto_db *db);
void context__send_will(struct mosquitto_db *db, struct mosquitto *context);
void context__remove_from_by_id(struct mosquitto_db *db, struct mosquitto *context);

int connect__on_authorised(struct mosquitto_db *db, struct mosquitto *context, void *auth_data_out, uint16_t auth_data_out_len);

/* ============================================================
 * Logging functions
 * ============================================================ */
int log__init(struct mosquitto__config *config);
int log__close(struct mosquitto__config *config);
int log__printf(struct mosquitto *mosq, int level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
void log__internal(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* ============================================================
 * Bridge functions
 * ============================================================ */
#ifdef WITH_BRIDGE
int bridge__new(struct mosquitto_db *db, struct mosquitto__bridge *bridge);
int bridge__connect(struct mosquitto_db *db, struct mosquitto *context);
int bridge__connect_step1(struct mosquitto_db *db, struct mosquitto *context);
int bridge__connect_step2(struct mosquitto_db *db, struct mosquitto *context);
int bridge__connect_step3(struct mosquitto_db *db, struct mosquitto *context);
void bridge__packet_cleanup(struct mosquitto *context);
#endif

/* ============================================================
 * Property related functions
 * ============================================================ */
int property__process_connect(struct mosquitto *context, mosquitto_property **props);
int property__process_will(struct mosquitto *context, struct mosquitto_message_all *msg, mosquitto_property **props);
int property__process_disconnect(struct mosquitto *context, mosquitto_property **props);

/* ============================================================
 * Security related functions
 * ============================================================ */
int acl__find_acls(struct mosquitto_db *db, struct mosquitto *context);
int mosquitto_security_module_init(struct mosquitto_db *db);
int mosquitto_security_module_cleanup(struct mosquitto_db *db);

int mosquitto_security_init(struct mosquitto_db *db, bool reload);
int mosquitto_security_apply(struct mosquitto_db *db);
int mosquitto_security_cleanup(struct mosquitto_db *db, bool reload);
int mosquitto_acl_check(struct mosquitto_db *db, struct mosquitto *context, const char *topic, long payloadlen, void* payload, int qos, bool retain, int access);
int mosquitto_unpwd_check(struct mosquitto_db *db, struct mosquitto *context, const char *username, const char *password);
int mosquitto_psk_key_get(struct mosquitto_db *db, struct mosquitto *context, const char *hint, const char *identity, char *key, int max_key_len);

int mosquitto_security_init_default(struct mosquitto_db *db, bool reload);
int mosquitto_security_apply_default(struct mosquitto_db *db);
int mosquitto_security_cleanup_default(struct mosquitto_db *db, bool reload);
int mosquitto_acl_check_default(struct mosquitto_db *db, struct mosquitto *context, const char *topic, int access);
int mosquitto_unpwd_check_default(struct mosquitto_db *db, struct mosquitto *context, const char *username, const char *password);
int mosquitto_psk_key_get_default(struct mosquitto_db *db, struct mosquitto *context, const char *hint, const char *identity, char *key, int max_key_len);

int mosquitto_security_auth_start(struct mosquitto_db *db, struct mosquitto *context, bool reauth, const void *data_in, uint16_t data_in_len, void **data_out, uint16_t *data_out_len);
int mosquitto_security_auth_continue(struct mosquitto_db *db, struct mosquitto *context, const void *data_in, uint16_t data_len, void **data_out, uint16_t *data_out_len);

/* ============================================================
 * Session expiry
 * ============================================================ */
int session_expiry__add(struct mosquitto_db *db, struct mosquitto *context);
void session_expiry__remove(struct mosquitto *context);
void session_expiry__remove_all(struct mosquitto_db *db);
void session_expiry__check(struct mosquitto_db *db, time_t now);
void session_expiry__send_all(struct mosquitto_db *db);

/* ============================================================
 * Window service and signal related functions
 * ============================================================ */
#if defined(WIN32) || defined(__CYGWIN__)
void service_install(void);
void service_uninstall(void);
void service_run(void);

DWORD WINAPI SigThreadProc(void* data);
#endif

/* ============================================================
 * Websockets related functions
 * ============================================================ */
#ifdef WITH_WEBSOCKETS
#  if defined(LWS_LIBRARY_VERSION_NUMBER)
struct lws_context *mosq_websockets_init(struct mosquitto__listener *listener, const struct mosquitto__config *conf);
#  else
struct libwebsocket_context *mosq_websockets_init(struct mosquitto__listener *listener, const struct mosquitto__config *conf);
#  endif
#endif
void do_disconnect(struct mosquitto_db *db, struct mosquitto *context, int reason);

/* ============================================================
 * Will delay
 * ============================================================ */
int will_delay__add(struct mosquitto *context);
void will_delay__check(struct mosquitto_db *db, time_t now);
void will_delay__send_all(struct mosquitto_db *db);
void will_delay__remove(struct mosquitto *mosq);

#endif

