/*
Copyright (c) 2009-2014 Roger Light <roger@atchoo.org>

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

#ifndef MQTT3_H
#define MQTT3_H

#include <config.h>
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
#    define libwebsocket_get_protocol(A) lws_get_protocol((A))

#    define libwebsocket_context lws_context
#    define libwebsocket_protocols lws_protocols
#    define libwebsocket_callback_reasons lws_callback_reasons
#    define libwebsocket lws
#  endif
#endif

#include <mosquitto_internal.h>
#include <mosquitto_plugin.h>
#include <mosquitto.h>
#include "tls_mosq.h"
#include "uthash.h"

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

enum mosquitto_protocol {
	mp_mqtt,
	mp_mqttsn,
	mp_websockets
};

typedef uint64_t dbid_t;

struct _mqtt3_listener {
	int fd;
	char *host;
	uint16_t port;
	int max_connections;
	char *mount_point;
	mosq_sock_t *socks;
	int sock_count;
	int client_count;
	enum mosquitto_protocol protocol;
	bool use_username_as_clientid;
#ifdef WITH_TLS
	char *cafile;
	char *capath;
	char *certfile;
	char *keyfile;
	char *ciphers;
	char *psk_hint;
	bool require_certificate;
	SSL_CTX *ssl_ctx;
	char *crlfile;
	bool use_identity_as_username;
	char *tls_version;
#endif
#ifdef WITH_WEBSOCKETS
	struct libwebsocket_context *ws_context;
	char *http_dir;
	struct libwebsocket_protocols *ws_protocol;
#endif
};

struct mqtt3_config {
	char *config_file;
	char *acl_file;
	bool allow_anonymous;
	bool allow_duplicate_messages;
	bool allow_zero_length_clientid;
	char *auto_id_prefix;
	int auto_id_prefix_len;
	int autosave_interval;
	bool autosave_on_changes;
	char *clientid_prefixes;
	bool connection_messages;
	bool daemon;
	struct _mqtt3_listener default_listener;
	struct _mqtt3_listener *listeners;
	int listener_count;
	int log_dest;
	int log_facility;
	int log_type;
	bool log_timestamp;
	char *log_file;
	FILE *log_fptr;
	uint32_t message_size_limit;
	char *password_file;
	bool persistence;
	char *persistence_location;
	char *persistence_file;
	char *persistence_filepath;
	time_t persistent_client_expiration;
	char *pid_file;
	char *psk_file;
	bool queue_qos0_messages;
	int retry_interval;
	int sys_interval;
	bool upgrade_outgoing_qos;
	char *user;
	bool verbose;
#ifdef WITH_WEBSOCKETS
	int websockets_log_level;
	bool have_websockets_listener;
#endif
#ifdef WITH_BRIDGE
	struct _mqtt3_bridge *bridges;
	int bridge_count;
#endif
	char *auth_plugin;
	struct mosquitto_auth_opt *auth_options;
	int auth_option_count;
};

struct _mosquitto_subleaf {
	struct _mosquitto_subleaf *prev;
	struct _mosquitto_subleaf *next;
	struct mosquitto *context;
	int qos;
};

struct _mosquitto_subhier {
	struct _mosquitto_subhier *parent;
	struct _mosquitto_subhier *children;
	struct _mosquitto_subhier *next;
	struct _mosquitto_subleaf *subs;
	char *topic;
	struct mosquitto_msg_store *retained;
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
	char **dest_ids;
	int dest_id_count;
	int ref_count;
	char *topic;
	void *payload;
	uint32_t payloadlen;
	uint16_t source_mid;
	uint16_t mid;
	uint8_t qos;
	bool retain;
};

struct mosquitto_client_msg{
	struct mosquitto_client_msg *next;
	struct mosquitto_msg_store *store;
	time_t timestamp;
	uint16_t mid;
	uint8_t qos;
	bool retain;
	enum mosquitto_msg_direction direction;
	enum mosquitto_msg_state state;
	bool dup;
};

struct _mosquitto_unpwd{
	char *username;
	char *password;
#ifdef WITH_TLS
	unsigned int password_len;
	unsigned int salt_len;
	unsigned char *salt;
#endif
	UT_hash_handle hh;
};

struct _mosquitto_acl{
	struct _mosquitto_acl *next;
	char *topic;
	int access;
	int ucount;
	int ccount;
};

struct _mosquitto_acl_user{
	struct _mosquitto_acl_user *next;
	char *username;
	struct _mosquitto_acl *acl;
};

struct _mosquitto_auth_plugin{
	void *lib;
	void *user_data;
	int (*plugin_version)(void);
	int (*plugin_init)(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count);
	int (*plugin_cleanup)(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count);
	int (*security_init)(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload);
	int (*security_cleanup)(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload);
	int (*acl_check)(void *user_data, const char *clientid, const char *username, const char *topic, int access);
	int (*unpwd_check)(void *user_data, const char *username, const char *password);
	int (*psk_key_get)(void *user_data, const char *hint, const char *identity, char *key, int max_key_len);
};

struct mosquitto_db{
	dbid_t last_db_id;
	struct _mosquitto_subhier subs;
	struct _mosquitto_unpwd *unpwd;
	struct _mosquitto_acl_user *acl_list;
	struct _mosquitto_acl *acl_patterns;
	struct _mosquitto_unpwd *psk_id;
	struct mosquitto *contexts_by_id;
	struct mosquitto *contexts_by_sock;
	struct mosquitto *contexts_for_free;
#ifdef WITH_BRIDGE
	struct mosquitto **bridges;
#endif
	struct _clientid_index_hash *clientid_index_hash;
	struct mosquitto_msg_store *msg_store;
	struct mosquitto_msg_store_load *msg_store_load;
#ifdef WITH_BRIDGE
	int bridge_count;
#endif
	int msg_store_count;
	struct mqtt3_config *config;
	int persistence_changes;
	struct _mosquitto_auth_plugin auth_plugin;
#ifdef WITH_SYS_TREE
	int subscription_count;
	int retained_count;
#endif
	struct mosquitto *ll_for_free;
};

enum mqtt3_bridge_direction{
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

struct _mqtt3_bridge_topic{
	char *topic;
	int qos;
	enum mqtt3_bridge_direction direction;
	char *local_prefix;
	char *remote_prefix;
	char *local_topic; /* topic prefixed with local_prefix */
	char *remote_topic; /* topic prefixed with remote_prefix */
};

struct bridge_address{
	char *address;
	int port;
};

struct _mqtt3_bridge{
	char *name;
	struct bridge_address *addresses;
	int cur_address;
	int address_count;
	time_t primary_retry;
	bool round_robin;
	bool try_private;
	bool try_private_accepted;
	bool clean_session;
	int keepalive;
	struct _mqtt3_bridge_topic *topics;
	int topic_count;
	bool topic_remapping;
	enum _mosquitto_protocol protocol_version;
	time_t restart_t;
	char *remote_clientid;
	char *remote_username;
	char *remote_password;
	char *local_clientid;
	char *local_username;
	char *local_password;
	bool notifications;
	char *notification_topic;
	enum mosquitto_bridge_start_type start_type;
	int idle_timeout;
	int restart_timeout;
	int threshold;
	bool lazy_reconnect;
	bool attempt_unsubscribe;
	bool initial_notification_done;
#ifdef WITH_TLS
	char *tls_cafile;
	char *tls_capath;
	char *tls_certfile;
	char *tls_keyfile;
	bool tls_insecure;
	char *tls_version;
#  ifdef REAL_WITH_TLS_PSK
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
int mosquitto_main_loop(struct mosquitto_db *db, mosq_sock_t *listensock, int listensock_count, int listener_max);
struct mosquitto_db *_mosquitto_get_db(void);

/* ============================================================
 * Config functions
 * ============================================================ */
/* Initialise config struct to default values. */
void mqtt3_config_init(struct mqtt3_config *config);
/* Parse command line options into config. */
int mqtt3_config_parse_args(struct mqtt3_config *config, int argc, char *argv[]);
/* Read configuration data from config->config_file into config.
 * If reload is true, don't process config options that shouldn't be reloaded (listeners etc)
 * Returns 0 on success, 1 if there is a configuration error or if a file cannot be opened.
 */
int mqtt3_config_read(struct mqtt3_config *config, bool reload);
/* Free all config data. */
void mqtt3_config_cleanup(struct mqtt3_config *config);

int drop_privileges(struct mqtt3_config *config, bool temporary);
int restore_privileges(void);

/* ============================================================
 * Server send functions
 * ============================================================ */
int _mosquitto_send_connack(struct mosquitto *context, int ack, int result);
int _mosquitto_send_suback(struct mosquitto *context, uint16_t mid, uint32_t payloadlen, const void *payload);

/* ============================================================
 * Network functions
 * ============================================================ */
int mqtt3_socket_accept(struct mosquitto_db *db, mosq_sock_t listensock);
int mqtt3_socket_listen(struct _mqtt3_listener *listener);
int _mosquitto_socket_get_address(mosq_sock_t sock, char *buf, int len);

/* ============================================================
 * Read handling functions
 * ============================================================ */
int mqtt3_packet_handle(struct mosquitto_db *db, struct mosquitto *context);
int mqtt3_handle_connack(struct mosquitto_db *db, struct mosquitto *context);
int mqtt3_handle_connect(struct mosquitto_db *db, struct mosquitto *context);
int mqtt3_handle_disconnect(struct mosquitto_db *db, struct mosquitto *context);
int mqtt3_handle_publish(struct mosquitto_db *db, struct mosquitto *context);
int mqtt3_handle_subscribe(struct mosquitto_db *db, struct mosquitto *context);
int mqtt3_handle_unsubscribe(struct mosquitto_db *db, struct mosquitto *context);

/* ============================================================
 * Database handling
 * ============================================================ */
int mqtt3_db_open(struct mqtt3_config *config, struct mosquitto_db *db);
int mqtt3_db_close(struct mosquitto_db *db);
#ifdef WITH_PERSISTENCE
int mqtt3_db_backup(struct mosquitto_db *db, bool shutdown);
int mqtt3_db_restore(struct mosquitto_db *db);
#endif
void mqtt3_db_limits_set(int inflight, int queued);
/* Return the number of in-flight messages in count. */
int mqtt3_db_message_count(int *count);
int mqtt3_db_message_delete(struct mosquitto_db *db, struct mosquitto *context, uint16_t mid, enum mosquitto_msg_direction dir);
int mqtt3_db_message_insert(struct mosquitto_db *db, struct mosquitto *context, uint16_t mid, enum mosquitto_msg_direction dir, int qos, bool retain, struct mosquitto_msg_store *stored);
int mqtt3_db_message_release(struct mosquitto_db *db, struct mosquitto *context, uint16_t mid, enum mosquitto_msg_direction dir);
int mqtt3_db_message_update(struct mosquitto *context, uint16_t mid, enum mosquitto_msg_direction dir, enum mosquitto_msg_state state);
int mqtt3_db_message_write(struct mosquitto_db *db, struct mosquitto *context);
int mqtt3_db_messages_delete(struct mosquitto_db *db, struct mosquitto *context);
int mqtt3_db_messages_easy_queue(struct mosquitto_db *db, struct mosquitto *context, const char *topic, int qos, uint32_t payloadlen, const void *payload, int retain);
int mqtt3_db_messages_queue(struct mosquitto_db *db, const char *source_id, const char *topic, int qos, int retain, struct mosquitto_msg_store **stored);
int mqtt3_db_message_store(struct mosquitto_db *db, const char *source, uint16_t source_mid, const char *topic, int qos, uint32_t payloadlen, const void *payload, int retain, struct mosquitto_msg_store **stored, dbid_t store_id);
int mqtt3_db_message_store_find(struct mosquitto *context, uint16_t mid, struct mosquitto_msg_store **stored);
void mosquitto__db_msg_store_add(struct mosquitto_db *db, struct mosquitto_msg_store *store);
void mosquitto__db_msg_store_remove(struct mosquitto_db *db, struct mosquitto_msg_store *store);
void mosquitto__db_msg_store_deref(struct mosquitto_db *db, struct mosquitto_msg_store **store);
void mosquitto__db_msg_store_clean(struct mosquitto_db *db);
/* Check all messages waiting on a client reply and resend if timeout has been exceeded. */
int mqtt3_db_message_timeout_check(struct mosquitto_db *db, unsigned int timeout);
int mqtt3_db_message_reconnect_reset(struct mosquitto_db *db, struct mosquitto *context);
int mqtt3_retain_queue(struct mosquitto_db *db, struct mosquitto *context, const char *sub, int sub_qos);
void mqtt3_db_sys_update(struct mosquitto_db *db, int interval, time_t start_time);
void mqtt3_db_vacuum(void);

/* ============================================================
 * Subscription functions
 * ============================================================ */
int mqtt3_sub_add(struct mosquitto_db *db, struct mosquitto *context, const char *sub, int qos, struct _mosquitto_subhier *root);
int mqtt3_sub_remove(struct mosquitto_db *db, struct mosquitto *context, const char *sub, struct _mosquitto_subhier *root);
int mqtt3_sub_search(struct mosquitto_db *db, struct _mosquitto_subhier *root, const char *source_id, const char *topic, int qos, int retain, struct mosquitto_msg_store *stored);
void mqtt3_sub_tree_print(struct _mosquitto_subhier *root, int level);
int mqtt3_subs_clean_session(struct mosquitto_db *db, struct mosquitto *context);

/* ============================================================
 * Context functions
 * ============================================================ */
struct mosquitto *mqtt3_context_init(struct mosquitto_db *db, mosq_sock_t sock);
void mqtt3_context_cleanup(struct mosquitto_db *db, struct mosquitto *context, bool do_free);
void mqtt3_context_disconnect(struct mosquitto_db *db, struct mosquitto *context);
void mosquitto__add_context_to_disused(struct mosquitto_db *db, struct mosquitto *context);
void mosquitto__free_disused_contexts(struct mosquitto_db *db);

/* ============================================================
 * Logging functions
 * ============================================================ */
int mqtt3_log_init(struct mqtt3_config *config);
int mqtt3_log_close(struct mqtt3_config *config);
int _mosquitto_log_printf(struct mosquitto *mosq, int level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

/* ============================================================
 * Bridge functions
 * ============================================================ */
#ifdef WITH_BRIDGE
int mqtt3_bridge_new(struct mosquitto_db *db, struct _mqtt3_bridge *bridge);
int mqtt3_bridge_connect(struct mosquitto_db *db, struct mosquitto *context);
void mqtt3_bridge_packet_cleanup(struct mosquitto *context);
#endif

/* ============================================================
 * Security related functions
 * ============================================================ */
int mosquitto_security_module_init(struct mosquitto_db *db);
int mosquitto_security_module_cleanup(struct mosquitto_db *db);

int mosquitto_security_init(struct mosquitto_db *db, bool reload);
int mosquitto_security_apply(struct mosquitto_db *db);
int mosquitto_security_cleanup(struct mosquitto_db *db, bool reload);
int mosquitto_acl_check(struct mosquitto_db *db, struct mosquitto *context, const char *topic, int access);
int mosquitto_unpwd_check(struct mosquitto_db *db, const char *username, const char *password);
int mosquitto_psk_key_get(struct mosquitto_db *db, const char *hint, const char *identity, char *key, int max_key_len);

int mosquitto_security_init_default(struct mosquitto_db *db, bool reload);
int mosquitto_security_apply_default(struct mosquitto_db *db);
int mosquitto_security_cleanup_default(struct mosquitto_db *db, bool reload);
int mosquitto_acl_check_default(struct mosquitto_db *db, struct mosquitto *context, const char *topic, int access);
int mosquitto_unpwd_check_default(struct mosquitto_db *db, const char *username, const char *password);
int mosquitto_psk_key_get_default(struct mosquitto_db *db, const char *hint, const char *identity, char *key, int max_key_len);

/* ============================================================
 * Window service related functions
 * ============================================================ */
#if defined(WIN32) || defined(__CYGWIN__)
void service_install(void);
void service_uninstall(void);
void service_run(void);
#endif

/* ============================================================
 * Websockets related functions
 * ============================================================ */
#ifdef WITH_WEBSOCKETS
#  if defined(LWS_LIBRARY_VERSION_NUMBER)
struct lws_context *mosq_websockets_init(struct _mqtt3_listener *listener, int log_level);
#  else
struct libwebsocket_context *mosq_websockets_init(struct _mqtt3_listener *listener, int log_level);
#  endif
#endif
void do_disconnect(struct mosquitto_db *db, struct mosquitto *context);

#endif
