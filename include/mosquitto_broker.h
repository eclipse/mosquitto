/*
Copyright (c) 2009-2021 Roger Light <roger@atchoo.org>

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
*/

/*
 * File: mosquitto_broker.h
 *
 * This header contains functions for use by plugins.
 */
#ifndef MOSQUITTO_BROKER_H
#define MOSQUITTO_BROKER_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(WIN32) && defined(mosquitto_EXPORTS)
#	define mosq_EXPORT  __declspec(dllexport)
#else
#	define mosq_EXPORT
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include <mosquitto.h>

struct mosquitto;
typedef struct mqtt5__property mosquitto_property;

enum mosquitto_protocol {
	mp_mqtt,
	mp_mqttsn,
	mp_websockets,
	mp_quic,
};

enum mosquitto_broker_msg_direction {
	mosq_bmd_in = 0,
	mosq_bmd_out = 1
};

/* =========================================================================
 *
 * Section: Register callbacks.
 *
 * ========================================================================= */

/* Callback events */
enum mosquitto_plugin_event {
	MOSQ_EVT_RELOAD = 1,
	MOSQ_EVT_ACL_CHECK = 2,
	MOSQ_EVT_BASIC_AUTH = 3,
	MOSQ_EVT_EXT_AUTH_START = 4,
	MOSQ_EVT_EXT_AUTH_CONTINUE = 5,
	MOSQ_EVT_CONTROL = 6,
	MOSQ_EVT_MESSAGE = 7,
	MOSQ_EVT_PSK_KEY = 8,
	MOSQ_EVT_TICK = 9,
	MOSQ_EVT_DISCONNECT = 10,
	MOSQ_EVT_CONNECT = 11,
	MOSQ_EVT_PERSIST_RESTORE = 12,
	MOSQ_EVT_PERSIST_CONFIG_ADD = 13,
	MOSQ_EVT_PERSIST_MSG_ADD = 14,
	MOSQ_EVT_PERSIST_MSG_DELETE = 15,
	MOSQ_EVT_PERSIST_MSG_LOAD = 16,
	MOSQ_EVT_PERSIST_RETAIN_ADD = 17,
	MOSQ_EVT_PERSIST_RETAIN_DELETE = 18,
	MOSQ_EVT_PERSIST_CLIENT_ADD = 19,
	MOSQ_EVT_PERSIST_CLIENT_DELETE = 20,
	MOSQ_EVT_PERSIST_CLIENT_UPDATE = 21,
	MOSQ_EVT_PERSIST_SUBSCRIPTION_ADD = 22,
	MOSQ_EVT_PERSIST_SUBSCRIPTION_DELETE = 23,
	MOSQ_EVT_PERSIST_CLIENT_MSG_ADD = 24,
	MOSQ_EVT_PERSIST_CLIENT_MSG_DELETE = 25,
	MOSQ_EVT_PERSIST_CLIENT_MSG_UPDATE = 26,
	MOSQ_EVT_PERSIST_CLIENT_MSG_CLEAR = 27,
	MOSQ_EVT_PERSIST_CLIENT_MSG_LOAD = 28,
};

/* Data for the MOSQ_EVT_RELOAD event */
struct mosquitto_evt_reload {
	void *future;
	struct mosquitto_opt *options;
	int option_count;
	void *future2[4];
};

/* Data for the MOSQ_EVT_ACL_CHECK event */
struct mosquitto_evt_acl_check {
	void *future;
	struct mosquitto *client;
	const char *topic;
	const void *payload;
	mosquitto_property *properties;
	int access;
	uint32_t payloadlen;
	uint8_t qos;
	bool retain;
	void *future2[4];
};

/* Data for the MOSQ_EVT_BASIC_AUTH event */
struct mosquitto_evt_basic_auth {
	void *future;
	struct mosquitto *client;
	char *username;
	char *password;
	void *future2[4];
};

/* Data for the MOSQ_EVT_PSK_KEY event */
struct mosquitto_evt_psk_key {
	void *future;
	struct mosquitto *client;
	const char *hint;
	const char *identity;
	char *key;
	int max_key_len;
	void *future2[4];
};

/* Data for the MOSQ_EVT_EXTENDED_AUTH event */
struct mosquitto_evt_extended_auth {
	void *future;
	struct mosquitto *client;
	const void *data_in;
	void *data_out;
	uint16_t data_in_len;
	uint16_t data_out_len;
	const char *auth_method;
	void *future2[3];
};

/* Data for the MOSQ_EVT_CONTROL event */
struct mosquitto_evt_control {
	void *future;
	struct mosquitto *client;
	const char *topic;
	const void *payload;
	const mosquitto_property *properties;
	char *reason_string;
	uint32_t payloadlen;
	uint8_t qos;
	uint8_t reason_code;
	bool retain;
	void *future2[4];
};

/* Data for the MOSQ_EVT_MESSAGE event */
struct mosquitto_evt_message {
	void *future;
	struct mosquitto *client;
	char *topic;
	void *payload;
	mosquitto_property *properties;
	char *reason_string;
	uint32_t payloadlen;
	uint8_t qos;
	uint8_t reason_code;
	bool retain;
	void *future2[4];
};


/* Data for the MOSQ_EVT_TICK event */
struct mosquitto_evt_tick {
	void *future;
	long now_ns;
	long next_ms;
	time_t now_s;
	time_t next_s;
	void *future2[4];
};

/* Data for the MOSQ_EVT_CONNECT event */
struct mosquitto_evt_connect {
	void *future;
	struct mosquitto *client;
	void *future2[4];
};

/* Data for the MOSQ_EVT_DISCONNECT event */
struct mosquitto_evt_disconnect {
	void *future;
	struct mosquitto *client;
	int reason;
	void *future2[4];
};

/* Data for the MOSQ_EVT_PERSIST_RESTORE event */
/* NOTE: The persistence interface is currently marked as unstable, which means
 * it may change in a future minor release. */
struct mosquitto_evt_persist_restore {
	void *future[8];
};

/* Data for the MOSQ_EVT_PERSIST_CLIENT_ADD/_DELETE/_UPDATE event */
/* NOTE: The persistence interface is currently marked as unstable, which means
 * it may change in a future minor release. */
struct mosquitto_evt_persist_client {
	const char *client_id;
	const char *username;
	const char *auth_method;
	const struct mosquitto_message_v5 *will;
	char *plugin_client_id;
	char *plugin_username;
	char *plugin_auth_method;
	struct mosquitto_message_v5 *plugin_will;
	time_t will_delay_time; /* update */
	time_t session_expiry_time; /* update */
	uint32_t will_delay_interval;
	uint32_t session_expiry_interval;
	uint32_t max_packet_size;
	uint16_t listener_port;
	uint8_t max_qos;
	bool retain_available;
	uint8_t padding[6];
	void *future[8];
};


/* Data for the MOSQ_EVT_PERSIST_SUBSCRIPTION_ADD/_DELETE event */
/* NOTE: The persistence interface is currently marked as unstable, which means
 * it may change in a future minor release. */
struct mosquitto_evt_persist_subscription {
	const char *client_id;
	const char *topic;
	char *plugin_client_id;
	char *plugin_topic;
	uint32_t subscription_identifier;
	uint8_t subscription_options;
	uint8_t padding[3];
	void *future[8];
};


/* Data for the MOSQ_EVT_PERSIST_CLIENT_MSG_ADD/_DELETE/_UPDATE event */
/* NOTE: The persistence interface is currently marked as unstable, which means
 * it may change in a future minor release. */
struct mosquitto_evt_persist_client_msg {
	const char *client_id;
	char *plugin_client_id;
	uint64_t cmsg_id;
	uint64_t store_id;
	uint32_t subscription_identifier;
	uint16_t mid;
	uint8_t qos;
	bool retain;
	bool dup; /* add, update */
	uint8_t direction;
	uint8_t state; /* add, update */
	uint8_t padding[5];
	void *future[8];
};


/* Data for the MOSQ_EVT_PERSIST_MSG_ADD/_DELETE/_LOAD event */
/* NOTE: The persistence interface is currently marked as unstable, which means
 * it may change in a future minor release. */
struct mosquitto_evt_persist_msg {
	uint64_t store_id;
	int64_t expiry_time;
	const char *topic;
	const void *payload;
	const char *source_id;
	const char *source_username;
	char *plugin_topic;
	void *plugin_payload;
	char *plugin_source_id;
	char *plugin_source_username;
	const mosquitto_property *properties;
	mosquitto_property *plugin_properties;
	uint32_t payloadlen;
	uint16_t source_mid;
	uint16_t source_port;
	uint8_t qos;
	bool retain;
	uint8_t padding[6];
	void *future[8];
};


/* Data for the MOSQ_EVT_PERSIST_RETAIN/_DELETE event */
/* NOTE: The persistence interface is currently marked as unstable, which means
 * it may change in a future minor release. */
struct mosquitto_evt_persist_retain {
	const char *topic;
	char *plugin_topic;
	uint64_t store_id;
	void *future[8];
};


/* Callback definition */
typedef int (*MOSQ_FUNC_generic_callback)(int, void *, void *);

typedef struct mosquitto_plugin_id_t mosquitto_plugin_id_t;

/*
 * Function: mosquitto_plugin_set_info
 *
 * Set plugin name and version information for the broker to report. It is
 * recommended this is used in the mosquitto_plugin_init() call.
 */
mosq_EXPORT int mosquitto_plugin_set_info(
		mosquitto_plugin_id_t *identifier,
		const char *plugin_name,
		const char *plugin_version);


/*
 * Function: mosquitto_callback_register
 *
 * Register a callback for an event.
 *
 * Parameters:
 *  identifier - the plugin identifier, as provided by <mosquitto_plugin_init>.
 *  event - the event to register a callback for. Can be one of:
 *          * MOSQ_EVT_RELOAD
 *              Called when the broker is sent a signal indicating it should
 *              reload its configuration.
 *          * MOSQ_EVT_ACL_CHECK
 *              Called when a publish/subscribe/unsubscribe command is received
 *              and the broker wants to check when the client is allowed to carry
 *              out this command.
 *          * MOSQ_EVT_BASIC_AUTH
 *              Called when a client connects to the broker, to allow the
 *              username/password/clientid to be authenticated.
 *          * MOSQ_EVT_EXT_AUTH_START
 *              Called when an MQTT v5 client connects, if it is using extended
 *              authentication.
 *          * MOSQ_EVT_EXT_AUTH_CONTINUE
 *              Called when an MQTT v5 client connects, if it is using extended
 *              authentication.
 *          * MOSQ_EVT_CONTROL
 *              Called on receipt of a $CONTROL message that the plugin has
 *              registered for.
 *          * MOSQ_EVT_MESSAGE
 *              Called for each PUBLISH message after it has been received and
 *              authorised, but before it is sent to subscribing clients. The
 *              contents of the message can be modified.
 *          * MOSQ_EVT_PSK_KEY
 *              Called when a client connects with TLS-PSK and the broker needs
 *              the PSK information.
 *          * MOSQ_EVT_TICK
 *              Called periodically in the event loop. At the moment this
 *              occurs at a regular frequency, but this should not be relied
 *              upon.
 *          * MOSQ_EVT_DISCONNECT
 *              Called when a client disconnects from the broker.
 *          * MOSQ_EVT_CONNECT
 *              Called when a client has successfully connected to the broker,
 *              i.e. has been authenticated.
 *  cb_func - the callback function
 *  event_data - event specific data
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success
 *	MOSQ_ERR_INVAL - if cb_func is NULL
 *	MOSQ_ERR_NOMEM - on out of memory
 *	MOSQ_ERR_ALREADY_EXISTS - if cb_func has already been registered for this event
 *	MOSQ_ERR_NOT_SUPPORTED - if the event is not supported
 */
mosq_EXPORT int mosquitto_callback_register(
		mosquitto_plugin_id_t *identifier,
		int event,
		MOSQ_FUNC_generic_callback cb_func,
		const void *event_data,
		void *userdata);

/*
 * Function: mosquitto_callback_unregister
 *
 * Unregister a previously registered callback function.
 *
 * Parameters:
 *  identifier - the plugin identifier, as provided by <mosquitto_plugin_init>.
 *  event - the event to register a callback for. Can be one of:
 *          * MOSQ_EVT_RELOAD
 *          * MOSQ_EVT_ACL_CHECK
 *          * MOSQ_EVT_BASIC_AUTH
 *          * MOSQ_EVT_EXT_AUTH_START
 *          * MOSQ_EVT_EXT_AUTH_CONTINUE
 *          * MOSQ_EVT_CONTROL
 *          * MOSQ_EVT_MESSAGE
 *          * MOSQ_EVT_PSK_KEY
 *          * MOSQ_EVT_TICK
 *          * MOSQ_EVT_DISCONNECT
 *          * MOSQ_EVT_CONNECT
 *  cb_func - the callback function
 *  event_data - event specific data
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success
 *	MOSQ_ERR_INVAL - if cb_func is NULL
 *	MOSQ_ERR_NOT_FOUND - if cb_func was not registered for this event
 *	MOSQ_ERR_NOT_SUPPORTED - if the event is not supported
 */
mosq_EXPORT int mosquitto_callback_unregister(
		mosquitto_plugin_id_t *identifier,
		int event,
		MOSQ_FUNC_generic_callback cb_func,
		const void *event_data);


/* =========================================================================
 *
 * Section: Memory allocation.
 *
 * Use these functions when allocating or freeing memory to have your memory
 * included in the memory tracking on the broker.
 *
 * ========================================================================= */

/*
 * Function: mosquitto_calloc
 */
mosq_EXPORT void *mosquitto_calloc(size_t nmemb, size_t size);

/*
 * Function: mosquitto_free
 */
mosq_EXPORT void mosquitto_free(void *mem);

/*
 * Function: mosquitto_malloc
 */
mosq_EXPORT void *mosquitto_malloc(size_t size);

/*
 * Function: mosquitto_realloc
 */
mosq_EXPORT void *mosquitto_realloc(void *ptr, size_t size);

/*
 * Function: mosquitto_strdup
 */
mosq_EXPORT char *mosquitto_strdup(const char *s);

/* =========================================================================
 *
 * Section: Utility Functions
 *
 * Use these functions from within your plugin.
 *
 * ========================================================================= */


/*
 * Function: mosquitto_log_printf
 *
 * Write a log message using the broker configured logging.
 *
 * Parameters:
 * 	level -    Log message priority. Can currently be one of:
 *
 *             * MOSQ_LOG_INFO
 *             * MOSQ_LOG_NOTICE
 *             * MOSQ_LOG_WARNING
 *             * MOSQ_LOG_ERR
 *             * MOSQ_LOG_DEBUG
 *             * MOSQ_LOG_SUBSCRIBE (not recommended for use by plugins)
 *             * MOSQ_LOG_UNSUBSCRIBE (not recommended for use by plugins)
 *
 *             These values are defined in mosquitto.h.
 *
 *	fmt, ... - printf style format and arguments.
 */
mosq_EXPORT void mosquitto_log_printf(int level, const char *fmt, ...);


/* =========================================================================
 *
 * Client Functions
 *
 * Use these functions to access client information.
 *
 * ========================================================================= */

/*
 * Function: mosquitto_client_address
 *
 * Retrieve the IP address of the client as a string.
 */
mosq_EXPORT const char *mosquitto_client_address(const struct mosquitto *client);


/*
 * Function: mosquitto_client_address
 *
 * Retrieve the network port number the client connected to, or 0 on error.
 */
mosq_EXPORT int mosquitto_client_port(const struct mosquitto *client);


/*
 * Function: mosquitto_client_clean_session
 *
 * Retrieve the clean session flag value for a client.
 */
mosq_EXPORT bool mosquitto_client_clean_session(const struct mosquitto *client);


/*
 * Function: mosquitto_client_id
 *
 * Retrieve the client id associated with a client.
 */
mosq_EXPORT const char *mosquitto_client_id(const struct mosquitto *client);


/*
 * Function: mosquitto_client_keepalive
 *
 * Retrieve the keepalive value for a client.
 */
mosq_EXPORT int mosquitto_client_keepalive(const struct mosquitto *client);


/*
 * Function: mosquitto_client_certificate
 *
 * If TLS support is enabled, return the certificate provided by a client as an
 * X509 pointer from openssl. If the client did not provide a certificate, then
 * NULL will be returned. This function will only ever return a non-NULL value
 * if the `require_certificate` option is set to true.
 *
 * When you have finished with the x509 pointer, it must be freed using
 * X509_free().
 *
 * If TLS is not supported, this function will always return NULL.
 */
mosq_EXPORT void *mosquitto_client_certificate(const struct mosquitto *client);


/*
 * Function: mosquitto_client_protocol
 *
 * Retrieve the protocol with which the client has connected. Can be one of:
 *
 * mp_mqtt (MQTT over TCP)
 * mp_mqttsn (MQTT-SN)
 * mp_websockets (MQTT over Websockets)
 * mp_quic (MQTT over QUIC)
 */
mosq_EXPORT int mosquitto_client_protocol(const struct mosquitto *client);


/*
 * Function: mosquitto_client_protocol_version
 *
 * Retrieve the MQTT protocol version with which the client has connected. Can be one of:
 *
 * Returns:
 *   3 - for MQTT v3 / v3.1
 *   4 - for MQTT v3.1.1
 *   5 - for MQTT v5
 */
mosq_EXPORT int mosquitto_client_protocol_version(const struct mosquitto *client);


/*
 * Function: mosquitto_client_sub_count
 *
 * Retrieve the number of subscriptions that have been made by a client.
 */
mosq_EXPORT int mosquitto_client_sub_count(const struct mosquitto *client);


/*
 * Function: mosquitto_client_username
 *
 * Retrieve the username associated with a client.
 */
mosq_EXPORT const char *mosquitto_client_username(const struct mosquitto *client);


/* Function: mosquitto_set_username
 *
 * Set the username for a client.
 *
 * This removes and replaces the current username for a client and hence
 * updates its access.
 *
 * username can be NULL, in which case the client will become anonymous, but
 * must not be zero length.
 *
 * In the case of error, the client will be left with its original username.
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS - on success
 *   MOSQ_ERR_INVAL - if client is NULL, or if username is zero length
 *   MOSQ_ERR_NOMEM - on out of memory
 */
mosq_EXPORT int mosquitto_set_username(struct mosquitto *client, const char *username);


/* =========================================================================
 *
 * Section: Client control
 *
 * ========================================================================= */

/* Function: mosquitto_kick_client_by_clientid
 *
 * Forcefully disconnect a client from the broker.
 *
 * If clientid != NULL, then the client with the matching client id is
 *   disconnected from the broker.
 * If clientid == NULL, then all clients are disconnected from the broker.
 *
 * If with_will == true, then if the client has a Last Will and Testament
 *   defined then this will be sent. If false, the LWT will not be sent.
 */
mosq_EXPORT int mosquitto_kick_client_by_clientid(const char *clientid, bool with_will);

/* Function: mosquitto_kick_client_by_username
 *
 * Forcefully disconnect a client from the broker.
 *
 * If username != NULL, then all clients with a matching username are kicked
 *   from the broker.
 * If username == NULL, then all clients that do not have a username are
 *   kicked.
 *
 * If with_will == true, then if the client has a Last Will and Testament
 *   defined then this will be sent. If false, the LWT will not be sent.
 */
mosq_EXPORT int mosquitto_kick_client_by_username(const char *username, bool with_will);


/* =========================================================================
 *
 * Section: Publishing functions
 *
 * ========================================================================= */

/* Function: mosquitto_broker_publish
 *
 * Publish a message from within a plugin.
 *
 * This function allows a plugin to publish a message. Messages published in
 * this way are treated as coming from the broker and so will not be passed to
 * `mosquitto_auth_acl_check(, MOSQ_ACL_WRITE, , )` for checking. Read access
 * will be enforced as normal for individual clients when they are due to
 * receive the message.
 *
 * It can be used to send messages to all clients that have a matching
 * subscription, or to a single client whether or not it has a matching
 * subscription.
 *
 * Parameters:
 *  clientid -   optional string. If set to NULL, the message is delivered to all
 *               clients. If non-NULL, the message is delivered only to the
 *               client with the corresponding client id. If the client id
 *               specified is not connected, the message will be dropped.
 *  topic -      message topic
 *  payloadlen - payload length in bytes. Can be 0 for an empty payload.
 *  payload -    payload bytes. If payloadlen > 0 this must not be NULL. Must
 *               be allocated on the heap. Will be freed by mosquitto after use if the
 *               function returns success.
 *  qos -        message QoS to use.
 *  retain -     should retain be set on the message. This does not apply if
 *               clientid is non-NULL.
 *  properties - MQTT v5 properties to attach to the message. If the function
 *               returns success, then properties is owned by the broker and
 *               will be freed at a later point.
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS - on success
 *   MOSQ_ERR_INVAL - if topic is NULL, if payloadlen < 0, if payloadlen > 0
 *                    and payload is NULL, if qos is not 0, 1, or 2.
 *   MOSQ_ERR_NOMEM - on out of memory
 */
mosq_EXPORT int mosquitto_broker_publish(
		const char *clientid,
		const char *topic,
		int payloadlen,
		void *payload,
		int qos,
		bool retain,
		mosquitto_property *properties);


/* Function: mosquitto_broker_publish_copy
 *
 * Publish a message from within a plugin.
 *
 * This function is identical to mosquitto_broker_publish, except that a copy
 * of `payload` is taken.
 *
 * Parameters:
 *  clientid -   optional string. If set to NULL, the message is delivered to all
 *               clients. If non-NULL, the message is delivered only to the
 *               client with the corresponding client id. If the client id
 *               specified is not connected, the message will be dropped.
 *  topic -      message topic
 *  payloadlen - payload length in bytes. Can be 0 for an empty payload.
 *  payload -    payload bytes. If payloadlen > 0 this must not be NULL.
 *	             Memory remains the property of the calling function.
 *  qos -        message QoS to use.
 *  retain -     should retain be set on the message. This does not apply if
 *               clientid is non-NULL.
 *  properties - MQTT v5 properties to attach to the message. If the function
 *               returns success, then properties is owned by the broker and
 *               will be freed at a later point.
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS - on success
 *   MOSQ_ERR_INVAL - if topic is NULL, if payloadlen < 0, if payloadlen > 0
 *                    and payload is NULL, if qos is not 0, 1, or 2.
 *   MOSQ_ERR_NOMEM - on out of memory
 */
mosq_EXPORT int mosquitto_broker_publish_copy(
		const char *clientid,
		const char *topic,
		int payloadlen,
		const void *payload,
		int qos,
		bool retain,
		mosquitto_property *properties);

/* Function: mosquitto_complete_basic_auth
 *
 * Complete a delayed authentication request.
 *
 * Useful for plugins that subscribe to the MOSQ_EVT_BASIC_AUTH event. If your
 * plugin makes authentication requests that are not "instant", in particular
 * if they communicate with an external service, then instead of blocking for a
 * reply and returning MOSQ_ERR_SUCCESS or MOSQ_ERR_AUTH, the plugin can return
 * MOSQ_ERR_AUTH_DELAYED. This means that the plugin is promising to tell the
 * broker the authentication result in the future. Once the plugin has an
 * answer, it should call `mosquitto_complete_basic_auth()` passing the client
 * id and the result.
 *
 * Result:
 *  MOSQ_ERR_SUCCESS - the client successfully authenticated
 *  MOSQ_ERR_AUTH - the client authentication failed
 *
 * Other error codes can be used if more appropriate, and the client connection
 * will still be rejected, e.g. MOSQ_ERR_NOMEM.
 *
 * The plugin may use extra threads to handle the authentication requests, but
 * the call to `mosquitto_complete_basic_auth()` must happen in the main
 * mosquitto thread. Using the MOSQ_EVT_TICK event for this is suggested.
 */
mosq_EXPORT void mosquitto_complete_basic_auth(const char* client_id, int result);


/* Function: mosquitto_broker_node_id_set
 *
 * Set a node ID for this broker between 0-1023 inclusive. This is used to help
 * generate unique client message IDs and hence can be useful for persistence
 * plugins where brokers are sharing a database. It is down to the plugin to ensure
 * this ID is unique.
 *
 * Result:
 *  MOSQ_ERR_SUCCESS - on success
 *  MOSQ_ERR_INVAL - the value was > 1023.
 */
mosq_EXPORT int mosquitto_broker_node_id_set(uint16_t id);


/* =================================================================
 *
 * Persistence interface
 *
 * ================================================================= */

/* NOTE: The persistence interface is currently marked as unstable, which means
 * it may change in a future minor release. */


/* Function: mosquitto_persist_client_add
 *
 * Use to add a new client session, in particular when restoring on starting
 * the broker.
 *
 * Parameters:
 *   client->plugin_client_id - the client id of the client to add
 *          This must be allocated on the heap and becomes the property of the
 *          broker immediately this call is made. Must not be NULL.
 *   client->plugin_username - the username for the client session, or NULL. Must
 *          be allocated on the heap and becomes the property of the broker
 *          immediately this call is made.
 *   client->plugin_auth_method - the MQTT v5 extended authentication method,
 *          or NULL. Must be allocated on the heap and becomes the property of
 *          the broker immediately this call is made.
 *   client->clean_start - the new MQTT clean start parameter
 *   client->will_delay_time - the actual will delay time for this client
 *   client->session_expiry_time - the actual session expiry time for this
 *          client
 *   client->will_delay_interval - the MQTT v5 will delay interval for this
 *          client
 *   client->max_qos - the MQTT v5 maximum QoS parameter for this client
 *   client->maximum_packet_size - the MQTT v5 maximum packet size parameter
 *          for this client
 *   client->retain_available - the MQTT v5 retain available parameter for this
 *          client
 *   client->listener_port - the listener port that this client last connected to
 *
 *   All other members of struct mosquitto_evt_persist_client are unused.
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS - on success
 *   MOSQ_ERR_INVAL - if client or client->plugin_client_id is NULL, or if a
 *          client with the same ID already exists.
 *   MOSQ_ERR_NOMEM - on out of memory
 */
int mosquitto_persist_client_add(struct mosquitto_evt_persist_client *client);


/* Function: mosquitto_persist_client_update
 *
 * Use to update client session parameters
 *
 * Parameters:
 *   client->plugin_client_id - the client id of the client to update
 *          The broker will *not* modify this string and it remains the
 *          property of the plugin.
 *   client->username - the new username for the client session, or NULL. Must
 *          be allocated on the heap and becomes the property of the broker
 *          immediately this call is made.
 *   client->clean_start - the new MQTT clean start parameter
 *   client->will_delay_time - the actual will delay time for this client
 *   client->session_expiry_time - the actual session expiry time for this
 *          client
 *   client->will_delay_interval - the MQTT v5 will delay interval for this
 *          client
 *   client->max_qos - the MQTT v5 maximum QoS parameter for this client
 *   client->maximum_packet_size - the MQTT v5 maximum packet size parameter
 *          for this client
 *   client->retain_available - the MQTT v5 retain available parameter for this
 *          client
 *   client->listener_port - the listener port that this client last connected to
 *
 *   All other members of struct mosquitto_evt_persist_client are unused.
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS - on success
 *   MOSQ_ERR_INVAL - if client or client->plugin_client_id is NULL
 *   MOSQ_ERR_NOT_FOUND - the client is not found
 */
int mosquitto_persist_client_update(struct mosquitto_evt_persist_client *client);


/* Function: mosquitto_persist_client_delete
 *
 * Use to delete client session for a client from the broker
 *
 * Parameters:
 *   client_id - the client id of the client to delete
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS - on success
 *   MOSQ_ERR_INVAL - if client_id is NULL
 *   MOSQ_ERR_NOT_FOUND - the referenced client is not found
 */
int mosquitto_persist_client_delete(const char *client_id);


/* Function: mosquitto_persist_client_msg_add
 *
 * Use to add a client message for a particular client.
 *
 * Parameters:
 *   client_msg->plugin_client_id - the client id of the client that the
 *          message belongs to. The broker will *not* modify this string and it
 *          remains the property of the plugin.
 *   client_msg->store_id - the store ID of the stored message that this client
 *          message references.
 *   client_msg->cmsg_id - the client message id of the new message
 *   client_msg->mid - the MQTT message id of the new message
 *   client_msg->qos - the MQTT QoS of the new message
 *   client_msg->direction - the direction of the new message from the perspective
 *          of the broker (mosq_md_in / mosq_md_out)
 *   client_msg->retain - the retain flag of the message
 *   client_msg->subscription_identifier - the MQTT v5 subscription identifier,
 *          for outgoing messages only.
 *
 *   All other members of struct mosquitto_evt_persist_client_msg are unused.
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS - on success
 *   MOSQ_ERR_INVAL - if client_msg or client_msg->plugin_client_id is NULL
 *   MOSQ_ERR_NOT_FOUND - the client or stored message is not found
 */
int mosquitto_persist_client_msg_add(struct mosquitto_evt_persist_client_msg *client_msg);


/* Function: mosquitto_persist_client_msg_delete
 *
 * Use to delete a client message for a particular client.
 *
 * Parameters:
 *   client_msg->plugin_client_id - the client id of the client that the
 *          message belongs to. The broker will *not* modify this string and it
 *          remains the property of the plugin.
 *   client_msg->cmsg_id - the client message id of the affected message
 *   client_msg->mid - the MQTT message id of the affected message
 *   client_msg->qos - the MQTT QoS of the affected message
 *   client_msg->direction - the direction of the message from the perspective
 *          of the broker (mosq_md_in / mosq_md_out)
 *
 *   All other members of struct mosquitto_evt_persist_client_msg are unused.
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS - on success
 *   MOSQ_ERR_INVAL - if client_msg or client_msg->plugin_client_id is NULL
 *   MOSQ_ERR_NOT_FOUND - the client is not found
 */
int mosquitto_persist_client_msg_delete(struct mosquitto_evt_persist_client_msg *client_msg);


/* Function: mosquitto_persist_client_msg_update
 *
 * Use to update the state of a client message for a particular client.
 *
 * Parameters:
 *   client_msg->plugin_client_id - the client id of the client that the
 *          message belongs to. The broker will *not* modify this string and it
 *          remains the property of the plugin.
 *   client_msg->cmsg_id - the client message id of the affected message
 *   client_msg->mid - the MQTT message id of the affected message
 *   client_msg->qos - the MQTT QoS of the affected message
 *   client_msg->direction - the direction of the message from the perspective
 *          of the broker (mosq_md_in / mosq_md_out)
 *   client_msg->state - the new state of the message
 *
 *   All other members of struct mosquitto_evt_persist_client_msg are unused.
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS - on success
 *   MOSQ_ERR_INVAL - if client_msg or client_msg->plugin_client_id is NULL
 *   MOSQ_ERR_NOT_FOUND - the client is not found
 */
int mosquitto_persist_client_msg_update(struct mosquitto_evt_persist_client_msg *client_msg);


/* Function: mosquitto_persist_msg_add
 *
 * Use to add a new stored message. Any client messages or retained message
 * refering to this stored message must be added afterwards.
 *
 * Parameters:
 *   msg->store_id - the stored message ID
 *   msg->plugin_source_id - the client id of the client that the
 *          message originated with, or NULL.
 *          The broker will *not* modify this string and it remains the
 *          property of the plugin.
 *   msg->plugin_source_username - the username of the client that the
 *          message originated with, or NULL.
 *          The broker will *not* modify this string and it remains the
 *          property of the plugin.
 *   msg->topic - the message topic.
 *          Must be allocated on the heap and becomes the property of the
 *          broker immediately this call is made.
 *   msg->payload - the message payload.
 *          Must be allocated on the heap and becomes the property of the
 *          broker immediately this call is made.
 *   msg->payloadlen - the length of the payload, in bytes
 *   msg->expiry_time - the time at which the message expires, or 0.
 *   msg->properties - list of MQTT v5 message properties for this message.
 *          Must be allocated on the heap and becomes the property of the
 *          broker immediately this call is made.
 *   msg->retain - the message retain flag as delivered to the broker
 *   msg->qos - the message QoS as delivered to the broker
 *   msg->source_port - the network port number that the originating client was
 *          connected to, or 0.
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS - on success
 *   MOSQ_ERR_NOMEM - on out of memory
 */
int mosquitto_persist_msg_add(struct mosquitto_evt_persist_msg *msg);


/* Function: mosquitto_persist_msg_delete
 *
 * Use to delete a stored message.
 *
 * Parameters:
 *   store_id - the stored message ID
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS - on success
 */
int mosquitto_persist_msg_delete(uint64_t store_id);


/* Function: mosquitto_persist_subscription_add
 *
 * Use to add a new subscription for a client
 *
 * Parameters:
 *   client_id - the client id of the client the new subscription is for
 *   topic - the topic filter for the subscription
 *   subscription_options - the QoS and other flags for this subscription
 *   subscription_identifier - the MQTT v5 subscription id, or 0
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS - on success
 *   MOSQ_ERR_INVAL - if client_id or topic are NULL, or are zero length
 *   MOSQ_ERR_NOT_FOUND - the referenced client was not found
 *   MOSQ_ERR_NOMEM - on out of memory
 */
int mosquitto_subscription_add(const char *client_id, const char *topic, uint8_t subscription_options, uint32_t subscription_identifier);


/* Function: mosquitto_persist_subscription_delete
 *
 * Use to delete a subscription for a client
 *
 * Parameters:
 *   client_id - the client id of the client the new subscription is for
 *   topic - the topic filter for the subscription
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS - on success
 *   MOSQ_ERR_INVAL - if client_id or topic are NULL, or are zero length
 *   MOSQ_ERR_NOT_FOUND - the referenced client was not found
 *   MOSQ_ERR_NOMEM - on out of memory
 */
int mosquitto_subscription_delete(const char *client_id, const char *topic);


/* Function: mosquitto_persist_retain_add
 *
 * Use to add a retained message. It is not required to delete a retained
 * message for an existing topic first.
 *
 * Parameters:
 *   msg->plugin_topic - the topic that the message references
 *          The broker will *not* modify this string and it remains the
 *          property of the plugin.
 *   msg->store_id - the store id of the stored message that is to be retained
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS - on success
 *   MOSQ_ERR_INVAL - if msg or msg->plugin_topic are NULL
 *   MOSQ_ERR_NOT_FOUND - the referenced stored message was not found
 *   MOSQ_ERR_NOMEM - on out of memory
 */
int mosquitto_persist_retain_add(struct mosquitto_evt_persist_retain *retain);


/* Function: mosquitto_persist_retain_delete
 *
 * Use to delete a retained message.
 *
 * Parameters:
 *   msg->plugin_topic - the topic that the message references
 *          The broker will *not* modify this string and it remains the
 *          property of the plugin.
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS - on success
 *   MOSQ_ERR_INVAL - if msg or msg->plugin_topic are NULL
 *   MOSQ_ERR_NOMEM - on out of memory
 */
int mosquitto_persist_retain_delete(const char *topic);

#ifdef __cplusplus
}
#endif
#endif
