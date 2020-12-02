/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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

struct mosquitto;
typedef struct mqtt5__property mosquitto_property;

enum mosquitto_protocol {
	mp_mqtt,
	mp_mqttsn,
	mp_websockets
};

/* =========================================================================
 *
 * Register callbacks.
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
	void *future2[4];
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
	long next_ns;
	int now_s;
	int next_s;
	void *future2[4];
};

/* Data for the MOSQ_EVT_DISCONNECT event */
struct mosquitto_evt_disconnect {
	void *future;
	struct mosquitto *client;
	int reason;
	void *future2[4];
};


/* Callback definition */
typedef int (*MOSQ_FUNC_generic_callback)(int, void *, void *);

typedef struct mosquitto_plugin_id_t mosquitto_plugin_id_t;

/*
 * Function: mosquitto_callback_register
 */
mosq_EXPORT int mosquitto_callback_register(
		mosquitto_plugin_id_t *identifier,
		int event,
		MOSQ_FUNC_generic_callback cb_func,
		const void *event_data,
		void *userdata);

/*
 * Function: mosquitto_callback_unregister
 */
mosq_EXPORT int mosquitto_callback_unregister(
		mosquitto_plugin_id_t *identifier,
		int event,
		MOSQ_FUNC_generic_callback cb_func,
		const void *event_data);


/* =========================================================================
 *
 * Memory allocation.
 *
 * Use these functions when allocating or freeing memory to have your memory
 * included in the memory tracking on the broker.
 *
 * ========================================================================= */
mosq_EXPORT void *mosquitto_calloc(size_t nmemb, size_t size);
mosq_EXPORT void mosquitto_free(void *mem);
mosq_EXPORT void *mosquitto_malloc(size_t size);
mosq_EXPORT void *mosquitto_realloc(void *ptr, size_t size);
mosq_EXPORT char *mosquitto_strdup(const char *s);

/* =========================================================================
 *
 * Utility Functions
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
 *             MOSQ_LOG_INFO
 *             MOSQ_LOG_NOTICE
 *             MOSQ_LOG_WARNING
 *             MOSQ_LOG_ERR
 *             MOSQ_LOG_DEBUG
 *             MOSQ_LOG_SUBSCRIBE (not recommended for use by plugins)
 *             MOSQ_LOG_UNSUBSCRIBE (not recommended for use by plugins)
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
 */
mosq_EXPORT int mosquitto_client_protocol(const struct mosquitto *client);


/*
 * Function: mosquitto_client_protocol_version
 *
 * Retrieve the MQTT protocol version with which the client has connected. Can be one of:
 *
 * 3 - for MQTT v3 / v3.1
 * 4 - for MQTT v3.1.1
 * 5 - for MQTT v5
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
 * Client control
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
 * Publishing functions
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

#ifdef __cplusplus
}
#endif

#endif
