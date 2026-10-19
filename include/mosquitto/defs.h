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
*/

#ifndef MOSQUITTO_DEFS_H
#define MOSQUITTO_DEFS_H

/*
 * File: mosquitto/defs.h
 *
 * This header contains defines and enums used by the mosquitto broker and
 * libmosquitto, the Mosquitto client library.
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <mosquitto/mqtt_protocol.h>

/* Log types */
#define MOSQ_LOG_NONE           0
#define MOSQ_LOG_INFO           (1<<0)
#define MOSQ_LOG_NOTICE         (1<<1)
#define MOSQ_LOG_WARNING        (1<<2)
#define MOSQ_LOG_ERR            (1<<3)
#define MOSQ_LOG_DEBUG          (1<<4)
#define MOSQ_LOG_SUBSCRIBE      (1<<5)
#define MOSQ_LOG_UNSUBSCRIBE    (1<<6)
#define MOSQ_LOG_WEBSOCKETS     (1<<7)
#define MOSQ_LOG_INTERNAL       0x80000000U
#define MOSQ_LOG_ALL            0xFFFFFFFFU

/* Enum: mosq_err_t
 * Integer values returned from many libmosquitto functions. */
enum mosq_err_t {
	MOSQ_ERR_QUOTA_EXCEEDED = -6,
	MOSQ_ERR_AUTH_DELAYED = -5,
	MOSQ_ERR_AUTH_CONTINUE = -4,
	MOSQ_ERR_NO_SUBSCRIBERS = -3,
	MOSQ_ERR_SUB_EXISTS = -2,
	MOSQ_ERR_CONN_PENDING = -1,
	MOSQ_ERR_SUCCESS = 0,
	MOSQ_ERR_NOMEM = 1,
	MOSQ_ERR_PROTOCOL = 2,
	MOSQ_ERR_INVAL = 3,
	MOSQ_ERR_NO_CONN = 4,
	MOSQ_ERR_CONN_REFUSED = 5,
	MOSQ_ERR_NOT_FOUND = 6,
	MOSQ_ERR_CONN_LOST = 7,
	MOSQ_ERR_TLS = 8,
	MOSQ_ERR_PAYLOAD_SIZE = 9,
	MOSQ_ERR_NOT_SUPPORTED = 10,
	MOSQ_ERR_AUTH = 11,
	MOSQ_ERR_ACL_DENIED = 12,
	MOSQ_ERR_UNKNOWN = 13,
	MOSQ_ERR_ERRNO = 14,
	MOSQ_ERR_EAI = 15,
	MOSQ_ERR_PROXY = 16,
	MOSQ_ERR_PLUGIN_DEFER = 17,
	MOSQ_ERR_MALFORMED_UTF8 = 18,
	MOSQ_ERR_KEEPALIVE = 19,
	MOSQ_ERR_LOOKUP = 20,
	MOSQ_ERR_MALFORMED_PACKET = 21,
	MOSQ_ERR_DUPLICATE_PROPERTY = 22,
	MOSQ_ERR_TLS_HANDSHAKE = 23,
	MOSQ_ERR_QOS_NOT_SUPPORTED = 24,
	MOSQ_ERR_OVERSIZE_PACKET = 25,
	MOSQ_ERR_OCSP = 26,
	MOSQ_ERR_TIMEOUT = 27,
	/* 28, 29, 30 - was internal only, moved to MQTT v5 section. */
	MOSQ_ERR_ALREADY_EXISTS = 31,
	MOSQ_ERR_PLUGIN_IGNORE = 32,
	MOSQ_ERR_HTTP_BAD_ORIGIN = 33,
	MOSQ_ERR_AUTH_DENIED = 34,

	/* MQTT v5 direct equivalents 128-255 */
	MOSQ_ERR_UNSPECIFIED = 128,
	/* MOSQ_ERR_MALFORMED_PACKET = 129, // 21 above */
	MOSQ_ERR_IMPLEMENTATION_SPECIFIC = 131,
	MOSQ_ERR_UNSUPPORTED_PROTOCOL_VERSION = 132,
	MOSQ_ERR_CLIENT_IDENTIFIER_NOT_VALID = 133,
	MOSQ_ERR_BAD_USERNAME_OR_PASSWORD = 134,
	/* MOSQ_ERR_NOT_AUTHORIZED = 135, //  11 above */
	MOSQ_ERR_SERVER_UNAVAILABLE = 136,
	MOSQ_ERR_SERVER_BUSY = 137,
	MOSQ_ERR_BANNED = 138,
	MOSQ_ERR_SERVER_SHUTTING_DOWN = 139,
	MOSQ_ERR_BAD_AUTHENTICATION_METHOD = 140,
	/* MOSQ_ERR_KEEP_ALIVE_TIMEOUT = 141, // 19 above */
	MOSQ_ERR_SESSION_TAKEN_OVER = 142,
	MOSQ_ERR_TOPIC_FILTER_INVALID = 143,
	MOSQ_ERR_TOPIC_NAME_INVALID = 144,
	MOSQ_ERR_PACKET_ID_IN_USE = 145,
	MOSQ_ERR_PACKET_ID_NOT_FOUND = 146,
	MOSQ_ERR_RECEIVE_MAXIMUM_EXCEEDED = 147,
	MOSQ_ERR_TOPIC_ALIAS_INVALID = 148,
	/* MOSQ_ERR_PACKET_TOO_LARGE = 149, // 25 above */
	MOSQ_ERR_MESSAGE_RATE_TOO_HIGH = 150,
	/* MOSQ_ERR_QUOTA_EXCEEDED = 151, */
	MOSQ_ERR_ADMINISTRATIVE_ACTION = 152,
	MOSQ_ERR_PAYLOAD_FORMAT_INVALID = 153,
	MOSQ_ERR_RETAIN_NOT_SUPPORTED = 154,
	/* MOSQ_ERR_QOS_NOT_SUPPORTED = 155, // 24 above */
	MOSQ_ERR_USE_ANOTHER_SERVER = 156,
	MOSQ_ERR_SERVER_MOVED = 157,
	MOSQ_ERR_SHARED_SUBS_NOT_SUPPORTED = 158,
	MOSQ_ERR_CONNECTION_RATE_EXCEEDED = 159,
	MOSQ_ERR_MAXIMUM_CONNECT_TIME = 160,
	MOSQ_ERR_SUBSCRIPTION_IDS_NOT_SUPPORTED = 161,
	MOSQ_ERR_WILDCARD_SUBS_NOT_SUPPORTED = 162,
};

enum mosq_transport_t {
	MOSQ_T_TCP = 1,
	MOSQ_T_WEBSOCKETS = 2,
};

/* MQTT specification restricts client ids to a maximum of 23 characters */
#define MOSQ_MQTT_ID_MAX_LENGTH 23

#define MQTT_PROTOCOL_V31 3
#define MQTT_PROTOCOL_V311 4
#define MQTT_PROTOCOL_V5 5

struct mosquitto;
typedef struct mqtt5__property mosquitto_property;

#ifdef __cplusplus
}
#endif

#endif
