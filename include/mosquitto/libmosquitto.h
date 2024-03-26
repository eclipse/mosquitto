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

#ifndef MOSQUITTO_LIBMOSQUITTO_H
#define MOSQUITTO_LIBMOSQUITTO_H

/*
 * File: mosquitto/libmosquitto.h
 *
 * This header contains functions and definitions for use with libmosquitto, the Mosquitto client library.
 */
#ifdef __cplusplus
extern "C" {
#endif


#ifdef WIN32
#  ifndef LIBMOSQUITTO_STATIC
#    ifdef libmosquitto_EXPORTS
#      define libmosq_EXPORT  __declspec(dllexport)
#    else
#      define libmosq_EXPORT  __declspec(dllimport)
#    endif
#  else
#    define libmosq_EXPORT
#  endif
#else
#  define libmosq_EXPORT
#endif

#if defined(_MSC_VER) && _MSC_VER < 1900 && !defined(bool)
#	ifndef __cplusplus
#		define bool char
#		define true 1
#		define false 0
#	endif
#else
#	ifndef __cplusplus
#		include <stdbool.h>
#	endif
#endif

#include <stddef.h>
#include <stdint.h>

#include <mosquitto/defs.h>
#include <mosquitto/mqtt_protocol.h>

#define LIBMOSQUITTO_MAJOR 2
#define LIBMOSQUITTO_MINOR 1
#define LIBMOSQUITTO_REVISION 0
/* LIBMOSQUITTO_VERSION_NUMBER looks like 1002001 for e.g. version 1.2.1. */
#define LIBMOSQUITTO_VERSION_NUMBER (LIBMOSQUITTO_MAJOR*1000000+LIBMOSQUITTO_MINOR*1000+LIBMOSQUITTO_REVISION)

/* Enum: mosq_opt_t
 *
 * Client options.
 *
 * See <mosquitto_int_option>, <mosquitto_string_option>, and <mosquitto_void_option>.
 */
enum mosq_opt_t {
	MOSQ_OPT_PROTOCOL_VERSION = 1,
	MOSQ_OPT_SSL_CTX = 2,
	MOSQ_OPT_SSL_CTX_WITH_DEFAULTS = 3,
	MOSQ_OPT_RECEIVE_MAXIMUM = 4,
	MOSQ_OPT_SEND_MAXIMUM = 5,
	MOSQ_OPT_TLS_KEYFORM = 6,
	MOSQ_OPT_TLS_ENGINE = 7,
	MOSQ_OPT_TLS_ENGINE_KPASS_SHA1 = 8,
	MOSQ_OPT_TLS_OCSP_REQUIRED = 9,
	MOSQ_OPT_TLS_ALPN = 10,
	MOSQ_OPT_TCP_NODELAY = 11,
	MOSQ_OPT_BIND_ADDRESS = 12,
	MOSQ_OPT_TLS_USE_OS_CERTS = 13,
	MOSQ_OPT_DISABLE_SOCKETPAIR = 14,
	MOSQ_OPT_TRANSPORT = 15,
	MOSQ_OPT_HTTP_PATH = 16,
	MOSQ_OPT_HTTP_HEADER_SIZE = 17,
};

/* Struct: mosquitto_message
 *
 * Contains details of a PUBLISH message.
 *
 * int mid - the message/packet ID of the PUBLISH message, assuming this is a
 *           QoS 1 or 2 message. Will be set to 0 for QoS 0 messages.
 *
 * char *topic - the topic the message was delivered on.
 *
 * void *payload - the message payload. This will be payloadlen bytes long, and
 *                 may be NULL if a zero length payload was sent.
 *
 * int payloadlen - the length of the payload, in bytes.
 *
 * int qos - the quality of service of the message, 0, 1, or 2.
 *
 * bool retain - set to true for stale retained messages.
 */
struct mosquitto_message{
	int mid;
	char *topic;
	void *payload;
	int payloadlen;
	int qos;
	bool retain;
};

struct mosquitto_message_v5{
	void *payload;
	char *topic;
	mosquitto_property *properties;
	uint32_t payloadlen;
	uint8_t qos;
	bool retain;
	uint8_t padding[2];
};

/*
 * Topic: Threads
 *	libmosquitto provides thread safe operation, with the exception of
 *	<mosquitto_lib_init> which is not thread safe.
 *
 *	If the library has been compiled without thread support it is *not*
 *	guaranteed to be thread safe.
 *
 *	If your application uses threads you must use <mosquitto_threaded_set> to
 *	tell the library this is the case, otherwise it makes some optimisations
 *	for the single threaded case that may result in unexpected behaviour for
 *	the multi threaded case.
 */
/***************************************************
 * Important note
 *
 * The following functions that deal with network operations will return
 * MOSQ_ERR_SUCCESS on success, but this does not mean that the operation has
 * taken place. An attempt will be made to write the network data, but if the
 * socket is not available for writing at that time then the packet will not be
 * sent. To ensure the packet is sent, call mosquitto_loop() (which must also
 * be called to process incoming network data).
 * This is especially important when disconnecting a client that has a will. If
 * the broker does not receive the DISCONNECT command, it will assume that the
 * client has disconnected unexpectedly and send the will.
 *
 * mosquitto_connect()
 * mosquitto_disconnect()
 * mosquitto_subscribe()
 * mosquitto_unsubscribe()
 * mosquitto_publish()
 ***************************************************/


/* ======================================================================
 *
 * Section: Library version, init, and cleanup
 *
 * ====================================================================== */
/*
 * Function: mosquitto_lib_version
 *
 * Can be used to obtain version information for the mosquitto library.
 * This allows the application to compare the library version against the
 * version it was compiled against by using the LIBMOSQUITTO_MAJOR,
 * LIBMOSQUITTO_MINOR and LIBMOSQUITTO_REVISION defines.
 *
 * Parameters:
 *  major -    an integer pointer. If not NULL, the major version of the
 *             library will be returned in this variable.
 *  minor -    an integer pointer. If not NULL, the minor version of the
 *             library will be returned in this variable.
 *  revision - an integer pointer. If not NULL, the revision of the library will
 *             be returned in this variable.
 *
 * Returns:
 *	LIBMOSQUITTO_VERSION_NUMBER - which is a unique number based on the major,
 *		minor and revision values.
 * See Also:
 * 	<mosquitto_lib_cleanup>, <mosquitto_lib_init>
 */
libmosq_EXPORT int mosquitto_lib_version(int *major, int *minor, int *revision);

/*
 * Function: mosquitto_lib_init
 *
 * Must be called before any other mosquitto functions.
 *
 * This function is *not* thread safe.
 *
 * Returns:
 * 	MOSQ_ERR_SUCCESS - on success.
 * 	MOSQ_ERR_UNKNOWN - on Windows, if sockets couldn't be initialized.
 *
 * See Also:
 * 	<mosquitto_lib_cleanup>, <mosquitto_lib_version>
 */
libmosq_EXPORT int mosquitto_lib_init(void);

/*
 * Function: mosquitto_lib_cleanup
 *
 * Call to free resources associated with the library.
 *
 * Returns:
 * 	MOSQ_ERR_SUCCESS - always
 *
 * See Also:
 * 	<mosquitto_lib_init>, <mosquitto_lib_version>
 */
libmosq_EXPORT int mosquitto_lib_cleanup(void);

#include <mosquitto/libmosquitto_auth.h>
#include <mosquitto/libmosquitto_callbacks.h>
#include <mosquitto/libmosquitto_connect.h>
#include <mosquitto/libmosquitto_create_delete.h>
#include <mosquitto/libmosquitto_helpers.h>
#include <mosquitto/libmosquitto_loop.h>
#include <mosquitto/libmosquitto_message.h>
#include <mosquitto/libmosquitto_options.h>
#include <mosquitto/libmosquitto_publish.h>
#include <mosquitto/libmosquitto_socks.h>
#include <mosquitto/libmosquitto_subscribe.h>
#include <mosquitto/libmosquitto_tls.h>
#include <mosquitto/libmosquitto_unsubscribe.h>
#include <mosquitto/libmosquitto_will.h>

#ifdef __cplusplus
}
#endif

#endif
