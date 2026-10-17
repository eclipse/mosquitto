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

#ifndef MOSQUITTO_LIBMOSQUITTO_CALLBACKS_H
#define MOSQUITTO_LIBMOSQUITTO_CALLBACKS_H

/*
 * File: mosquitto/libmosquitto_callbacks.h
 *
 * This header contains functions for handling libmosquitto client callbacks.
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include <mosquitto/defs.h>
#include <mosquitto/mqtt_protocol.h>

/* ======================================================================
 *
 * Section: Callbacks
 *
 * ====================================================================== */
/*
 * Function: mosquitto_connect_callback_set
 *
 * Set the connect callback. This is called when the library receives a CONNACK
 * message in response to a connection.
 *
 * Parameters:
 *  mosq -       a valid mosquitto instance.
 *  on_connect - a callback function in the following form:
 *               void callback(struct mosquitto *mosq, void *obj, int rc)
 *
 * Callback Parameters:
 *  mosq - the mosquitto instance making the callback.
 *  obj - the user data provided in <mosquitto_new>
 *  rc -  the return code of the connection response. The values are defined by
 *        the MQTT protocol version in use.
 *        For MQTT v5.0, look at section 3.2.2.2 Connect Reason code: https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html
 *        For MQTT v3.1.1, look at section 3.2.2.3 Connect Return code: http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html
 *
 * See Also:
 *  <mosquitto_pre_connect_callback_set>
 */
typedef void (*LIBMOSQ_CB_connect)(struct mosquitto *mosq, void *obj, int rc);
libmosq_EXPORT void mosquitto_connect_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_connect on_connect);

/*
 * Function: mosquitto_connect_with_flags_callback_set
 *
 * Set the connect callback. This is called when the library receives a CONNACK
 * message in response to a connection.
 *
 * Parameters:
 *  mosq -       a valid mosquitto instance.
 *  on_connect - a callback function in the following form:
 *               void callback(struct mosquitto *mosq, void *obj, int rc)
 *
 * Callback Parameters:
 *  mosq - the mosquitto instance making the callback.
 *  obj - the user data provided in <mosquitto_new>
 *  rc -  the return code of the connection response. The values are defined by
 *        the MQTT protocol version in use.
 *        For MQTT v5.0, look at section 3.2.2.2 Connect Reason code: https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html
 *        For MQTT v3.1.1, look at section 3.2.2.3 Connect Return code: http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html
 *  flags - the connect flags.
 *
 * See Also:
 *  <mosquitto_pre_connect_callback_set>
 */
typedef void (*LIBMOSQ_CB_connect_with_flags)(struct mosquitto *mosq, void *obj, int rc, int flags);
libmosq_EXPORT void mosquitto_connect_with_flags_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_connect_with_flags on_connect);

/*
 * Function: mosquitto_connect_v5_callback_set
 *
 * Set the connect callback. This is called when the library receives a CONNACK
 * message in response to a connection.
 *
 * It is valid to set this callback for all MQTT protocol versions. If it is
 * used with MQTT clients that use MQTT v3.1.1 or earlier, then the `props`
 * argument will always be NULL.
 *
 * Parameters:
 *  mosq -       a valid mosquitto instance.
 *  on_connect - a callback function in the following form:
 *               void callback(struct mosquitto *mosq, void *obj, int rc)
 *
 * Callback Parameters:
 *  mosq - the mosquitto instance making the callback.
 *  obj - the user data provided in <mosquitto_new>
 *  rc -  the return code of the connection response. The values are defined by
 *        the MQTT protocol version in use.
 *        For MQTT v5.0, look at section 3.2.2.2 Connect Reason code: https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html
 *        For MQTT v3.1.1, look at section 3.2.2.3 Connect Return code: http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html
 *  flags - the connect flags.
 *  props - list of MQTT 5 properties, or NULL
 *
 * See Also:
 *  <mosquitto_pre_connect_callback_set>
 */
typedef void (*LIBMOSQ_CB_connect_v5)(struct mosquitto *mosq, void *obj, int rc, int flags, const mosquitto_property *props);
libmosq_EXPORT void mosquitto_connect_v5_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_connect_v5 on_connect);

/*
 * Function: mosquitto_pre_connect_callback_set
 *
 * Set the pre-connect callback. The pre-connect callback is called just before an attempt is made to connect to the broker. This may be useful if you are using <mosquitto_loop_start>, or
 * <mosquitto_loop_forever>, because when your client disconnects the library
 * will by default automatically reconnect. Using the pre-connect callback
 * allows you to set usernames, passwords, and TLS related parameters.
 *
 * Parameters:
 *  mosq -           a valid mosquitto instance.
 *  on_pre_connect - a callback function in the following form:
 *                   void callback(struct mosquitto *mosq, void *obj)
 *
 * Callback Parameters:
 *  mosq - the mosquitto instance making the callback.
 *  obj - the user data provided in <mosquitto_new>
 */
typedef void (*LIBMOSQ_CB_pre_connect)(struct mosquitto *mosq, void *obj);
libmosq_EXPORT void mosquitto_pre_connect_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_pre_connect on_pre_connect);

/*
 * Function: mosquitto_transport_open_callback_set
 *
 * Set the transport open callback. This is called whenever the library needs
 * a connection to the broker, for the initial connection and for every
 * reconnection, and must return an already connected socket. Use this with
 * <mosquitto_connect_transport> when the transport is provided by the
 * application, for example by a local proxy terminating TLS.
 *
 * The socket is owned by the library from then on and is set non-blocking. On
 * disconnection it is handed back to the transport close callback, or closed by
 * the library if no such callback is set. If the socket cannot be set
 * non-blocking the library closes it directly and takes no ownership, so the
 * transport close callback is not called for it.
 *
 * Parameters:
 *  mosq -              a valid mosquitto instance.
 *  on_transport_open - a callback function in the following form:
 *                      int callback(struct mosquitto *mosq, void *obj, int *sock)
 *
 * Callback Parameters:
 *  mosq - the mosquitto instance making the callback.
 *  obj -  the user data provided in <mosquitto_new>
 *  sock - where to store the connected socket.
 *
 * Callback Returns:
 *  MOSQ_ERR_SUCCESS - on success. Any other value is returned to the caller
 *                     of the connect function, e.g. MOSQ_ERR_ERRNO.
 */
typedef int (*LIBMOSQ_CB_transport_open)(struct mosquitto *mosq, void *obj, int *sock);
libmosq_EXPORT void mosquitto_transport_open_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_transport_open on_transport_open);

/*
 * Function: mosquitto_transport_close_callback_set
 *
 * Set the transport close callback. This is called whenever the library is
 * done with the socket it is connected on, in place of the library closing
 * that socket itself, so that an application providing its own transport can
 * tear it down. It is the counterpart of
 * <mosquitto_transport_open_callback_set>, and is called once for every
 * socket the library took from the transport open callback, whether the
 * connection ended through <mosquitto_disconnect>, an error, or
 * <mosquitto_destroy>.
 *
 * The callback is responsible for closing the socket. If no transport close
 * callback is set the library closes the socket itself.
 *
 * The callback is called for whichever socket the library is connected on, so
 * it is only useful alongside <mosquitto_connect_transport>.
 *
 * Parameters:
 *  mosq -               a valid mosquitto instance.
 *  on_transport_close - a callback function in the following form:
 *                       int callback(struct mosquitto *mosq, void *obj, int sock)
 *
 * Callback Parameters:
 *  mosq - the mosquitto instance making the callback.
 *  obj -  the user data provided in <mosquitto_new>
 *  sock - the socket to close, as returned by the transport open callback.
 *
 * Callback Returns:
 *  0 - on success. Any other value is treated as a close failure, as for
 *      close().
 *
 * See Also:
 *  <mosquitto_transport_open_callback_set>, <mosquitto_connect_transport>
 */
typedef int (*LIBMOSQ_CB_transport_close)(struct mosquitto *mosq, void *obj, int sock);
libmosq_EXPORT void mosquitto_transport_close_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_transport_close on_transport_close);

/*
 * Function: mosquitto_disconnect_callback_set
 *
 * Set the disconnect callback. This is called when the broker has received the
 * DISCONNECT command and has disconnected the client.
 *
 * Parameters:
 *  mosq -          a valid mosquitto instance.
 *  on_disconnect - a callback function in the following form:
 *                  void callback(struct mosquitto *mosq, void *obj)
 *
 * Callback Parameters:
 *  mosq - the mosquitto instance making the callback.
 *  obj -  the user data provided in <mosquitto_new>
 *  rc -   integer value indicating the reason for the disconnect. A value of 0
 *         means the client has called <mosquitto_disconnect>. Any other value
 *         indicates that the disconnect is unexpected.
 */
typedef void (*LIBMOSQ_CB_disconnect)(struct mosquitto *mosq, void *obj, int rc);
libmosq_EXPORT void mosquitto_disconnect_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_disconnect on_disconnect);

/*
 * Function: mosquitto_disconnect_v5_callback_set
 *
 * Set the disconnect callback. This is called when the broker has received the
 * DISCONNECT command and has disconnected the client.
 *
 * It is valid to set this callback for all MQTT protocol versions. If it is
 * used with MQTT clients that use MQTT v3.1.1 or earlier, then the `props`
 * argument will always be NULL.
 *
 * Parameters:
 *  mosq -          a valid mosquitto instance.
 *  on_disconnect - a callback function in the following form:
 *                  void callback(struct mosquitto *mosq, void *obj)
 *
 * Callback Parameters:
 *  mosq - the mosquitto instance making the callback.
 *  obj -  the user data provided in <mosquitto_new>
 *  rc -   integer value indicating the reason for the disconnect. A value of 0
 *         means the client has called <mosquitto_disconnect>. Any other value
 *         indicates that the disconnect is unexpected.
 *  props - list of MQTT 5 properties, or NULL
 */
typedef void (*LIBMOSQ_CB_disconnect_v5)(struct mosquitto *mosq, void *obj, int rc, const mosquitto_property *props);
libmosq_EXPORT void mosquitto_disconnect_v5_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_disconnect_v5 on_disconnect);

/*
 * Function: mosquitto_publish_callback_set
 *
 * Set the publish callback. This is called when a message initiated with
 * <mosquitto_publish> has been sent to the broker. "Sent" means different
 * things depending on the QoS of the message:
 *
 * QoS 0: The PUBLISH was passed to the local operating system for delivery,
 *        there is no guarantee that it was delivered to the remote broker.
 * QoS 1: The PUBLISH was sent to the remote broker and the corresponding
 *        PUBACK was received by the library.
 * QoS 2: The PUBLISH was sent to the remote broker and the corresponding
 *        PUBCOMP was received by the library.
 *
 * Parameters:
 *  mosq -       a valid mosquitto instance.
 *  on_publish - a callback function in the following form:
 *               void callback(struct mosquitto *mosq, void *obj, int mid)
 *
 * Callback Parameters:
 *  mosq - the mosquitto instance making the callback.
 *  obj -  the user data provided in <mosquitto_new>
 *  mid -  the message id of the sent message.
 */
typedef void (*LIBMOSQ_CB_publish)(struct mosquitto *mosq, void *obj, int mid);
libmosq_EXPORT void mosquitto_publish_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_publish on_publish);

/*
 * Function: mosquitto_publish_v5_callback_set
 *
 * Set the publish callback. This is called when a message initiated with
 * <mosquitto_publish> has been sent to the broker. This callback will be
 * called both if the message is sent successfully, or if the broker responded
 * with an error, which will be reflected in the reason_code parameter.
 * "Sent" means different things depending on the QoS of the message:
 *
 * QoS 0: The PUBLISH was passed to the local operating system for delivery,
 *        there is no guarantee that it was delivered to the remote broker.
 * QoS 1: The PUBLISH was sent to the remote broker and the corresponding
 *        PUBACK was received by the library.
 * QoS 2: The PUBLISH was sent to the remote broker and the corresponding
 *        PUBCOMP was received by the library.
 *
 *
 * It is valid to set this callback for all MQTT protocol versions. If it is
 * used with MQTT clients that use MQTT v3.1.1 or earlier, then the `props`
 * argument will always be NULL.
 *
 * Parameters:
 *  mosq -       a valid mosquitto instance.
 *  on_publish - a callback function in the following form:
 *               void callback(struct mosquitto *mosq, void *obj, int mid)
 *
 * Callback Parameters:
 *  mosq - the mosquitto instance making the callback.
 *  obj -  the user data provided in <mosquitto_new>
 *  mid -  the message id of the sent message.
 *  reason_code - the MQTT 5 reason code
 *  props - list of MQTT 5 properties, or NULL
 */
typedef void (*LIBMOSQ_CB_publish_v5)(struct mosquitto *mosq, void *obj, int mid, int reason_code, const mosquitto_property *props);
libmosq_EXPORT void mosquitto_publish_v5_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_publish_v5 on_publish);

/*
 * Function: mosquitto_message_callback_set
 *
 * Set the message callback. This is called when a message is received from the
 * broker and the required QoS flow has completed.
 *
 * Parameters:
 *  mosq -       a valid mosquitto instance.
 *  on_message - a callback function in the following form:
 *               void callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
 *
 * Callback Parameters:
 *  mosq -    the mosquitto instance making the callback.
 *  obj -     the user data provided in <mosquitto_new>
 *  message - the message data. This variable and associated memory will be
 *            freed by the library after the callback completes. The client
 *            should make copies of any of the data it requires.
 *
 * See Also:
 * 	<mosquitto_message_copy>
 */
typedef void (*LIBMOSQ_CB_message)(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message);
libmosq_EXPORT void mosquitto_message_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_message on_message);

/*
 * Function: mosquitto_message_v5_callback_set
 *
 * Set the message callback. This is called when a message is received from the
 * broker and the required QoS flow has completed.
 *
 * It is valid to set this callback for all MQTT protocol versions. If it is
 * used with MQTT clients that use MQTT v3.1.1 or earlier, then the `props`
 * argument will always be NULL.
 *
 * Parameters:
 *  mosq -       a valid mosquitto instance.
 *  on_message - a callback function in the following form:
 *               void callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
 *
 * Callback Parameters:
 *  mosq -    the mosquitto instance making the callback.
 *  obj -     the user data provided in <mosquitto_new>
 *  message - the message data. This variable and associated memory will be
 *            freed by the library after the callback completes. The client
 *            should make copies of any of the data it requires.
 *  props - list of MQTT 5 properties, or NULL
 *
 * See Also:
 * 	<mosquitto_message_copy>
 */
typedef void (*LIBMOSQ_CB_message_v5)(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message, const mosquitto_property *props);
libmosq_EXPORT void mosquitto_message_v5_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_message_v5 on_message);

/*
 * Function: mosquitto_subscribe_callback_set
 *
 * Set the subscribe callback. This is called when the library receives a
 * SUBACK message in response to a SUBSCRIBE.
 *
 * Parameters:
 *  mosq -         a valid mosquitto instance.
 *  on_subscribe - a callback function in the following form:
 *                 void callback(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
 *
 * Callback Parameters:
 *  mosq -        the mosquitto instance making the callback.
 *  obj -         the user data provided in <mosquitto_new>
 *  mid -         the message id of the subscribe message.
 *  qos_count -   the number of granted subscriptions (size of granted_qos).
 *  granted_qos - an array of integers indicating the granted QoS for each of
 *                the subscriptions.
 */
typedef void (*LIBMOSQ_CB_subscribe)(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos);
libmosq_EXPORT void mosquitto_subscribe_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_subscribe on_subscribe);

/*
 * Function: mosquitto_subscribe_v5_callback_set
 *
 * Set the subscribe callback. This is called when the library receives a
 * SUBACK message in response to a SUBSCRIBE.
 *
 * It is valid to set this callback for all MQTT protocol versions. If it is
 * used with MQTT clients that use MQTT v3.1.1 or earlier, then the `props`
 * argument will always be NULL.
 *
 * Parameters:
 *  mosq -         a valid mosquitto instance.
 *  on_subscribe - a callback function in the following form:
 *                 void callback(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
 *
 * Callback Parameters:
 *  mosq -        the mosquitto instance making the callback.
 *  obj -         the user data provided in <mosquitto_new>
 *  mid -         the message id of the subscribe message.
 *  qos_count -   the number of granted subscriptions (size of granted_qos).
 *  granted_qos - an array of integers indicating the granted QoS for each of
 *                the subscriptions.
 *  props - list of MQTT 5 properties, or NULL
 */
typedef void (*LIBMOSQ_CB_subscribe_v5)(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos, const mosquitto_property *props);
libmosq_EXPORT void mosquitto_subscribe_v5_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_subscribe_v5 on_subscribe);

/*
 * Function: mosquitto_unsubscribe_callback_set
 *
 * Set the unsubscribe callback. This is called when the library receives a
 * UNSUBACK message in response to an UNSUBSCRIBE.
 *
 * Parameters:
 *  mosq -           a valid mosquitto instance.
 *  on_unsubscribe - a callback function in the following form:
 *                   void callback(struct mosquitto *mosq, void *obj, int mid)
 *
 * Callback Parameters:
 *  mosq - the mosquitto instance making the callback.
 *  obj -  the user data provided in <mosquitto_new>
 *  mid -  the message id of the unsubscribe message.
 */
typedef void (*LIBMOSQ_CB_unsubscribe)(struct mosquitto *mosq, void *obj, int mid);
libmosq_EXPORT void mosquitto_unsubscribe_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_unsubscribe on_unsubscribe);

/*
 * Function: mosquitto_unsubscribe_v5_callback_set
 *
 * Set the unsubscribe callback. This is called when the library receives a
 * UNSUBACK message in response to an UNSUBSCRIBE.
 *
 * It is valid to set this callback for all MQTT protocol versions. If it is
 * used with MQTT clients that use MQTT v3.1.1 or earlier, then the `props`
 * argument will always be NULL.
 *
 * Parameters:
 *  mosq -           a valid mosquitto instance.
 *  on_unsubscribe - a callback function in the following form:
 *                   void callback(struct mosquitto *mosq, void *obj, int mid, const mosquitto_property *props)
 *
 * Callback Parameters:
 *  mosq - the mosquitto instance making the callback.
 *  obj -  the user data provided in <mosquitto_new>
 *  mid -  the message id of the unsubscribe message.
 *  props - list of MQTT 5 properties, or NULL
 */
typedef void (*LIBMOSQ_CB_unsubscribe_v5)(struct mosquitto *mosq, void *obj, int mid, const mosquitto_property *props);
libmosq_EXPORT void mosquitto_unsubscribe_v5_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_unsubscribe_v5 on_unsubscribe);

/*
 * Function: mosquitto_unsubscribe2_v5_callback_set
 *
 * Set the unsubscribe callback. This is called when the library receives a
 * UNSUBACK message in response to an UNSUBSCRIBE.
 *
 * It is valid to set this callback for all MQTT protocol versions. If it is
 * used with MQTT clients that use MQTT v3.1.1 or earlier, then the `props`
 * argument will always be NULL.
 *
 * Parameters:
 *  mosq -           a valid mosquitto instance.
 *  on_unsubscribe - a callback function in the following form:
 *                   void callback(struct mosquitto *mosq, void *obj, int mid,
 *                   int reason_code_count, const int *reason_codes, const mosquitto_property *props)
 *
 * Callback Parameters:
 *  mosq -              the mosquitto instance making the callback.
 *  obj -               the user data provided in <mosquitto_new>
 *  mid -               the message id of the unsubscribe message.
 *  reason_code_count - the count of reason code responses
 *  reason_codes -      an array of integers indicating the reason codes for each of
 *                      the unsubscription requests.
 *  mid -               the message id of the unsubscribe message.
 *  props -             list of MQTT 5 properties, or NULL
 */
typedef void (*LIBMOSQ_CB_unsubscribe2_v5)(struct mosquitto *mosq, void *obj, int mid, int reason_code_count, const int *reason_codes, const mosquitto_property *props);
libmosq_EXPORT void mosquitto_unsubscribe2_v5_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_unsubscribe2_v5 on_unsubscribe);

/*
 * Function: mosquitto_ext_auth_callback_set
 *
 * Set the callback for extended authentication. This should be used if you
 * want to support MQTT v5.0 extended authentication.
 *
 *  mosq -        a valid mosquitto instance.
 *  on_ext_auth - a callback function in the following form:
 *                void callback(struct mosquitto *mosq, void *obj, const char *auth_method, int auth_data_len, const void *auth_data, const mosquitto_property *props)
 *
 * Callback Parameters:
 *  mosq -          the mosquitto instance making the callback.
 *  obj -           the user data provided in <mosquitto_new>
 *  auth_method -   the authentication method provided by the broker
 *  auth_data_len - the length of auth_data in bytes
 *  auth_data -     the authentication data, or NULL
 *  props -         list of MQTT 5 properties sent
 *                  note that this includes the auth-method and auth-data
 *                  properties, so you cannot use it directly with
 *                  mosquitto_ext_auth_continue and must instead create your
 *                  own property list
 *
 * Callback Return:
 *  MOSQ_ERR_SUCCESS - if you accept the authentication data
 *  MOSQ_ERR_AUTH    - if the authentication should fail
 *  MOSQ_ERR_NOMEM   - on out of memory
 *
 * See Also:
 *    <mosquitto_ext_auth_continue>
 */
typedef int (*LIBMOSQ_CB_ext_auth)(struct mosquitto *mosq, void *obj, const char *auth_method, uint16_t auth_data_len, const void *auth_data, const mosquitto_property *props);
libmosq_EXPORT void mosquitto_ext_auth_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_ext_auth on_ext_auth);

/*
 * Function: mosquitto_log_callback_set
 *
 * Set the logging callback. This should be used if you want event logging
 * information from the client library.
 *
 *  mosq -   a valid mosquitto instance.
 *  on_log - a callback function in the following form:
 *           void callback(struct mosquitto *mosq, void *obj, int level, const char *str)
 *
 * Callback Parameters:
 *  mosq -  the mosquitto instance making the callback.
 *  obj -   the user data provided in <mosquitto_new>
 *  level - the log message level from the values:
 *	        MOSQ_LOG_INFO
 *	        MOSQ_LOG_NOTICE
 *	        MOSQ_LOG_WARNING
 *	        MOSQ_LOG_ERR
 *	        MOSQ_LOG_DEBUG
 *	str -   the message string.
 */
typedef void (*LIBMOSQ_CB_log)(struct mosquitto *mosq, void *obj, int level, const char *str);
libmosq_EXPORT void mosquitto_log_callback_set(struct mosquitto *mosq, LIBMOSQ_CB_log on_log);

#ifdef __cplusplus
}
#endif

#endif
