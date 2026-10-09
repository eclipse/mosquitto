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

#ifndef MOSQUITTO_LIBMOSQUITTO_CONNECT_H
#define MOSQUITTO_LIBMOSQUITTO_CONNECT_H

/*
 * File: mosquitto/libmosquitto_connect.h
 *
 * This header contains functions for connect/disconnecting/reconnectng clients in libmosquitto.
 */
#ifdef __cplusplus
extern "C" {
#endif

/* ======================================================================
 *
 * Section: Connecting, reconnecting, disconnecting
 *
 * ====================================================================== */
/*
 * Function: mosquitto_connect
 *
 * Connect to an MQTT broker.
 *
 * It is valid to use this function for clients using all MQTT protocol versions.
 * If you need to set MQTT v5 CONNECT properties, use <mosquitto_connect_bind_v5>
 * instead.
 *
 * Parameters:
 * 	mosq -      a valid mosquitto instance.
 * 	host -      the hostname or ip address of the broker to connect to.
 * 	port -      the network port to connect to. Usually 1883.
 * 	keepalive - the number of seconds after which the client should send a PING
 *              message to the broker if no other messages have been exchanged
 *              in that time.
 *
 * Returns:
 * 	MOSQ_ERR_SUCCESS - on success.
 * 	MOSQ_ERR_INVAL -   if the input parameters were invalid, which could be any of:
 * 	                   * mosq == NULL
 * 	                   * host == NULL
 * 	                   * port < 0
 * 	                   * keepalive < 2 (keepalive == 0 is allowed, for an infinite keepalive)
 * 	MOSQ_ERR_ERRNO -   if a system call returned an error. The variable errno
 *                     contains the error code, even on Windows.
 *                     Use strerror_r() where available or FormatMessage() on
 *                     Windows.
 *
 * See Also:
 * 	<mosquitto_connect_bind>, <mosquitto_connect_async>, <mosquitto_reconnect>, <mosquitto_disconnect>, <mosquitto_tls_set>
 */
libmosq_EXPORT int mosquitto_connect(struct mosquitto *mosq, const char *host, int port, int keepalive);

/*
 * Function: mosquitto_connect_bind
 *
 * Connect to an MQTT broker. This extends the functionality of
 * <mosquitto_connect> by adding the bind_address parameter. Use this function
 * if you need to restrict network communication over a particular interface.
 *
 * Parameters:
 * 	mosq -         a valid mosquitto instance.
 * 	host -         the hostname or ip address of the broker to connect to.
 * 	port -         the network port to connect to. Usually 1883.
 * 	keepalive -    the number of seconds after which the client should send a PING
 *                 message to the broker if no other messages have been exchanged
 *                 in that time.
 *  bind_address - the hostname or ip address of the local network interface to
 *                 bind to. If you do not want to bind to a specific interface,
 *                 set this to NULL.
 *
 * Returns:
 * 	MOSQ_ERR_SUCCESS - on success.
 * 	MOSQ_ERR_INVAL -   if the input parameters were invalid.
 * 	MOSQ_ERR_ERRNO -   if a system call returned an error. The variable errno
 *                     contains the error code, even on Windows.
 *                     Use strerror_r() where available or FormatMessage() on
 *                     Windows.
 *
 * See Also:
 * 	<mosquitto_connect>, <mosquitto_connect_async>, <mosquitto_connect_bind_async>
 */
libmosq_EXPORT int mosquitto_connect_bind(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address);

/*
 * Function: mosquitto_connect_bind_v5
 *
 * Connect to an MQTT broker. This extends the functionality of
 * <mosquitto_connect> by adding the bind_address parameter and MQTT v5
 * properties. Use this function if you need to restrict network communication
 * over a particular interface.
 *
 * Use e.g. <mosquitto_property_add_string> and similar to create a list of
 * properties, then attach them to this connect. Properties need freeing with
 * <mosquitto_property_free_all>.
 *
 * If the mosquitto instance `mosq` is using MQTT v5, the `properties` argument
 * will be applied to the CONNECT message. For MQTT v3.1.1 and below, the
 * `properties` argument will be ignored.
 *
 * Set your client to use MQTT v5 immediately after it is created:
 *
 * mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);
 *
 * Parameters:
 * 	mosq -         a valid mosquitto instance.
 * 	host -         the hostname or ip address of the broker to connect to.
 * 	port -         the network port to connect to. Usually 1883.
 * 	keepalive -    the number of seconds after which the client should send a PING
 *                 message to the broker if no other messages have been exchanged
 *                 in that time.
 *  bind_address - the hostname or ip address of the local network interface to
 *                 bind to. If you do not want to bind to a specific interface,
 *                 set this to NULL.
 *  properties - the MQTT 5 properties for the connect (not for the Will).
 *
 * Returns:
 * 	MOSQ_ERR_SUCCESS - on success.
 * 	MOSQ_ERR_INVAL -   if the input parameters were invalid, which could be any of:
 * 	                   * mosq == NULL
 * 	                   * host == NULL
 * 	                   * port < 0
 * 	                   * keepalive < 5 (keepalive == 0 is allowed, for an infinite keepalive)
 * 	MOSQ_ERR_ERRNO -   if a system call returned an error. The variable errno
 *                     contains the error code, even on Windows.
 *                     Use strerror_r() where available or FormatMessage() on
 *                     Windows.
 *	MOSQ_ERR_DUPLICATE_PROPERTY - if a property is duplicated where it is forbidden.
 *	MOSQ_ERR_PROTOCOL - if any property is invalid for use with CONNECT.
 *
 * See Also:
 * 	<mosquitto_connect>, <mosquitto_connect_async>, <mosquitto_connect_bind_async>,
 * 	<mosquitto_connect_bind_v5_async>
 */
libmosq_EXPORT int mosquitto_connect_bind_v5(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address, const mosquitto_property *properties);

/*
 * Function: mosquitto_connect_bind_v5_async
 *
 * Connect to an MQTT broker. This is a non-blocking call. If you use
 * <mosquitto_connect_async> your client must use the threaded interface
 * <mosquitto_loop_start>. If you need to use <mosquitto_loop>, you must use
 * <mosquitto_connect> to connect the client.
 *
 * May be called before or after <mosquitto_loop_start>.
 *
 * This extends the functionality of
 * <mosquitto_connect_async> by adding the bind_address parameter and MQTT v5
 * properties. Use this function if you need to restrict network communication
 * over a particular interface.
 *
 * Use e.g. <mosquitto_property_add_string> and similar to create a list of
 * properties, then attach them to this connect. Properties need freeing with
 * <mosquitto_property_free_all>.
 *
 * If the mosquitto instance `mosq` is using MQTT v5, the `properties` argument
 * will be applied to the CONNECT message. For MQTT v3.1.1 and below, the
 * `properties` argument will be ignored.
 *
 * Set your client to use MQTT v5 immediately after it is created:
 *
 * mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);
 *
 * Parameters:
 * 	mosq -         a valid mosquitto instance.
 * 	host -         the hostname or ip address of the broker to connect to.
 * 	port -         the network port to connect to. Usually 1883.
 * 	keepalive -    the number of seconds after which the client should send a PING
 *                 message to the broker if no other messages have been exchanged
 *                 in that time.
 *  bind_address - the hostname or ip address of the local network interface to
 *                 bind to. If you do not want to bind to a specific interface,
 *                 set this to NULL.
 *  properties - the MQTT 5 properties for the connect (not for the Will).
 *
 * Returns:
 * 	MOSQ_ERR_SUCCESS - on success.
 * 	MOSQ_ERR_INVAL -   if the input parameters were invalid, which could be any of:
 * 	                   * mosq == NULL
 * 	                   * host == NULL
 * 	                   * port < 0
 * 	                   * keepalive < 5 (keepalive == 0 is allowed, for an infinite keepalive)
 * 	MOSQ_ERR_ERRNO -   if a system call returned an error. The variable errno
 *                     contains the error code, even on Windows.
 *                     Use strerror_r() where available or FormatMessage() on
 *                     Windows.
 *	MOSQ_ERR_DUPLICATE_PROPERTY - if a property is duplicated where it is forbidden.
 *	MOSQ_ERR_PROTOCOL - if any property is invalid for use with CONNECT.
 *
 * See Also:
 * 	<mosquitto_connect>, <mosquitto_connect_async>, <mosquitto_connect_bind_async>,
 * 	<mosquitto_connect_bind_v5>
 */
libmosq_EXPORT int mosquitto_connect_bind_v5_async(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address, const mosquitto_property *properties);

/*
 * Function: mosquitto_connect_async
 *
 * Connect to an MQTT broker. This is a non-blocking call. If you use
 * <mosquitto_connect_async> your client must use the threaded interface
 * <mosquitto_loop_start>. If you need to use <mosquitto_loop>, you must use
 * <mosquitto_connect> to connect the client.
 *
 * May be called before or after <mosquitto_loop_start>.
 *
 * Parameters:
 * 	mosq -      a valid mosquitto instance.
 * 	host -      the hostname or ip address of the broker to connect to.
 * 	port -      the network port to connect to. Usually 1883.
 * 	keepalive - the number of seconds after which the client should send a PING
 *              message to the broker if no other messages have been exchanged
 *              in that time.
 *
 * Returns:
 * 	MOSQ_ERR_SUCCESS - on success.
 * 	MOSQ_ERR_INVAL -   if the input parameters were invalid.
 * 	MOSQ_ERR_ERRNO -   if a system call returned an error. The variable errno
 *                     contains the error code, even on Windows.
 *                     Use strerror_r() where available or FormatMessage() on
 *                     Windows.
 *
 * See Also:
 * 	<mosquitto_connect_bind_async>, <mosquitto_connect>, <mosquitto_reconnect>, <mosquitto_disconnect>, <mosquitto_tls_set>
 */
libmosq_EXPORT int mosquitto_connect_async(struct mosquitto *mosq, const char *host, int port, int keepalive);

/*
 * Function: mosquitto_connect_bind_async
 *
 * Connect to an MQTT broker. This is a non-blocking call. If you use
 * <mosquitto_connect_bind_async> your client must use the threaded interface
 * <mosquitto_loop_start>. If you need to use <mosquitto_loop>, you must use
 * <mosquitto_connect> to connect the client.
 *
 * This extends the functionality of <mosquitto_connect_async> by adding the
 * bind_address parameter. Use this function if you need to restrict network
 * communication over a particular interface.
 *
 * May be called before or after <mosquitto_loop_start>.
 *
 * Parameters:
 * 	mosq -         a valid mosquitto instance.
 * 	host -         the hostname or ip address of the broker to connect to.
 * 	port -         the network port to connect to. Usually 1883.
 * 	keepalive -    the number of seconds after which the client should send a PING
 *                 message to the broker if no other messages have been exchanged
 *                 in that time.
 *  bind_address - the hostname or ip address of the local network interface to
 *                 bind to. If you do not want to bind to a specific interface,
 *                 set this to NULL.
 *
 * Returns:
 * 	MOSQ_ERR_SUCCESS - on success.
 * 	MOSQ_ERR_INVAL -   if the input parameters were invalid, which could be any of:
 * 	                   * mosq == NULL
 * 	                   * host == NULL
 * 	                   * port < 0
 * 	                   * keepalive < 5
 * 	MOSQ_ERR_ERRNO -   if a system call returned an error. The variable errno
 *                     contains the error code, even on Windows.
 *                     Use strerror_r() where available or FormatMessage() on
 *                     Windows.
 *
 * See Also:
 * 	<mosquitto_connect_async>, <mosquitto_connect>, <mosquitto_connect_bind>
 */
libmosq_EXPORT int mosquitto_connect_bind_async(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address);

/*
 * Function: mosquitto_connect_srv
 *
 * Connect to an MQTT broker.
 *
 * If you set `host` to `example.com`, then this call will attempt to retrieve
 * the DNS SRV record for `_secure-mqtt._tcp.example.com` or
 * `_mqtt._tcp.example.com` to discover which actual host to connect to.
 *
 * DNS SRV support is not usually compiled in to libmosquitto, use of this call
 * is not recommended.
 *
 * Parameters:
 * 	mosq -         a valid mosquitto instance.
 * 	host -         the hostname to search for an SRV record.
 * 	keepalive -    the number of seconds after which the client should send a PING
 *                 message to the broker if no other messages have been exchanged
 *                 in that time.
 *  bind_address - the hostname or ip address of the local network interface to
 *                 bind to. If you do not want to bind to a specific interface,
 *                 set this to NULL.
 *
 * Returns:
 * 	MOSQ_ERR_SUCCESS - on success.
 * 	MOSQ_ERR_INVAL -   if the input parameters were invalid, which could be any of:
 * 	                   * mosq == NULL
 * 	                   * host == NULL
 * 	                   * port < 0
 * 	                   * keepalive < 5
 * 	MOSQ_ERR_ERRNO -   if a system call returned an error. The variable errno
 *                     contains the error code, even on Windows.
 *                     Use strerror_r() where available or FormatMessage() on
 *                     Windows.
 *
 * See Also:
 * 	<mosquitto_connect_async>, <mosquitto_connect>, <mosquitto_connect_bind>
 */
libmosq_EXPORT int mosquitto_connect_srv(struct mosquitto *mosq, const char *host, int keepalive, const char *bind_address);

/*
 * Function: mosquitto_reconnect
 *
 * Reconnect to a broker.
 *
 * This function provides an easy way of reconnecting to a broker after a
 * connection has been lost. It uses the values that were provided in the
 * <mosquitto_connect> call. It must not be called before
 * <mosquitto_connect>.
 *
 * Parameters:
 * 	mosq - a valid mosquitto instance.
 *
 * Returns:
 * 	MOSQ_ERR_SUCCESS - on success.
 * 	MOSQ_ERR_INVAL -   if the input parameters were invalid.
 * 	MOSQ_ERR_NOMEM -   if an out of memory condition occurred.
 * 	MOSQ_ERR_ERRNO -   if a system call returned an error. The variable errno
 *                     contains the error code, even on Windows.
 *                     Use strerror_r() where available or FormatMessage() on
 *                     Windows.
 *
 * See Also:
 * 	<mosquitto_connect>, <mosquitto_disconnect>, <mosquitto_reconnect_async>
 */
libmosq_EXPORT int mosquitto_reconnect(struct mosquitto *mosq);

/*
 * Function: mosquitto_reconnect_async
 *
 * Reconnect to a broker. Non blocking version of <mosquitto_reconnect>.
 *
 * This function provides an easy way of reconnecting to a broker after a
 * connection has been lost. It uses the values that were provided in the
 * <mosquitto_connect> or <mosquitto_connect_async> calls. It must not be
 * called before <mosquitto_connect>.
 *
 * Parameters:
 * 	mosq - a valid mosquitto instance.
 *
 * Returns:
 * 	MOSQ_ERR_SUCCESS - on success.
 * 	MOSQ_ERR_INVAL -   if the input parameters were invalid.
 * 	MOSQ_ERR_NOMEM -   if an out of memory condition occurred.
 * 	MOSQ_ERR_ERRNO -   if a system call returned an error. The variable errno
 *                     contains the error code, even on Windows.
 *                     Use strerror_r() where available or FormatMessage() on
 *                     Windows.
 *
 * See Also:
 * 	<mosquitto_connect>, <mosquitto_disconnect>
 */
libmosq_EXPORT int mosquitto_reconnect_async(struct mosquitto *mosq);

/*
 * Function: mosquitto_disconnect
 *
 * Disconnect from the broker.
 *
 * It is valid to use this function for clients using all MQTT protocol versions.
 * If you need to set MQTT v5 DISCONNECT properties, use
 * <mosquitto_disconnect_v5> instead.
 *
 * Parameters:
 *	mosq - a valid mosquitto instance.
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success.
 * 	MOSQ_ERR_INVAL -   if the input parameters were invalid.
 * 	MOSQ_ERR_NO_CONN -  if the client isn't connected to a broker.
 */
libmosq_EXPORT int mosquitto_disconnect(struct mosquitto *mosq);

/*
 * Function: mosquitto_disconnect_v5
 *
 * Disconnect from the broker, with attached MQTT properties.
 *
 * Use e.g. <mosquitto_property_add_string> and similar to create a list of
 * properties, then attach them to this disconnect. Properties need freeing with
 * <mosquitto_property_free_all>.
 *
 * If the mosquitto instance `mosq` is using MQTT v5, the `properties` argument
 * will be applied to the DISCONNECT message. For MQTT v3.1.1 and below, the
 * `properties` argument will be ignored.
 *
 * Set your client to use MQTT v5 immediately after it is created:
 *
 * mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);
 *
 * Parameters:
 *	mosq - a valid mosquitto instance.
 *	reason_code - the disconnect reason code.
 * 	properties - a valid mosquitto_property list, or NULL.
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success.
 * 	MOSQ_ERR_INVAL -   if the input parameters were invalid.
 * 	MOSQ_ERR_NO_CONN -  if the client isn't connected to a broker.
 *	MOSQ_ERR_DUPLICATE_PROPERTY - if a property is duplicated where it is forbidden.
 *	MOSQ_ERR_PROTOCOL - if any property is invalid for use with DISCONNECT.
 */
libmosq_EXPORT int mosquitto_disconnect_v5(struct mosquitto *mosq, int reason_code, const mosquitto_property *properties);

#ifdef __cplusplus
}
#endif

#endif
