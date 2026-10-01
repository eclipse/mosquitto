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

#ifndef MOSQUITTO_LIBMOSQUITTO_OPTIONS_H
#define MOSQUITTO_LIBMOSQUITTO_OPTIONS_H

/*
 * File: mosquitto/libmosquitto_options.h
 *
 * This header contains functions for setting client options in libmosquitto.
 */
#ifdef __cplusplus
extern "C" {
#endif

/* ======================================================================
 *
 * Section: Client options
 *
 * ====================================================================== */
/*
 * Function: mosquitto_opts_set
 *
 * Used to set options for the client.
 *
 * This function is deprecated, the replacement <mosquitto_int_option>,
 * <mosquitto_string_option> and <mosquitto_void_option> functions should
 * be used instead.
 *
 * Parameters:
 *	mosq -   a valid mosquitto instance.
 *	option - the option to set.
 *	value -  the option specific value.
 *
 * Options:
 *	MOSQ_OPT_PROTOCOL_VERSION - Value must be an int, set to either
 *	          MQTT_PROTOCOL_V31 or MQTT_PROTOCOL_V311. Must be set
 *	          before the client connects.
 *	          Defaults to MQTT_PROTOCOL_V31.
 *
 *	MOSQ_OPT_SSL_CTX - Pass an openssl SSL_CTX to be used when creating
 *	          TLS connections rather than libmosquitto creating its own.
 *	          This must be called before connecting to have any effect.
 *	          If you use this option, the onus is on you to ensure that
 *	          you are using secure settings.
 *	          Setting to NULL means that libmosquitto will use its own SSL_CTX
 *	          if TLS is to be used.
 *	          This option is only available for openssl 1.1.0 and higher.
 *
 *	MOSQ_OPT_SSL_CTX_WITH_DEFAULTS - Value must be an int set to 1 or 0.
 *	          If set to 1, then the user specified SSL_CTX passed in using
 *	          MOSQ_OPT_SSL_CTX will have the default options applied to it.
 *	          This means that you only need to change the values that are
 *	          relevant to you. If you use this option then you must configure
 *	          the TLS options as normal, i.e. you should use
 *	          <mosquitto_tls_set> to configure the cafile/capath as a minimum.
 *	          This option is only available for openssl 1.1.0 and higher.
 */
libmosq_EXPORT int mosquitto_opts_set(struct mosquitto *mosq, enum mosq_opt_t option, void *value);

/*
 * Function: mosquitto_int_option
 *
 * Used to set integer options for the client.
 *
 * Parameters:
 *	mosq -   a valid mosquitto instance.
 *	option - the option to set.
 *	value -  the option specific value.
 *
 * Options:
 *	MOSQ_OPT_TCP_NODELAY - Set to 1 to disable Nagle's algorithm on client
 *	          sockets. This has the effect of reducing latency of individual
 *	          messages at the potential cost of increasing the number of
 *	          packets being sent.
 *	          Defaults to 0, which means Nagle remains enabled.
 *
 *	MOSQ_OPT_PROTOCOL_VERSION - Value must be set to either MQTT_PROTOCOL_V31,
 *	          MQTT_PROTOCOL_V311, or MQTT_PROTOCOL_V5. Must be set before the
 *	          client connects.  Defaults to MQTT_PROTOCOL_V311.
 *
 *	MOSQ_OPT_RECEIVE_MAXIMUM - Value can be set between 1 and 65535 inclusive,
 *	          and represents the maximum number of incoming QoS 1 and QoS 2
 *	          messages that this client wants to process at once. Defaults to
 *	          20. This option is not valid for MQTT v3.1 or v3.1.1 clients.
 *	          Note that if the MQTT_PROP_RECEIVE_MAXIMUM property is in the
 *	          proplist passed to mosquitto_connect_v5(), then that property
 *	          will override this option. Using this option is the recommended
 *	          method however.
 *
 *	MOSQ_OPT_SEND_MAXIMUM - Value can be set between 1 and 65535 inclusive,
 *	          and represents the maximum number of outgoing QoS 1 and QoS 2
 *	          messages that this client will attempt to have "in flight" at
 *	          once. Defaults to 20.
 *	          This option is not valid for MQTT v3.1 or v3.1.1 clients.
 *	          Note that if the broker being connected to sends a
 *	          MQTT_PROP_RECEIVE_MAXIMUM property that has a lower value than
 *	          this option, then the broker provided value will be used.
 *
 *	MOSQ_OPT_SSL_CTX_WITH_DEFAULTS - If value is set to a non zero value,
 *	          then the user specified SSL_CTX passed in using MOSQ_OPT_SSL_CTX
 *	          will have the default options applied to it. This means that
 *	          you only need to change the values that are relevant to you.
 *	          If you use this option then you must configure the TLS options
 *	          as normal, i.e.  you should use <mosquitto_tls_set> to
 *	          configure the cafile/capath as a minimum.
 *	          This option is only available for openssl 1.1.0 and higher.
 *
 *	MOSQ_OPT_TLS_OCSP_REQUIRED - Set whether OCSP checking on TLS
 *	          connections is required. Set to 1 to enable checking,
 *	          or 0 (the default) for no checking.
 *
 *	MOSQ_OPT_TLS_USE_OS_CERTS - Set to 1 to instruct the client to load and
 *	          trust OS provided CA certificates for use with TLS connections.
 *	          Set to 0 (the default) to only use manually specified CA certs.
 *
 *	MOSQ_OPT_DISABLE_SOCKETPAIR - By default, each client connected will create
 *            an internal pair of connected sockets to allow the network thread
 *            to be notified and woken up if another thread calls
 *            <mosquitto_publish> or other similar command. If you are
 *            operating with an external loop, this is not necessary and
 *            consumes an extra two sockets per client. Set this option to 1 to
 *            disable the use of the socket pair.
 *
 *	MOSQ_OPT_TRANSPORT - Have the client connect with either MQTT over TCP as
 *	          normal, or MQTT over WebSockets. Set the value to MOSQ_T_TCP or
 *	          MOSQ_T_WEBSOCKETS.
 *
 *	MOSQ_OPT_HTTP_HEADER_SIZE - Size the size of buffer that will be allocated
 *	          to store the incoming HTTP header when using Websocket transport.
 *	          Defaults to 4096. Setting to below 100 will result in a return
*	          value of MOSQ_ERR_INVAL. This should be set before starting the
*	          connection. If you try to set this when the initial http request
*	          is underway then it will return MOSQ_ERR_INVAL.
 */
libmosq_EXPORT int mosquitto_int_option(struct mosquitto *mosq, enum mosq_opt_t option, int value);


/*
 * Function: mosquitto_string_option
 *
 * Used to set const char* options for the client.
 *
 * Parameters:
 *	mosq -   a valid mosquitto instance.
 *	option - the option to set.
 *	value -  the option specific value.
 *
 * Options:
 *	MOSQ_OPT_TLS_ENGINE - Configure the client for TLS Engine support.
 *	          Pass a TLS Engine ID to be used when creating TLS
 *	          connections. Must be set before <mosquitto_connect>.
 *	          Must be a valid engine, and note that the string will not be used
 *	          until a connection attempt is made so this function will return
 *	          success even if an invalid engine string is passed.
 *
 *	MOSQ_OPT_TLS_KEYFORM - Configure the client to treat the keyfile
 *	          differently depending on its type.  Must be set
 *	          before <mosquitto_connect>.
 *	          Set as either "pem" or "engine", to determine from where the
 *	          private key for a TLS connection will be obtained. Defaults to
 *	          "pem", a normal private key file.
 *
 *	MOSQ_OPT_TLS_ENGINE_KPASS_SHA1 - Where the TLS Engine requires the use of
 *	          a password to be accessed, this option allows a hex encoded
 *	          SHA1 hash of the private key password to be passed to the
 *	          engine directly. Must be set before <mosquitto_connect>.
 *
 *	MOSQ_OPT_TLS_ALPN - If the broker being connected to has multiple
 *	          services available on a single TLS port, such as both MQTT
 *	          and WebSockets, use this option to configure the ALPN
 *	          option for the connection.
 *
 *	MOSQ_OPT_BIND_ADDRESS - Set the hostname or ip address of the local network
 *	          interface to bind to when connecting.
 *
 *	MOSQ_OPT_PEER_NAME - Set the name of the remote peer when connecting with
 *	          <mosquitto_connect_transport>. Used for the TLS server name and
 *	          hostname check, and for the WebSockets Host header.
 */
libmosq_EXPORT int mosquitto_string_option(struct mosquitto *mosq, enum mosq_opt_t option, const char *value);


/*
 * Function: mosquitto_void_option
 *
 * Used to set void* options for the client.
 *
 * Parameters:
 *	mosq -   a valid mosquitto instance.
 *	option - the option to set.
 *	value -  the option specific value.
 *
 * Options:
 *	MOSQ_OPT_SSL_CTX - Pass an openssl SSL_CTX to be used when creating TLS
 *	          connections rather than libmosquitto creating its own.  This must
 *	          be called before connecting to have any effect. If you use this
 *	          option, the onus is on you to ensure that you are using secure
 *	          settings.
 *	          Setting to NULL means that libmosquitto will use its own SSL_CTX
 *	          if TLS is to be used.
 *	          This option is only available for openssl 1.1.0 and higher.
 */
libmosq_EXPORT int mosquitto_void_option(struct mosquitto *mosq, enum mosq_opt_t option, void *value);

/*
 * Function: mosquitto_reconnect_delay_set
 *
 * Control the behaviour of the client when it has unexpectedly disconnected in
 * <mosquitto_loop_forever> or after <mosquitto_loop_start>. The default
 * behaviour if this function is not used is to repeatedly attempt to reconnect
 * with a delay of 1 second until the connection succeeds.
 *
 * Use reconnect_delay parameter to change the delay between successive
 * reconnection attempts. You may also enable exponential backoff of the time
 * between reconnections by setting reconnect_exponential_backoff to true and
 * set an upper bound on the delay with reconnect_delay_max.
 *
 * Example 1:
 *	delay=2, delay_max=10, exponential_backoff=False
 *	Delays would be: 2, 4, 6, 8, 10, 10, ...
 *
 * Example 2:
 *	delay=3, delay_max=30, exponential_backoff=True
 *	Delays would be: 3, 6, 12, 24, 30, 30, ...
 *
 * Parameters:
 *  mosq -                          a valid mosquitto instance.
 *  reconnect_delay -               the number of seconds to wait between
 *                                  reconnects.
 *  reconnect_delay_max -           the maximum number of seconds to wait
 *                                  between reconnects.
 *  reconnect_exponential_backoff - use exponential backoff between
 *                                  reconnect attempts. Set to true to enable
 *                                  exponential backoff.
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success.
 * 	MOSQ_ERR_INVAL -   if the input parameters were invalid.
 */
libmosq_EXPORT int mosquitto_reconnect_delay_set(struct mosquitto *mosq, unsigned int reconnect_delay, unsigned int reconnect_delay_max, bool reconnect_exponential_backoff);

/*
 * Function: mosquitto_max_inflight_messages_set
 *
 * This function is deprecated. Use the <mosquitto_int_option> function with the
 * MOSQ_OPT_SEND_MAXIMUM option instead.
 *
 * Set the number of QoS 1 and 2 messages that can be "in flight" at one time.
 * An in flight message is part way through its delivery flow. Attempts to send
 * further messages with <mosquitto_publish> will result in the messages being
 * queued until the number of in flight messages reduces.
 *
 * A higher number here results in greater message throughput, but if set
 * higher than the maximum in flight messages on the broker may lead to
 * delays in the messages being acknowledged.
 *
 * Set to 0 for no maximum.
 *
 * Parameters:
 *  mosq -                  a valid mosquitto instance.
 *  max_inflight_messages - the maximum number of inflight messages. Defaults
 *                          to 20.
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success.
 * 	MOSQ_ERR_INVAL -   if the input parameters were invalid.
 */
libmosq_EXPORT int mosquitto_max_inflight_messages_set(struct mosquitto *mosq, unsigned int max_inflight_messages);

/*
 * Function: mosquitto_message_retry_set
 *
 * This function now has no effect.
 */
libmosq_EXPORT void mosquitto_message_retry_set(struct mosquitto *mosq, unsigned int message_retry);

/*
 * Function: mosquitto_user_data_set
 *
 * When <mosquitto_new> is called, the pointer given as the "obj" parameter
 * will be passed to the callbacks as user data. The <mosquitto_user_data_set>
 * function allows this obj parameter to be updated at any time. This function
 * will not modify the memory pointed to by the current user data pointer. If
 * it is dynamically allocated memory you must free it yourself.
 *
 * Parameters:
 *  mosq - a valid mosquitto instance.
 * 	obj -  A user pointer that will be passed as an argument to any callbacks
 * 	       that are specified.
 */
libmosq_EXPORT void mosquitto_user_data_set(struct mosquitto *mosq, void *obj);

/* Function: mosquitto_userdata
 *
 * Retrieve the "userdata" variable for a mosquitto client.
 *
 * Parameters:
 * 	mosq - a valid mosquitto instance.
 *
 * Returns:
 *	A pointer to the userdata member variable.
 */
libmosq_EXPORT void *mosquitto_userdata(struct mosquitto *mosq);

#ifdef __cplusplus
}
#endif

#endif
