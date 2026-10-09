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

#ifndef MOSQUITTO_LIBMOSQUITTO_SUBSCRIBE_H
#define MOSQUITTO_LIBMOSQUITTO_SUBSCRIBE_H

/*
 * File: mosquitto/libmosquitto_subscribe.h
 *
 * This header contains functions for subscribing in libmosquitto.
 */
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Function: mosquitto_subscribe
 *
 * Subscribe to a topic.
 *
 * It is valid to use this function for clients using all MQTT protocol versions.
 * If you need to set MQTT v5 SUBSCRIBE properties, use <mosquitto_subscribe_v5>
 * instead.
 *
 * Parameters:
 *	mosq - a valid mosquitto instance.
 *	mid -  a pointer to an int. If not NULL, the function will set this to
 *	       the message id of this particular message. This can be then used
 *	       with the subscribe callback to determine when the message has been
 *	       sent.
 *	sub -  the subscription pattern - must not be NULL or an empty string.
 *	qos -  the requested Quality of Service for this subscription.
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS -        on success.
 * 	MOSQ_ERR_INVAL -          if the input parameters were invalid.
 * 	MOSQ_ERR_NOMEM -          if an out of memory condition occurred.
 * 	MOSQ_ERR_NO_CONN -        if the client isn't connected to a broker.
 * 	MOSQ_ERR_MALFORMED_UTF8 - if the topic is not valid UTF-8
 *	MOSQ_ERR_OVERSIZE_PACKET - if the resulting packet would be larger than
 *	                           supported by the broker.
 */
libmosq_EXPORT int mosquitto_subscribe(struct mosquitto *mosq, int *mid, const char *sub, int qos);

/*
 * Function: mosquitto_subscribe_v5
 *
 * Subscribe to a topic, with attached MQTT properties.
 *
 * Use e.g. <mosquitto_property_add_string> and similar to create a list of
 * properties, then attach them to this subscribe. Properties need freeing with
 * <mosquitto_property_free_all>.
 *
 * If the mosquitto instance `mosq` is using MQTT v5, the `properties` argument
 * will be applied to the PUBLISH message. For MQTT v3.1.1 and below, the
 * `properties` argument will be ignored.
 *
 * Set your client to use MQTT v5 immediately after it is created:
 *
 * mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);
 *
 * Parameters:
 *	mosq - a valid mosquitto instance.
 *	mid -  a pointer to an int. If not NULL, the function will set this to
 *	       the message id of this particular message. This can be then used
 *	       with the subscribe callback to determine when the message has been
 *	       sent.
 *	sub -  the subscription pattern - must not be NULL or an empty string.
 *	qos -  the requested Quality of Service for this subscription.
 *	options - options to apply to this subscription, OR'd together. Set to 0 to
 *	          use the default options, otherwise choose from list of <mqtt5_sub_options>
 * 	properties - a valid mosquitto_property list, or NULL.
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS -        on success.
 * 	MOSQ_ERR_INVAL -          if the input parameters were invalid.
 * 	MOSQ_ERR_NOMEM -          if an out of memory condition occurred.
 * 	MOSQ_ERR_NO_CONN -        if the client isn't connected to a broker.
 * 	MOSQ_ERR_MALFORMED_UTF8 - if the topic is not valid UTF-8
 *	MOSQ_ERR_DUPLICATE_PROPERTY - if a property is duplicated where it is forbidden.
 *	MOSQ_ERR_PROTOCOL - if any property is invalid for use with SUBSCRIBE.
 *	MOSQ_ERR_OVERSIZE_PACKET - if the resulting packet would be larger than
 *	                           supported by the broker.
 */
libmosq_EXPORT int mosquitto_subscribe_v5(struct mosquitto *mosq, int *mid, const char *sub, int qos, int options, const mosquitto_property *properties);

/*
 * Function: mosquitto_subscribe_multiple
 *
 * Subscribe to multiple topics.
 *
 * Parameters:
 *	mosq - a valid mosquitto instance.
 *	mid -  a pointer to an int. If not NULL, the function will set this to
 *	       the message id of this particular message. This can be then used
 *	       with the subscribe callback to determine when the message has been
 *	       sent.
 *  sub_count - the count of subscriptions to be made
 *	sub -  array of sub_count pointers, each pointing to a subscription string.
 *	       The "char *const *const" datatype ensures that neither the array of
 *	       pointers nor the strings that they point to are mutable. If you aren't
 *	       familiar with this, just think of it as a safer "char **",
 *	       equivalent to "const char *" for a simple string pointer.
 *	       Each string must not be NULL nor an empty string.
 *	qos -  the requested Quality of Service for each subscription.
 *	options - options to apply to this subscription, OR'd together. This
 *	          argument is not used for MQTT v3 susbcriptions. Set to 0 to use
 *	          the default options, otherwise choose from list of <mqtt5_sub_options>
 * 	properties - a valid mosquitto_property list, or NULL. Only used with MQTT
 * 	             v5 clients.
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS -        on success.
 * 	MOSQ_ERR_INVAL -          if the input parameters were invalid.
 * 	MOSQ_ERR_NOMEM -          if an out of memory condition occurred.
 * 	MOSQ_ERR_NO_CONN -        if the client isn't connected to a broker.
 * 	MOSQ_ERR_MALFORMED_UTF8 - if a topic is not valid UTF-8
 *	MOSQ_ERR_OVERSIZE_PACKET - if the resulting packet would be larger than
 *	                           supported by the broker.
 */
libmosq_EXPORT int mosquitto_subscribe_multiple(struct mosquitto *mosq, int *mid, int sub_count, char *const *const sub, int qos, int options, const mosquitto_property *properties);

#ifdef __cplusplus
}
#endif

#endif
