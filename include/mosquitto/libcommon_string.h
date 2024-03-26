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

#ifndef MOSQUITTO_LIBCOMMON_STRING_H
#define MOSQUITTO_LIBCOMMON_STRING_H

/*
 * File: mosquitto.h
 *
 * This header contains functions and definitions for use with libmosquitto, the Mosquitto client library.
 *
 * The definitions are also used in Mosquitto broker plugins, and some functions are available to plugins.
 */
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Function: mosquitto_strerror
 *
 * Call to obtain a const string description of a mosquitto error number.
 *
 * Parameters:
 *	mosq_errno - a mosquitto error number.
 *
 * Returns:
 *	A constant string describing the error.
 */
libmosqcommon_EXPORT const char *mosquitto_strerror(int mosq_errno);

/*
 * Function: mosquitto_connack_string
 *
 * Call to obtain a const string description of an MQTT connection result.
 *
 * Parameters:
 *	connack_code - an MQTT connection result.
 *
 * Returns:
 *	A constant string describing the result.
 */
libmosqcommon_EXPORT const char *mosquitto_connack_string(int connack_code);

/*
 * Function: mosquitto_reason_string
 *
 * Call to obtain a const string description of an MQTT reason code.
 *
 * Parameters:
 *	reason_code - an MQTT reason code.
 *
 * Returns:
 *	A constant string describing the reason.
 */
libmosqcommon_EXPORT const char *mosquitto_reason_string(int reason_code);

/* Function: mosquitto_string_to_command
 *
 * Take a string input representing an MQTT command and convert it to the
 * libmosquitto integer representation.
 *
 * Parameters:
 *   str - the string to parse.
 *   cmd - pointer to an int, for the result.
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success
 *	MOSQ_ERR_INVAL - on an invalid input.
 *
 * Example:
 * (start code)
 *  mosquitto_string_to_command("CONNECT", &cmd);
 *  // cmd == CMD_CONNECT
 * (end)
 */
libmosqcommon_EXPORT int mosquitto_string_to_command(const char *str, int *cmd);

#ifdef __cplusplus
}
#endif

#endif
