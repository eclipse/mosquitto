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

#ifndef MOSQUITTO_LIBCOMMON_UTF8_H
#define MOSQUITTO_LIBCOMMON_UTF8_H

/*
 * File: mosquitto/libcommon_utf8.h
 */
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Function: mosquitto_validate_utf8
 *
 * Helper function to validate whether a UTF-8 string is valid, according to
 * the UTF-8 spec and the MQTT additions.
 *
 * Parameters:
 *   str - a string to check
 *   len - the length of the string in bytes
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS -        on success
 *   MOSQ_ERR_INVAL -          if str is NULL or len<0 or len>65536
 *   MOSQ_ERR_MALFORMED_UTF8 - if str is not valid UTF-8
 */
libmosqcommon_EXPORT int mosquitto_validate_utf8(const char *str, int len);

#ifdef __cplusplus
}
#endif

#endif
