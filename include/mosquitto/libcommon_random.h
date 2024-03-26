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

#ifndef MOSQUITTO_LIBCOMMON_RANDOM_H
#define MOSQUITTO_LIBCOMMON_RANDOM_H

/*
 * File: mosquitto/libcommon_random.h
 *
 * This header contains functions for obtaining random numbers.
 */
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Function: mosquitto_getrandom
 *
 * Get random bytes.
 *
 * Parameters:
 *	bytes -  a buffer to store the random bytes, at least count bytes long.
 *	count -  the number or bytes to retrieve
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS -        on success
 * 	MOSQ_ERR_UNKNOWN -        if an error occurred
 */
libmosqcommon_EXPORT int mosquitto_getrandom(void *bytes, int count);

#ifdef __cplusplus
}
#endif

#endif
