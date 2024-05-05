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

#ifndef MOSQUITTO_LIBCOMMON_MEMORY_H
#define MOSQUITTO_LIBCOMMON_MEMORY_H

/*
 * File: mosquitto/libcommon_memory.h
 *
 * This header contains functions and definitions for allocating and freeing
 * memory in broker plugins
 */
#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 *
 * Section: Memory allocation.
 *
 * Use these functions when allocating or freeing memory to have your memory
 * included in the memory tracking on the broker.
 *
 * ========================================================================= */

/*
 * Function: mosquitto_calloc
 */
libmosqcommon_EXPORT void *mosquitto_calloc(size_t nmemb, size_t size);

/*
 * Function: mosquitto_free
 */
libmosqcommon_EXPORT void mosquitto_free(void *mem);

/*
 * Function: mosquitto_malloc
 */
libmosqcommon_EXPORT void *mosquitto_malloc(size_t size);

/*
 * Function: mosquitto_realloc
 */
libmosqcommon_EXPORT void *mosquitto_realloc(void *ptr, size_t size);

/*
 * Function: mosquitto_strdup
 */
libmosqcommon_EXPORT char *mosquitto_strdup(const char *s);

/*
 * Function: mosquitto_strndup
 */
libmosqcommon_EXPORT char *mosquitto_strndup(const char *s, size_t n);

libmosqcommon_EXPORT void mosquitto_memory_set_limit(size_t lim);
libmosqcommon_EXPORT unsigned long mosquitto_memory_used(void);
libmosqcommon_EXPORT unsigned long mosquitto_max_memory_used(void);

#define mosquitto_FREE(A) do { mosquitto_free(A); (A) = NULL;} while(0)

#ifdef __cplusplus
}
#endif
#endif
