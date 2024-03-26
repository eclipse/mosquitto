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

#ifndef MOSQUITTO_LIBCOMMON_FILE_H
#define MOSQUITTO_LIBCOMMON_FILE_H

#include <stdbool.h>
#include <stdio.h>

/*
 * File: mosquitto/libcommon_file.h
 *
 * This header contains functions and definitions for reading/writing files.
 */
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Function: mosquitto_fopen
 */
libmosqcommon_EXPORT FILE *mosquitto_fopen(const char *path, const char *mode, bool restrict_read);


/*
 * Function: mosquitto_fgets
 */
libmosqcommon_EXPORT char *mosquitto_fgets(char **buf, int *buflen, FILE *stream);

/*
 * Function: mosquitto_write_file
 */
libmosqcommon_EXPORT int mosquitto_write_file(const char* target_path, bool restrict_read, int (*write_fn)(FILE* fptr, void* user_data), void* user_data, void (*log_fn)(const char* msg));

/*
 * Function: mosquitto_trimblanks
 *
 * Removes blanks from the end of a string.
 */
libmosqcommon_EXPORT char *mosquitto_trimblanks(char *str);

#ifdef __cplusplus
}
#endif

#endif
