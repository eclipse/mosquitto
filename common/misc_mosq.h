/*
Copyright (c) 2009-2021 Roger Light <roger@atchoo.org>

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
#ifndef MISC_MOSQ_H
#define MISC_MOSQ_H

#include <stdbool.h>
#include <stdio.h>

FILE *mosquitto__fopen(const char *path, const char *mode, bool restrict_read);
char *misc__trimblanks(char *str);
char *fgets_extending(char **buf, int *buflen, FILE *stream);

int mosquitto_write_file(const char* target_path, bool restrict_read, int (*write_fn)(FILE* fptr, void* user_data), void* user_data, void (*log_fn)(const char* msg));

char *strtok_dblesc(char *str, const char *delim, char **saveptr);
char *esc_for_strtok_dblesc(const char *plain, const char *delim);

#endif
