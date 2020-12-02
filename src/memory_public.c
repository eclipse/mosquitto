/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR EDL-1.0

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "mosquitto_broker.h"
#include "memory_mosq.h"

void *mosquitto_calloc(size_t nmemb, size_t size)
{
	return mosquitto__calloc(nmemb, size);
}

void mosquitto_free(void *mem)
{
	mosquitto__free(mem);
}

void *mosquitto_malloc(size_t size)
{
	return mosquitto__malloc(size);
}

void *mosquitto_realloc(void *ptr, size_t size)
{
	return mosquitto__realloc(ptr, size);
}

char *mosquitto_strdup(const char *s)
{
	return mosquitto__strdup(s);
}
