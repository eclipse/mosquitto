/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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

#include "config.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "mosquitto_internal.h"
#include "mosquitto.h"
#include "memory_mosq.h"

int log__printf(struct mosquitto *mosq, int priority, const char *fmt, ...)
{
	va_list va;
	char *s;
	size_t len;

	assert(mosq);
	assert(fmt);

	pthread_mutex_lock(&mosq->log_callback_mutex);
	if(mosq->on_log){
		len = strlen(fmt) + 500;
		s = mosquitto__malloc(len*sizeof(char));
		if(!s){
			pthread_mutex_unlock(&mosq->log_callback_mutex);
			return MOSQ_ERR_NOMEM;
		}

		va_start(va, fmt);
		vsnprintf(s, len, fmt, va);
		va_end(va);
		s[len-1] = '\0'; /* Ensure string is null terminated. */

		mosq->on_log(mosq, mosq->userdata, priority, s);

		mosquitto__free(s);
	}
	pthread_mutex_unlock(&mosq->log_callback_mutex);

	return MOSQ_ERR_SUCCESS;
}

