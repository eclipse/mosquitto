/*
Copyright (c) 2025 Roger Light <roger@atchoo.org>

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

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mallocfail/wrap.h>
#include <sys/stat.h>
#include <unistd.h>

static const uint8_t *packet_data = NULL;
static int packet_data_pos = 0;
static size_t packet_data_remaining = 0;

extern "C" {
#include "mosquitto_broker_internal.h"


ssize_t net__read(struct mosquitto *mosq, void *buf, size_t count)
{
	size_t res = count < packet_data_remaining?count:packet_data_remaining;
	UNUSED(mosq);
	memcpy(buf, &packet_data[packet_data_pos], res);
	packet_data_remaining -= res;
	return (ssize_t)res;
}


int http__context_init(struct mosquitto *context)
{
	context->transport = mosq_t_http;

	return MOSQ_ERR_SUCCESS;
}


int log__printf(struct mosquitto *mosq, unsigned int priority, const char *fmt, ...)
{
	UNUSED(mosq);
	UNUSED(priority);
	UNUSED(fmt);
	return MOSQ_ERR_SUCCESS;
}

}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct mosquitto context {};
	struct mosquitto__listener listener {};

	mallocfailwrap_init(data, size);

	packet_data = data;
	packet_data_pos = 0;
	packet_data_remaining = size;

	context.listener = &listener;
	context.proxy.cmd = -1;
	context.transport = mosq_t_proxy_v2;

	while(packet_data_remaining > 0 && context.transport != mosq_t_tcp){
		int rc = proxy_v2__read(&context);
		if(rc){
			break;
		}
	}
	free(context.address);
	free(context.proxy.buf);
	free(context.proxy.tls_version);
	free(context.proxy.cipher);

	return 0;
}
