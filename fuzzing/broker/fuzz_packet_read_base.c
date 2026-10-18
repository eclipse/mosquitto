/*
Copyright (c) 2023 Cedalo GmbH

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

#ifdef __cplusplus
extern "C" {
#endif

#include <mallocfail/wrap.h>

#include "fuzz_packet_read_base.h"
#include "mosquitto_broker_internal.h"
#include "mosquitto_internal.h"

#define kMinInputLength 3
#define kMaxInputLength 268435455U


int fuzz_packet_read_base(const uint8_t *data, size_t size, int (*packet_func)(struct mosquitto *))
{
	struct mosquitto *context = NULL;
	uint8_t *data_heap;
	struct mosquitto__listener listener;
	struct mosquitto__security_options secopts;

	if(size < kMinInputLength || size > kMaxInputLength){
		return 0;
	}

	db.config = (struct mosquitto__config *)calloc(1, sizeof(struct mosquitto__config));
	log__init(db.config);

	memset(&listener, 0, sizeof(listener));
	memset(&secopts, 0, sizeof(secopts));

	context = context__init();
	if(!context){
		return 1;
	}
	listener.security_options = &secopts;
	context->listener = &listener;
	context->bridge = (struct mosquitto__bridge *)calloc(1, sizeof(struct mosquitto__bridge));;

	context->state = (enum mosquitto_client_state )data[0];
	context->protocol = (enum mosquitto__protocol )data[1];
	size -= 2;

	data_heap = (uint8_t *)malloc(size);
	if(!data_heap){
		free(context->bridge);
		context->bridge = NULL;
		free(db.config);
		db.config = NULL;
		return 1;
	}

	memcpy(data_heap, &data[2], size);

	context->in_packet.command = data_heap[0];
	context->in_packet.payload = (uint8_t *)data_heap;
	context->in_packet.packet_length = (uint32_t )size; /* Safe cast, because we've already limited the size */
	context->in_packet.remaining_length = (uint32_t )(size-1);
	context->in_packet.pos = 1;

	if(fuzz_packet_read_init(context)){
		free(context->bridge);
		context->bridge = NULL;
		free(db.config);
		return 1;
	}
	mallocfailwrap_init(data, size);

	packet_func(context);
	fuzz_packet_read_cleanup(context);

	free(context->bridge);
	context->bridge = NULL;

	context__cleanup(context, true);

	free(db.config);

	return 0;
}
#ifdef __cplusplus
}
#endif
