/*
Copyright (c) 2026 Cedalo GmbH

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   AdaLogics - client-side read-handle fuzzer.
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mosquitto.h"
#include "mosquitto/libcommon_memory.h"
#include "mosquitto_internal.h"
#include "packet_mosq.h"
#include "read_handle.h"

#define kMinInputLength 3
#define kMaxInputLength 268435455U

static int initialised = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct mosquitto *mosq;
	uint8_t *payload;
	size_t payload_len;

	if(size < kMinInputLength || size > kMaxInputLength){
		return 0;
	}

	if(!initialised){
		mosquitto_lib_init();
		initialised = 1;
	}

	mosq = mosquitto_new("fuzz-client", true, NULL);
	if(!mosq){
		return 0;
	}

	/* Put the client in a connected state; v5 also exercises the property parser */
	mosq->protocol = (data[0] & 0x01) ? mosq_p_mqtt311 : mosq_p_mqtt5;
	mosq->state = mosq_cs_connected;
	mosq->alias_max_l2r = 10;

	payload_len = size - 1;
	payload = (uint8_t *)mosquitto_malloc(payload_len);
	if(!payload){
		mosquitto_destroy(mosq);
		return 0;
	}
	memcpy(payload, &data[1], payload_len);

	/* Stage the bytes as a received packet with the command byte consumed (pos=1) */
	mosq->in_packet.command = payload[0];
	mosq->in_packet.payload = payload;
	mosq->in_packet.packet_length = (uint32_t)payload_len;
	mosq->in_packet.remaining_length = (uint32_t)(payload_len - 1);
	mosq->in_packet.pos = 1;

	handle__packet(mosq);

	packet__cleanup(&mosq->in_packet);
	mosquitto_destroy(mosq);

	return 0;
}
