/*
Copyright (c) 2024 Roger Light <roger@atchoo.org>

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
#include <unistd.h>
#include <sys/stat.h>

/*
 * Broker check of acl file
 */
extern "C" {
#include "mosquitto_broker_internal.h"
}


//int sub__messages_queue(const char *source_id, const char *topic, uint8_t qos, int retain, struct mosquitto__base_msg **stored)


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct mosquitto__base_msg basemsg, *pbasemsg;
	struct mosquitto__config config;

	mallocfailwrap_init(data, size);

	memset(&config, 0, sizeof(config));

	if(mosquitto_pub_topic_check2((const char *)data, size)){
		/* sub__messages_queue only receives topics that have already been
		 * checked with mosquitto_pub_topic_check2(), so we give it that benefit
		 * here. */
		return 0;
	}

	memset(&basemsg, 0, sizeof(basemsg));
	basemsg.ref_count = 1;
	pbasemsg = &basemsg;

	db.config = &config;
	config.log_type = 0;
	config.log_dest = 0;
	log__init(&config);
	db__open(&config);

	char *data0 = (char *)calloc(1, size+1);
	memcpy(data0, data, size);
	sub__messages_queue("fuzzer", data0, 0, 1, &pbasemsg);
	free(data0);

	db__close();

	return 0;
}
