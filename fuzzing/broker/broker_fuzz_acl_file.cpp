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
#include <sys/stat.h>
#include <unistd.h>

/*
 * Broker check of acl file
 */
extern "C" {
#include "mosquitto_broker_internal.h"
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char filename[100];
	FILE *fptr;
	struct mosquitto__config config;

	mallocfailwrap_init(data, size);

	memset(&config, 0, sizeof(config));

	db.config = &config;
	config.log_type = 0;
	config.log_dest = 0;

	umask(0077);

	snprintf(filename, sizeof(filename), "/tmp/acl_file_%d", getpid());
	fptr = fopen(filename, "wb");
	if(!fptr){
		return 1;
	}
	fwrite(data, 1, size, fptr);
	fclose(fptr);

	config.security_options.acl_data.acl_file = strdup(filename);

	log__init(&config);
	mosquitto_security_init_default();
	mosquitto_security_cleanup_default();
	config__cleanup(&config);

	unlink(filename);

	return 0;
}
