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

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>

#include "broker_fuzz.h"

/*
 * Broker check of config only, the config isn't used
 */

/* The broker fuzz-only main function. */
extern "C" int mosquitto_broker_main(int argc, char *argv[]);

void run_broker(char *filename)
{
	char *argv[5];
	int argc = 5;

	argv[0] = strdup("mosquitto");
	argv[1] = strdup("--test-config");
	argv[2] = strdup("-q");
	argv[3] = strdup("-c");
	argv[4] = strdup(filename);

	mosquitto_broker_main(argc, argv);

	for(int i=0; i<argc; i++){
		free(argv[i]);
	}
}



extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char filename[100];
	FILE *fptr;

	if(size < kMinInputLength){
		return 0;
	}

	umask(0077);

	snprintf(filename, sizeof(filename), "/tmp/mosquitto_%d.conf", getpid());
	fptr = fopen(filename, "wb");
	if(!fptr) return 1;
	fwrite(data, 1, size, fptr);
	fclose(fptr);

	run_broker(filename);

	unlink(filename);

	return 0;
}
