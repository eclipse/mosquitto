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
#include <unistd.h>

/*
 * Test loading a file
 */


/* The fuzz-only main function. */
extern "C" int db_dump_fuzz_main(int argc, char *argv[]);

void run_db_dump(char *filename)
{
	char *argv[2];
	int argc = 2;

	argv[0] = strdup("mosquitto_db_dump");
	argv[1] = filename;

	db_dump_fuzz_main(argc, argv);

	free(argv[0]);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char filename[100];
	FILE *fptr;

	snprintf(filename, sizeof(filename), "/tmp/db_dump_%d.db", getpid());
	fptr = fopen(filename, "wb");
	if(!fptr) return 1;
	fwrite(data, 1, size, fptr);
	fclose(fptr);

	run_db_dump(filename);

	unlink(filename);

	return 0;
}
