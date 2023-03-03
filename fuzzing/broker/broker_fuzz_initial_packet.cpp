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

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

#include "broker_fuzz.h"

/* Set to 0 to cause the broker to exit */
extern int g_run;

/*
 * This tests the first packet being sent to the broker only, with no authentication.
 */
void run_client(struct fuzz_data *fuzz)
{
	int sock;
	uint8_t data[20];
	size_t len;

	sock = connect_retrying(fuzz->port);
	if(sock < 0){
		abort();
	}

	errno = 0;
	len = send(sock, fuzz->data, fuzz->size, 0);
	if(len < fuzz->size){
		abort();
	}

	errno = 0;
	recv_timeout(sock, data, sizeof(data), 100000);
	close(sock);

	g_run = 0;
}
