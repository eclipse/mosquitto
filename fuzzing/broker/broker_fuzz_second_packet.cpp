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
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>

#include "broker_fuzz.h"

extern int g_run;

/*
 * This tests the second packet sent to the broker after the client has already
 * connected, with no authentication.
 */
void run_client(struct fuzz_data *fuzz)
{
	int sock;
	const uint8_t connect_packet[] = {0x10, 0x0D, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x0A, 0x00, 0x01, 0x70};
	const uint8_t connack_packet[] = {0x20, 0x02, 0x00, 0x00};
	uint8_t data[20];
	size_t len;

	sock = connect_retrying(fuzz->port);
	if(sock < 0){
		abort();
	}

	/* Do initial connect */
	errno = 0;
	len = send(sock, connect_packet, sizeof(connect_packet), 0);
	if(len < 0){
		abort();
	}

	/* And receive the CONNACK */
	recv_timeout(sock, data, sizeof(connack_packet), 100000);
	if(memcmp(data, connack_packet, sizeof(connack_packet))){
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
