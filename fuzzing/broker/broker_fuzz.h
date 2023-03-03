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
#ifndef BROKER_FUZZ_H
#define BROKER_FUZZ_H

#define kMinInputLength 5
#define kMaxInputLength 10000

struct fuzz_data{
	uint8_t *data;
	size_t size;
	uint16_t port;
};

void *run_broker(void *args);
void recv_timeout(int sock, void *buf, size_t len, int timeout_us);
int connect_retrying(int port);
void run_client(struct fuzz_data *fuzz);

#endif
