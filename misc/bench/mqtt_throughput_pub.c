/*
Copyright (c) 2026 the Mosquitto contributors.

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

SPDX-License-Identifier: EPL-2.0 OR EDL-1.0
*/

/*
 * Minimal single-connection throughput publisher for the broker.
 *
 * Opens one connection, publishes N QoS-0 messages of a fixed size as fast as
 * the broker will accept them, then reports the achieved rate. Used together
 * with one or more `mosquitto_sub` consumers to measure broker routing and
 * write throughput.
 *
 * Build:  cc -O2 mqtt_throughput_pub.c -lmosquitto -o mqtt_throughput_pub
 * Usage:  mqtt_throughput_pub [port] [count] [payload_bytes] [topic]
 */

#include <mosquitto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv)
{
	const char *host = "127.0.0.1";
	int port  = argc > 1 ? atoi(argv[1]) : 1883;
	long n    = argc > 2 ? atol(argv[2]) : 1000000;
	int psize = argc > 3 ? atoi(argv[3]) : 64;
	const char *topic = argc > 4 ? argv[4] : "bench/topic";
	struct timespec t0, t1;
	struct mosquitto *m;
	char *payload;
	double dt;

	payload = malloc((size_t)psize);
	if(!payload){ return 1; }
	memset(payload, 'x', (size_t)psize);

	mosquitto_lib_init();
	m = mosquitto_new(NULL, true, NULL);
	if(!m || mosquitto_connect(m, host, port, 60)){
		fprintf(stderr, "connect to %s:%d failed\n", host, port);
		return 1;
	}

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for(long i=0; i<n; i++){
		int rc = mosquitto_publish(m, NULL, topic, psize, payload, 0, false);
		if(rc == MOSQ_ERR_NOMEM || rc == MOSQ_ERR_ERRNO){
			mosquitto_loop_write(m, 1);
			i--;
			continue;
		}
		if((i & 0x3FF) == 0){
			mosquitto_loop_write(m, 1); /* drain periodically */
		}
	}
	while(mosquitto_want_write(m)){
		mosquitto_loop_write(m, 1);
	}
	clock_gettime(CLOCK_MONOTONIC, &t1);

	dt = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec)/1e9;
	fprintf(stderr, "published %ld msgs (%dB) in %.3fs = %.0f msg/s (%.1f MB/s)\n",
			n, psize, dt, (double)n/dt, (double)n*(double)psize/1e6/dt);

	mosquitto_disconnect(m);
	mosquitto_destroy(m);
	mosquitto_lib_cleanup();
	free(payload);
	return 0;
}
