/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
SPDX-License-Identifier: EPL-2.0 OR EDL-1.0

Contributors:
   Roger Light - initial implementation and documentation.
*/
#ifndef PUB_SHARED_H
#define PUB_SHARED_H

#define STATUS_CONNECTING 0
#define STATUS_CONNACK_RECVD 1
#define STATUS_WAITING 2
#define STATUS_DISCONNECTING 3
#define STATUS_DISCONNECTED 4
#define STATUS_NOHOPE 5

extern int mid_sent;
extern struct mosq_config cfg;


void my_connect_callback(struct mosquitto *mosq, void *obj, int result, int flags, const mosquitto_property *properties);
void my_disconnect_callback(struct mosquitto *mosq, void *obj, int rc, const mosquitto_property *properties);
void my_publish_callback(struct mosquitto *mosq, void *obj, int mid, int reason_code, const mosquitto_property *properties);
void my_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str);
int load_stdin(void);
int load_file(const char *filename);

int my_publish(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, void *payload, int qos, bool retain);

int pub_shared_init(void);
int pub_shared_loop(struct mosquitto *mosq);
void pub_shared_cleanup(void);

#endif
