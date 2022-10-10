/*
Copyright (c) 2021 Roger Light <roger@atchoo.org>

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
#ifndef CALLBACKS_H
#define CALLBACKS_H

#include "mosquitto.h"

void callback__on_pre_connect(struct mosquitto *mosq);
void callback__on_connect(struct mosquitto *mosq, uint8_t reason_code, uint8_t connect_flags, const mosquitto_property *properties);
void callback__on_publish(struct mosquitto *mosq, int mid, int reason_code, const mosquitto_property *properties);
void callback__on_message(struct mosquitto *mosq, const struct mosquitto_message *message, const mosquitto_property *properties);
void callback__on_subscribe(struct mosquitto *mosq, int mid, int qos_count, const int *granted_qos, const mosquitto_property *props);
void callback__on_unsubscribe(struct mosquitto *mosq, int mid, const mosquitto_property *props);
void callback__on_disconnect(struct mosquitto *mosq, int rc, const mosquitto_property *props);

#endif
