/*
Copyright (c) 2019 Roger Light <roger@atchoo.org>

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

#ifndef SUB_CLIENT_OUTPUT_H
#define SUB_CLIENT_OUTPUT_H

#include "mosquitto.h"
#include "client_shared.h"

void rand_init(void);
void print_message(struct mosq_config *cfg, const struct mosquitto_message *message, const mosquitto_property *properties);

#endif
