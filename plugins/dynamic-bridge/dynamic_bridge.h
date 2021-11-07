/*
Copyright (c) 2021 Benjamin Hansmann <benjamin.hansmann@riedel.net>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Benjamin Hansmann - initial implementation and documentation.
*/

#ifndef DYNAMIC_BRIDGE_H
#define DYNAMIC_BRIDGE_H

#include <cjson/cJSON.h>

#include "mosquitto.h"

/* ################################################################
 * #
 * # Plugin Functions
 * #
 * ################################################################ */

int dynbridge__handle_control(cJSON *j_responses, struct mosquitto *context, cJSON *commands);
void dynbridge__command_reply(cJSON *j_responses, struct mosquitto *context, const char *command, const char *error, const char *correlation_data);

/* ################################################################
 * #
 * # Client Functions
 * #
 * ################################################################ */

int dynbridge__process_create(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynbridge__process_list(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynbridge__process_delete(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);

#endif
