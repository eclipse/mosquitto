/*
Copyright (c) 2009-2021 Roger Light <roger@atchoo.org>

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
#ifndef LOGGING_MOSQ_H
#define LOGGING_MOSQ_H

#include "mosquitto.h"

#ifndef __GNUC__
#define __attribute__(attrib)
#endif

int log__printf(struct mosquitto *mosq, unsigned int level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

#endif
