/*
Copyright (c) 2010-2021 Roger Light <roger@atchoo.org>

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

#ifndef MOSQUITTO_LIBCOMMON_CJSON_H
#define MOSQUITTO_LIBCOMMON_CJSON_H

/*
 * File: mosquitto/libcommon_cjson.h
 *
 * This header contains functions for handling cJSON objects
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <cjson/cJSON.h>

libmosqcommon_EXPORT cJSON *mosquitto_properties_to_json(const mosquitto_property *properties);

#ifdef __cplusplus
}
#endif
#endif
