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

#ifndef MOSQUITTO_LIBCOMMON_H
#define MOSQUITTO_LIBCOMMON_H

/*
 * File: mosquitto/libcommon.h
 */
#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#  ifdef libmosquitto_common_EXPORTS
#    define libmosqcommon_EXPORT __declspec(dllexport)
#  else
#    define libmosqcommon_EXPORT  __declspec(dllimport)
#  endif
#else
#  define libmosqcommon_EXPORT
#endif

#include <mosquitto/libcommon_base64.h>
#include <mosquitto/libcommon_cjson.h>
#include <mosquitto/libcommon_file.h>
#include <mosquitto/libcommon_memory.h>
#include <mosquitto/libcommon_password.h>
#include <mosquitto/libcommon_properties.h>
#include <mosquitto/libcommon_random.h>
#include <mosquitto/libcommon_string.h>
#include <mosquitto/libcommon_time.h>
#include <mosquitto/libcommon_topic.h>
#include <mosquitto/libcommon_utf8.h>

#ifdef __cplusplus
}
#endif

#endif

