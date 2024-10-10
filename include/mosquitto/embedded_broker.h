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
*/

/*
 * File: mosquitto_broker.h
 *
 * This header contains functions for use by plugins.
 */
#ifndef MOSQUITTO_EMBEDDED_BROKER_H
#define MOSQUITTO_EMBEDDED_BROKER_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(WIN32) && defined(mosquitto_EXPORTS)
#	define mosq_EXPORT  __declspec(dllexport)
#else
#	define mosq_EXPORT
#endif

mosq_EXPORT int mosquitto_broker_main(int argc, char *argv[]);
  
}
#ifdef __cplusplus
}
#endif

#endif
