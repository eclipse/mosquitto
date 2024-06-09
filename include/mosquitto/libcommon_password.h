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

#ifndef MOSQUITTO_LIBCOMMON_PASSWORD_H
#define MOSQUITTO_LIBCOMMON_PASSWORD_H

/*
 * File: mosquitto/libcommon_password.h
 */
#ifdef __cplusplus
extern "C" {
#endif

enum mosquitto_pwhash_type{
	MOSQ_PW_DEFAULT,
	MOSQ_PW_SHA512 = 6,
	MOSQ_PW_SHA512_PBKDF2 = 7,
	MOSQ_PW_ARGON2ID = 8,
};

enum mosquitto_pw_params{
	MOSQ_PW_PARAM_ITERATIONS = 1,
};

struct mosquitto_pw;

libmosqcommon_EXPORT void mosquitto_pw_set_valid(struct mosquitto_pw *pw, bool valid);
libmosqcommon_EXPORT bool mosquitto_pw_is_valid(struct mosquitto_pw *pw);

libmosqcommon_EXPORT int mosquitto_pw_new(struct mosquitto_pw **pw, enum mosquitto_pwhash_type hashtype);
libmosqcommon_EXPORT void mosquitto_pw_cleanup(struct mosquitto_pw *pw);
libmosqcommon_EXPORT int mosquitto_pw_hash_encoded(struct mosquitto_pw *pw, const char *password);
libmosqcommon_EXPORT const char *mosquitto_pw_get_encoded(struct mosquitto_pw *pw);
libmosqcommon_EXPORT int mosquitto_pw_verify(struct mosquitto_pw *pw, const char *password);
libmosqcommon_EXPORT int mosquitto_pw_set_param(struct mosquitto_pw *pw, int param, int value);
libmosqcommon_EXPORT int mosquitto_pw_decode(struct mosquitto_pw *pw, const char *encoded_password);

#ifdef __cplusplus
}
#endif

#endif

