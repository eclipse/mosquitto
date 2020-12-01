/*
Copyright (c) 2010-2020 Roger Light <roger@atchoo.org>

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
#ifndef NET_MOSQ_H
#define NET_MOSQ_H

#ifndef WIN32
#  include <unistd.h>
#else
#  include <winsock2.h>
#  ifndef _SSIZE_T_DEFINED
typedef SSIZE_T ssize_t;
#    define _SSIZE_T_DEFINED
#  endif
#endif

#include "mosquitto_internal.h"
#include "mosquitto.h"

#ifdef WIN32
#  define COMPAT_CLOSE(a) closesocket(a)
#  define COMPAT_ECONNRESET WSAECONNRESET
#  define COMPAT_EINTR WSAEINTR
#  define COMPAT_EWOULDBLOCK WSAEWOULDBLOCK
#else
#  define COMPAT_CLOSE(a) close(a)
#  define COMPAT_ECONNRESET ECONNRESET
#  define COMPAT_EINTR EINTR
#  define COMPAT_EWOULDBLOCK EWOULDBLOCK
#endif

/* For when not using winsock libraries. */
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

/* Macros for accessing the MSB and LSB of a uint16_t */
#define MOSQ_MSB(A) (uint8_t)((A & 0xFF00) >> 8)
#define MOSQ_LSB(A) (uint8_t)(A & 0x00FF)

int net__init(void);
void net__cleanup(void);

#ifdef WITH_TLS
void net__init_tls(void);
#endif

int net__socket_connect(struct mosquitto *mosq, const char *host, uint16_t port, const char *bind_address, bool blocking);
int net__socket_close(struct mosquitto *mosq);
int net__try_connect(const char *host, uint16_t port, mosq_sock_t *sock, const char *bind_address, bool blocking);
int net__try_connect_step1(struct mosquitto *mosq, const char *host);
int net__try_connect_step2(struct mosquitto *mosq, uint16_t port, mosq_sock_t *sock);
int net__socket_connect_step3(struct mosquitto *mosq, const char *host);
int net__socket_nonblock(mosq_sock_t *sock);
int net__socketpair(mosq_sock_t *sp1, mosq_sock_t *sp2);

ssize_t net__read(struct mosquitto *mosq, void *buf, size_t count);
ssize_t net__write(struct mosquitto *mosq, void *buf, size_t count);

#ifdef WITH_TLS
void net__print_ssl_error(struct mosquitto *mosq);
int net__socket_apply_tls(struct mosquitto *mosq);
int net__socket_connect_tls(struct mosquitto *mosq);
int mosquitto__verify_ocsp_status_cb(SSL * ssl, void *arg);
UI_METHOD *net__get_ui_method(void);
#define ENGINE_FINISH(e) if(e) ENGINE_finish(e)
#define ENGINE_SECRET_MODE "SECRET_MODE"
#define ENGINE_SECRET_MODE_SHA 0x1000
#define ENGINE_PIN "PIN"
#endif

#endif
