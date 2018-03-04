/*
Copyright (c) 2010-2018 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
*/
#ifndef _NET_MOSQ_H_
#define _NET_MOSQ_H_

#ifndef WIN32
#include <unistd.h>
#else
#include <winsock2.h>
typedef int ssize_t;
#endif

#include <mosquitto_internal.h>
#include <mosquitto.h>

#ifdef WITH_BROKER
struct mosquitto_db;
#endif

#ifdef WIN32
#  define COMPAT_CLOSE(a) closesocket(a)
#  define COMPAT_ECONNRESET WSAECONNRESET
#  define COMPAT_EWOULDBLOCK WSAEWOULDBLOCK
#else
#  define COMPAT_CLOSE(a) close(a)
#  define COMPAT_ECONNRESET ECONNRESET
#  define COMPAT_EWOULDBLOCK EWOULDBLOCK
#endif

/* For when not using winsock libraries. */
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

/* Macros for accessing the MSB and LSB of a uint16_t */
#define MOSQ_MSB(A) (uint8_t)((A & 0xFF00) >> 8)
#define MOSQ_LSB(A) (uint8_t)(A & 0x00FF)

void _mosquitto_net_init(void);
void _mosquitto_net_cleanup(void);

void _mosquitto_packet_cleanup(struct _mosquitto_packet *packet);
int _mosquitto_packet_queue(struct mosquitto *mosq, struct _mosquitto_packet *packet);
int _mosquitto_socket_connect(struct mosquitto *mosq, const char *host, uint16_t port, const char *bind_address, bool blocking);
#ifdef WITH_BROKER
int _mosquitto_socket_close(struct mosquitto_db *db, struct mosquitto *mosq);
#else
int _mosquitto_socket_close(struct mosquitto *mosq);
#endif
int _mosquitto_try_connect(struct mosquitto *mosq, const char *host, uint16_t port, mosq_sock_t *sock, const char *bind_address, bool blocking);
int _mosquitto_try_connect_step1(struct mosquitto *mosq, const char *host);
int _mosquitto_try_connect_step2(struct mosquitto *mosq, uint16_t port, mosq_sock_t *sock);
int _mosquitto_socket_connect_step3(struct mosquitto *mosq, const char *host, uint16_t port, const char *bind_address, bool blocking);
int _mosquitto_socket_nonblock(mosq_sock_t sock);
int _mosquitto_socketpair(mosq_sock_t *sp1, mosq_sock_t *sp2);

int _mosquitto_read_byte(struct _mosquitto_packet *packet, uint8_t *byte);
int _mosquitto_read_bytes(struct _mosquitto_packet *packet, void *bytes, uint32_t count);
int _mosquitto_read_string(struct _mosquitto_packet *packet, char **str);
int _mosquitto_read_uint16(struct _mosquitto_packet *packet, uint16_t *word);

void _mosquitto_write_byte(struct _mosquitto_packet *packet, uint8_t byte);
void _mosquitto_write_bytes(struct _mosquitto_packet *packet, const void *bytes, uint32_t count);
void _mosquitto_write_string(struct _mosquitto_packet *packet, const char *str, uint16_t length);
void _mosquitto_write_uint16(struct _mosquitto_packet *packet, uint16_t word);

ssize_t _mosquitto_net_read(struct mosquitto *mosq, void *buf, size_t count);
ssize_t _mosquitto_net_write(struct mosquitto *mosq, void *buf, size_t count);

int _mosquitto_packet_write(struct mosquitto *mosq);
#ifdef WITH_BROKER
int _mosquitto_packet_read(struct mosquitto_db *db, struct mosquitto *mosq);
#else
int _mosquitto_packet_read(struct mosquitto *mosq);
#endif

#ifdef WITH_TLS
int _mosquitto_socket_apply_tls(struct mosquitto *mosq);
int mosquitto__socket_connect_tls(struct mosquitto *mosq);
#endif

#endif
