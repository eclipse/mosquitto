/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>

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

#ifndef MUX_H
#define MUX_H

#include "mosquitto_broker_internal.h"

int mux_epoll__init(struct mosquitto__listener_sock *listensock, int listensock_count);
int mux_epoll__add_out(struct mosquitto *context);
int mux_epoll__remove_out(struct mosquitto *context);
int mux_epoll__add_in(struct mosquitto *context);
int mux_epoll__delete(struct mosquitto *context);
int mux_epoll__handle(struct mosquitto__listener_sock *listensock, int listensock_count);
int mux_epoll__cleanup(void);

int mux_poll__init(struct mosquitto__listener_sock *listensock, int listensock_count);
int mux_poll__add_out(struct mosquitto *context);
int mux_poll__remove_out(struct mosquitto *context);
int mux_poll__add_in(struct mosquitto *context);
int mux_poll__delete(struct mosquitto *context);
int mux_poll__handle(struct mosquitto__listener_sock *listensock, int listensock_count);
int mux_poll__cleanup(void);

#endif
