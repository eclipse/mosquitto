/*
Copyright (c) 2015-2020 Roger Light <roger@atchoo.org>

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

#ifndef SYS_TREE_H
#define SYS_TREE_H

#if defined(WITH_SYS_TREE) && defined(WITH_BROKER)
extern uint64_t g_bytes_received;
extern uint64_t g_bytes_sent;
extern uint64_t g_pub_bytes_received;
extern uint64_t g_pub_bytes_sent;
extern unsigned long g_msgs_received;
extern unsigned long g_msgs_sent;
extern unsigned long g_pub_msgs_received;
extern unsigned long g_pub_msgs_sent;
extern unsigned long g_msgs_dropped;
extern int g_clients_expired;
extern unsigned int g_socket_connections;
extern unsigned int g_connection_count;

#define G_BYTES_RECEIVED_INC(A) (g_bytes_received+=(uint64_t)(A))
#define G_BYTES_SENT_INC(A) (g_bytes_sent+=(uint64_t)(A))
#define G_PUB_BYTES_RECEIVED_INC(A) (g_pub_bytes_received+=(A))
#define G_PUB_BYTES_SENT_INC(A) (g_pub_bytes_sent+=(A))
#define G_MSGS_RECEIVED_INC(A) (g_msgs_received+=(A))
#define G_MSGS_SENT_INC(A) (g_msgs_sent+=(A))
#define G_PUB_MSGS_RECEIVED_INC(A) (g_pub_msgs_received+=(A))
#define G_PUB_MSGS_SENT_INC(A) (g_pub_msgs_sent+=(A))
#define G_MSGS_DROPPED_INC() (g_msgs_dropped++)
#define G_CLIENTS_EXPIRED_INC() (g_clients_expired++)
#define G_SOCKET_CONNECTIONS_INC() (g_socket_connections++)
#define G_CONNECTION_COUNT_INC() (g_connection_count++)

#else

#define G_BYTES_RECEIVED_INC(A)
#define G_BYTES_SENT_INC(A)
#define G_PUB_BYTES_RECEIVED_INC(A)
#define G_PUB_BYTES_SENT_INC(A)
#define G_MSGS_RECEIVED_INC(A)
#define G_MSGS_SENT_INC(A)
#define G_PUB_MSGS_RECEIVED_INC(A)
#define G_PUB_MSGS_SENT_INC(A)
#define G_MSGS_DROPPED_INC()
#define G_CLIENTS_EXPIRED_INC()
#define G_SOCKET_CONNECTIONS_INC()
#define G_CONNECTION_COUNT_INC()

#endif

#endif
