/*
Copyright (c) 2009-2018 Roger Light <roger@atchoo.org>

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

#ifdef WITH_SYS_TREE

#include <math.h>
#include <stdio.h>

#include <config.h>

#include <mosquitto_broker.h>
#include <memory_mosq.h>
#include <time_mosq.h>

#define BUFLEN 100

uint64_t g_bytes_received = 0;
uint64_t g_bytes_sent = 0;
uint64_t g_pub_bytes_received = 0;
uint64_t g_pub_bytes_sent = 0;
unsigned long g_msgs_received = 0;
unsigned long g_msgs_sent = 0;
unsigned long g_pub_msgs_received = 0;
unsigned long g_pub_msgs_sent = 0;
unsigned long g_msgs_dropped = 0;
int g_clients_expired = 0;
unsigned int g_socket_connections = 0;
unsigned int g_connection_count = 0;

static void _sys_update_clients(struct mosquitto_db *db, char *buf)
{
	static unsigned int client_count = -1;
	static int clients_expired = -1;
	static unsigned int client_max = 0;
	static unsigned int disconnected_count = -1;
	static unsigned int connected_count = -1;

	unsigned int count_total, count_by_sock;

	count_total = HASH_CNT(hh_id, db->contexts_by_id);
	count_by_sock = HASH_CNT(hh_sock, db->contexts_by_sock);

	if(client_count != count_total){
		client_count = count_total;
		snprintf(buf, BUFLEN, "%d", client_count);
		mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/clients/total", 2, strlen(buf), buf, 1);

		if(client_count > client_max){
			client_max = client_count;
			snprintf(buf, BUFLEN, "%d", client_max);
			mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/clients/maximum", 2, strlen(buf), buf, 1);
		}
	}

	if(disconnected_count != count_total-count_by_sock){
		disconnected_count = count_total-count_by_sock;
		snprintf(buf, BUFLEN, "%d", disconnected_count);
		mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/clients/inactive", 2, strlen(buf), buf, 1);
		mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/clients/disconnected", 2, strlen(buf), buf, 1);
	}
	if(connected_count != count_by_sock){
		connected_count = count_by_sock;
		snprintf(buf, BUFLEN, "%d", connected_count);
		mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/clients/active", 2, strlen(buf), buf, 1);
		mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/clients/connected", 2, strlen(buf), buf, 1);
	}
	if(g_clients_expired != clients_expired){
		clients_expired = g_clients_expired;
		snprintf(buf, BUFLEN, "%d", clients_expired);
		mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/clients/expired", 2, strlen(buf), buf, 1);
	}
}

#ifdef REAL_WITH_MEMORY_TRACKING
static void _sys_update_memory(struct mosquitto_db *db, char *buf)
{
	static unsigned long current_heap = -1;
	static unsigned long max_heap = -1;
	unsigned long value_ul;

	value_ul = _mosquitto_memory_used();
	if(current_heap != value_ul){
		current_heap = value_ul;
		snprintf(buf, BUFLEN, "%lu", current_heap);
		mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/heap/current", 2, strlen(buf), buf, 1);
	}
	value_ul =_mosquitto_max_memory_used();
	if(max_heap != value_ul){
		max_heap = value_ul;
		snprintf(buf, BUFLEN, "%lu", max_heap);
		mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/heap/maximum", 2, strlen(buf), buf, 1);
	}
}
#endif

static void calc_load(struct mosquitto_db *db, char *buf, const char *topic, double exponent, double interval, double *current)
{
	double new_value;

	new_value = interval + exponent*((*current) - interval);
	if(fabs(new_value - (*current)) >= 0.01){
		snprintf(buf, BUFLEN, "%.2f", new_value);
		mqtt3_db_messages_easy_queue(db, NULL, topic, 2, strlen(buf), buf, 1);
	}
	(*current) = new_value;
}

/* Send messages for the $SYS hierarchy if the last update is longer than
 * 'interval' seconds ago.
 * 'interval' is the amount of seconds between updates. If 0, then no periodic
 * messages are sent for the $SYS hierarchy.
 * 'start_time' is the result of time() that the broker was started at.
 */
void mqtt3_db_sys_update(struct mosquitto_db *db, int interval, time_t start_time)
{
	static time_t last_update = 0;
	time_t now;
	time_t uptime;
	char buf[BUFLEN];

	static int msg_store_count = -1;
	static unsigned long msgs_received = -1;
	static unsigned long msgs_sent = -1;
	static unsigned long publish_dropped = -1;
	static unsigned long pub_msgs_received = -1;
	static unsigned long pub_msgs_sent = -1;
	static unsigned long long bytes_received = -1;
	static unsigned long long bytes_sent = -1;
	static unsigned long long pub_bytes_received = -1;
	static unsigned long long pub_bytes_sent = -1;
	static int subscription_count = -1;
	static int retained_count = -1;

	static double msgs_received_load1 = 0;
	static double msgs_received_load5 = 0;
	static double msgs_received_load15 = 0;
	static double msgs_sent_load1 = 0;
	static double msgs_sent_load5 = 0;
	static double msgs_sent_load15 = 0;
	static double publish_dropped_load1 = 0;
	static double publish_dropped_load5 = 0;
	static double publish_dropped_load15 = 0;
	double msgs_received_interval, msgs_sent_interval, publish_dropped_interval;

	static double publish_received_load1 = 0;
	static double publish_received_load5 = 0;
	static double publish_received_load15 = 0;
	static double publish_sent_load1 = 0;
	static double publish_sent_load5 = 0;
	static double publish_sent_load15 = 0;
	double publish_received_interval, publish_sent_interval;

	static double bytes_received_load1 = 0;
	static double bytes_received_load5 = 0;
	static double bytes_received_load15 = 0;
	static double bytes_sent_load1 = 0;
	static double bytes_sent_load5 = 0;
	static double bytes_sent_load15 = 0;
	double bytes_received_interval, bytes_sent_interval;

	static double socket_load1 = 0;
	static double socket_load5 = 0;
	static double socket_load15 = 0;
	double socket_interval;

	static double connection_load1 = 0;
	static double connection_load5 = 0;
	static double connection_load15 = 0;
	double connection_interval;

	double exponent;
	double i_mult;

	now = mosquitto_time();

	if(interval && now - interval > last_update){
		uptime = now - start_time;
		snprintf(buf, BUFLEN, "%d seconds", (int)uptime);
		mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/uptime", 2, strlen(buf), buf, 1);

		_sys_update_clients(db, buf);
		if(last_update > 0){
			i_mult = 60.0/(double)(now-last_update);

			msgs_received_interval = (g_msgs_received - msgs_received)*i_mult;
			msgs_sent_interval = (g_msgs_sent - msgs_sent)*i_mult;
			publish_dropped_interval = (g_msgs_dropped - publish_dropped)*i_mult;

			publish_received_interval = (g_pub_msgs_received - pub_msgs_received)*i_mult;
			publish_sent_interval = (g_pub_msgs_sent - pub_msgs_sent)*i_mult;

			bytes_received_interval = (g_bytes_received - bytes_received)*i_mult;
			bytes_sent_interval = (g_bytes_sent - bytes_sent)*i_mult;

			socket_interval = g_socket_connections*i_mult;
			g_socket_connections = 0;
			connection_interval = g_connection_count*i_mult;
			g_connection_count = 0;

			/* 1 minute load */
			exponent = exp(-1.0*(now-last_update)/60.0);

			calc_load(db, buf, "$SYS/broker/load/messages/received/1min", exponent, msgs_received_interval, &msgs_received_load1);
			calc_load(db, buf, "$SYS/broker/load/messages/sent/1min", exponent, msgs_sent_interval, &msgs_sent_load1);
			calc_load(db, buf, "$SYS/broker/load/publish/dropped/1min", exponent, publish_dropped_interval, &publish_dropped_load1);
			calc_load(db, buf, "$SYS/broker/load/publish/received/1min", exponent, publish_received_interval, &publish_received_load1);
			calc_load(db, buf, "$SYS/broker/load/publish/sent/1min", exponent, publish_sent_interval, &publish_sent_load1);
			calc_load(db, buf, "$SYS/broker/load/bytes/received/1min", exponent, bytes_received_interval, &bytes_received_load1);
			calc_load(db, buf, "$SYS/broker/load/bytes/sent/1min", exponent, bytes_sent_interval, &bytes_sent_load1);
			calc_load(db, buf, "$SYS/broker/load/sockets/1min", exponent, socket_interval, &socket_load1);
			calc_load(db, buf, "$SYS/broker/load/connections/1min", exponent, connection_interval, &connection_load1);

			/* 5 minute load */
			exponent = exp(-1.0*(now-last_update)/300.0);

			calc_load(db, buf, "$SYS/broker/load/messages/received/5min", exponent, msgs_received_interval, &msgs_received_load5);
			calc_load(db, buf, "$SYS/broker/load/messages/sent/5min", exponent, msgs_sent_interval, &msgs_sent_load5);
			calc_load(db, buf, "$SYS/broker/load/publish/dropped/5min", exponent, publish_dropped_interval, &publish_dropped_load5);
			calc_load(db, buf, "$SYS/broker/load/publish/received/5min", exponent, publish_received_interval, &publish_received_load5);
			calc_load(db, buf, "$SYS/broker/load/publish/sent/5min", exponent, publish_sent_interval, &publish_sent_load5);
			calc_load(db, buf, "$SYS/broker/load/bytes/received/5min", exponent, bytes_received_interval, &bytes_received_load5);
			calc_load(db, buf, "$SYS/broker/load/bytes/sent/5min", exponent, bytes_sent_interval, &bytes_sent_load5);
			calc_load(db, buf, "$SYS/broker/load/sockets/5min", exponent, socket_interval, &socket_load5);
			calc_load(db, buf, "$SYS/broker/load/connections/5min", exponent, connection_interval, &connection_load5);

			/* 15 minute load */
			exponent = exp(-1.0*(now-last_update)/900.0);

			calc_load(db, buf, "$SYS/broker/load/messages/received/15min", exponent, msgs_received_interval, &msgs_received_load15);
			calc_load(db, buf, "$SYS/broker/load/messages/sent/15min", exponent, msgs_sent_interval, &msgs_sent_load15);
			calc_load(db, buf, "$SYS/broker/load/publish/dropped/15min", exponent, publish_dropped_interval, &publish_dropped_load15);
			calc_load(db, buf, "$SYS/broker/load/publish/received/15min", exponent, publish_received_interval, &publish_received_load15);
			calc_load(db, buf, "$SYS/broker/load/publish/sent/15min", exponent, publish_sent_interval, &publish_sent_load15);
			calc_load(db, buf, "$SYS/broker/load/bytes/received/15min", exponent, bytes_received_interval, &bytes_received_load15);
			calc_load(db, buf, "$SYS/broker/load/bytes/sent/15min", exponent, bytes_sent_interval, &bytes_sent_load15);
			calc_load(db, buf, "$SYS/broker/load/sockets/15min", exponent, socket_interval, &socket_load15);
			calc_load(db, buf, "$SYS/broker/load/connections/15min", exponent, connection_interval, &connection_load15);
		}

		if(db->msg_store_count != msg_store_count){
			msg_store_count = db->msg_store_count;
			snprintf(buf, BUFLEN, "%d", msg_store_count);
			mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/messages/stored", 2, strlen(buf), buf, 1);
		}

		if(db->subscription_count != subscription_count){
			subscription_count = db->subscription_count;
			snprintf(buf, BUFLEN, "%d", subscription_count);
			mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/subscriptions/count", 2, strlen(buf), buf, 1);
		}

		if(db->retained_count != retained_count){
			retained_count = db->retained_count;
			snprintf(buf, BUFLEN, "%d", retained_count);
			mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/retained messages/count", 2, strlen(buf), buf, 1);
		}

#ifdef REAL_WITH_MEMORY_TRACKING
		_sys_update_memory(db, buf);
#endif

		if(msgs_received != g_msgs_received){
			msgs_received = g_msgs_received;
			snprintf(buf, BUFLEN, "%lu", msgs_received);
			mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/messages/received", 2, strlen(buf), buf, 1);
		}
		
		if(msgs_sent != g_msgs_sent){
			msgs_sent = g_msgs_sent;
			snprintf(buf, BUFLEN, "%lu", msgs_sent);
			mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/messages/sent", 2, strlen(buf), buf, 1);
		}

		if(publish_dropped != g_msgs_dropped){
			publish_dropped = g_msgs_dropped;
			snprintf(buf, BUFLEN, "%lu", publish_dropped);
			mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/publish/messages/dropped", 2, strlen(buf), buf, 1);
		}

		if(pub_msgs_received != g_pub_msgs_received){
			pub_msgs_received = g_pub_msgs_received;
			snprintf(buf, BUFLEN, "%lu", pub_msgs_received);
			mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/publish/messages/received", 2, strlen(buf), buf, 1);
		}
		
		if(pub_msgs_sent != g_pub_msgs_sent){
			pub_msgs_sent = g_pub_msgs_sent;
			snprintf(buf, BUFLEN, "%lu", pub_msgs_sent);
			mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/publish/messages/sent", 2, strlen(buf), buf, 1);
		}

		if(bytes_received != g_bytes_received){
			bytes_received = g_bytes_received;
			snprintf(buf, BUFLEN, "%llu", bytes_received);
			mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/bytes/received", 2, strlen(buf), buf, 1);
		}
		
		if(bytes_sent != g_bytes_sent){
			bytes_sent = g_bytes_sent;
			snprintf(buf, BUFLEN, "%llu", bytes_sent);
			mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/bytes/sent", 2, strlen(buf), buf, 1);
		}
		
		if(pub_bytes_received != g_pub_bytes_received){
			pub_bytes_received = g_pub_bytes_received;
			snprintf(buf, BUFLEN, "%llu", pub_bytes_received);
			mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/publish/bytes/received", 2, strlen(buf), buf, 1);
		}

		if(pub_bytes_sent != g_pub_bytes_sent){
			pub_bytes_sent = g_pub_bytes_sent;
			snprintf(buf, BUFLEN, "%llu", pub_bytes_sent);
			mqtt3_db_messages_easy_queue(db, NULL, "$SYS/broker/publish/bytes/sent", 2, strlen(buf), buf, 1);
		}

		last_update = mosquitto_time();
	}
}

#endif
