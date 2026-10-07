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

#ifdef WITH_SYS_TREE

#include "config.h"

#include <math.h>
#include <stdio.h>
#include <inttypes.h>
#include <limits.h>
#include <inttypes.h>

#include "mosquitto_broker_internal.h"
#include "sys_tree.h"

#define BUFLEN 100

#define SYS_TREE_QOS 2

#define METRIC_LOAD_1MIN 1
#define METRIC_LOAD_5MIN 2
#define METRIC_LOAD_15MIN 3

struct metric {
	int64_t current;
	int64_t next;
	const char *topic, *topic_alias;
	bool is_max;
};

struct metric_load {
	double current;
	const char *topic;
	int load_ref;
	uint8_t interval;
};

struct metric metrics[mosq_metric_max] = {
	{ 1, 0, "$SYS/broker/clients/total", NULL, false }, /* mosq_gauge_clients_total */
	{ 1, 0, "$SYS/broker/clients/maximum", NULL, true }, /* metric_clients_maximum */
	{ 1, 0, "$SYS/broker/clients/disconnected", "$SYS/broker/clients/inactive", false }, /* mosq_gauge_clients_disconnected */
	{ 1, 0, "$SYS/broker/clients/connected", "$SYS/broker/clients/active", false }, /* mosq_gauge_clients_connected */
	{ 1, 0, "$SYS/broker/clients/expired", NULL, false }, /* mosq_counter_clients_expired */
	{ 1, 0, "$SYS/broker/messages/stored", "$SYS/broker/store/messages/count", false }, /* mosq_gauge_message_store_count */
	{ 1, 0, "$SYS/broker/store/messages/bytes", NULL, false }, /* mosq_gauge_message_store_bytes */
	{ 1, 0, "$SYS/broker/subscriptions/count", NULL, false }, /* mosq_gauge_subscription_count */
	{ 1, 0, "$SYS/broker/shared_subscriptions/count", NULL, false }, /* mosq_gauge_shared_subscription_count */
	{ 1, 0, "$SYS/broker/retained messages/count", NULL, false }, /* mosq_gauge_retained_message_count */
#ifdef WITH_MEMORY_TRACKING
	{ 1, 0, "$SYS/broker/heap/current", NULL, false }, /* mosq_gauge_heap_current */
	{ 1, 0, "$SYS/broker/heap/maximum", NULL, true }, /* mosq_gauge_heap_maximum */
#else
	{ 1, 0, NULL, NULL, 0 }, /* mosq_gauge_heap_current */
	{ 1, 0, NULL, NULL, 0 }, /* mosq_gauge_heap_maximum */
#endif
	{ 1, 0, "$SYS/broker/messages/received", NULL, false }, /* mosq_counter_messages_received */
	{ 1, 0, "$SYS/broker/messages/sent", NULL, false }, /* mosq_counter_messages_sent */
	{ 1, 0, "$SYS/broker/bytes/received", NULL, false }, /* mosq_counter_bytes_received */
	{ 1, 0, "$SYS/broker/bytes/sent", NULL, false }, /* mosq_counter_bytes_sent */
	{ 1, 0, "$SYS/broker/publish/bytes/received", NULL, false }, /* mosq_counter_pub_bytes_received */
	{ 1, 0, "$SYS/broker/publish/bytes/sent", NULL, false }, /* mosq_counter_pub_bytes_sent */
	{ 1, 0, "$SYS/broker/packet/out/count", NULL, false }, /* mosq_gauge_out_packet_count */
	{ 1, 0, "$SYS/broker/packet/out/bytes", NULL, false }, /* mosq_gauge_out_packet_bytes */
	{ 1, 0, "$SYS/broker/connections/socket/count", NULL, false }, /* mosq_counter_socket_connections */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_connect_received */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_connect_sent */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_connack_received */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_connack_sent */
	{ 1, 0, "$SYS/broker/publish/messages/dropped", NULL, false }, /* mosq_counter_mqtt_publish_dropped */
	{ 1, 0, "$SYS/broker/publish/messages/received", NULL, false }, /* mosq_counter_mqtt_publish_received */
	{ 1, 0, "$SYS/broker/publish/messages/sent", NULL, false }, /* mosq_counter_mqtt_publish_sent */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_puback_received */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_puback_sent */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_pubrec_received */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_pubrec_sent */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_pubrel_received */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_pubrel_sent */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_pubcomp_received */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_pubcomp_sent */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_subscribe_received */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_subscribe_sent */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_suback_received */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_suback_sent */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_unsubscribe_received */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_unsubscribe_sent */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_unsuback_received */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_unsuback_sent */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_pingreq_received */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_pingreq_sent */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_pingresp_received */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_pingresp_sent */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_disconnect_received */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_disconnect_sent */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_auth_received */
	{ 1, 0, NULL, NULL, false }, /* mosq_counter_mqtt_auth_sent */
};

struct metric_load metric_loads[mosq_metric_load_max] = {
	{ 0.0, "$SYS/broker/load/messages/received/1min", mosq_counter_messages_received, METRIC_LOAD_1MIN }, /* metric_load_messages_received_1min */
	{ 0.0, "$SYS/broker/load/messages/received/5min", mosq_counter_messages_received, METRIC_LOAD_5MIN }, /* metric_load_messages_received_5min */
	{ 0.0, "$SYS/broker/load/messages/received/15min", mosq_counter_messages_received, METRIC_LOAD_15MIN }, /* metric_load_messages_received_15min */
	{ 0.0, "$SYS/broker/load/messages/sent/1min", mosq_counter_messages_sent, METRIC_LOAD_1MIN }, /* metric_load_messages_sent_1min */
	{ 0.0, "$SYS/broker/load/messages/sent/5min", mosq_counter_messages_sent, METRIC_LOAD_5MIN }, /* metric_load_messages_sent_5min */
	{ 0.0, "$SYS/broker/load/messages/sent/15min", mosq_counter_messages_sent, METRIC_LOAD_15MIN }, /* metric_load_messages_sent_15min */
	{ 0.0, "$SYS/broker/load/publish/dropped/1min", mosq_counter_mqtt_publish_dropped, METRIC_LOAD_1MIN }, /* metric_load_pub_messages_dropped_1min */
	{ 0.0, "$SYS/broker/load/publish/dropped/5min", mosq_counter_mqtt_publish_dropped, METRIC_LOAD_5MIN }, /* metric_load_pub_messages_dropped_5min */
	{ 0.0, "$SYS/broker/load/publish/dropped/15min", mosq_counter_mqtt_publish_dropped, METRIC_LOAD_15MIN }, /* metric_load_pub_messages_dropped_15min */
	{ 0.0, "$SYS/broker/load/publish/received/1min", mosq_counter_mqtt_publish_received, METRIC_LOAD_1MIN }, /* metric_load_pub_messages_received_1min */
	{ 0.0, "$SYS/broker/load/publish/received/5min", mosq_counter_mqtt_publish_received, METRIC_LOAD_5MIN }, /* metric_load_pub_messages_received_5min */
	{ 0.0, "$SYS/broker/load/publish/received/15min", mosq_counter_mqtt_publish_received, METRIC_LOAD_15MIN }, /* metric_load_pub_messages_received_15min */
	{ 0.0, "$SYS/broker/load/publish/sent/1min", mosq_counter_mqtt_publish_sent, METRIC_LOAD_1MIN }, /* metric_load_pub_messages_sent_1min */
	{ 0.0, "$SYS/broker/load/publish/sent/5min", mosq_counter_mqtt_publish_sent, METRIC_LOAD_5MIN }, /* metric_load_pub_messages_sent_5min */
	{ 0.0, "$SYS/broker/load/publish/sent/15min", mosq_counter_mqtt_publish_sent, METRIC_LOAD_15MIN }, /* metric_load_pub_messages_sent_15min */
	{ 0.0, "$SYS/broker/load/bytes/received/1min", mosq_counter_bytes_received, METRIC_LOAD_1MIN }, /* metric_load_bytes_received_1min */
	{ 0.0, "$SYS/broker/load/bytes/received/5min", mosq_counter_bytes_received, METRIC_LOAD_5MIN }, /* metric_load_bytes_received_5min */
	{ 0.0, "$SYS/broker/load/bytes/received/15min", mosq_counter_bytes_received, METRIC_LOAD_15MIN }, /* metric_load_bytes_received_15min */
	{ 0.0, "$SYS/broker/load/bytes/sent/1min", mosq_counter_bytes_sent, METRIC_LOAD_1MIN }, /* metric_load_bytes_sent_1min */
	{ 0.0, "$SYS/broker/load/bytes/sent/5min", mosq_counter_bytes_sent, METRIC_LOAD_5MIN }, /* metric_load_bytes_sent_5min */
	{ 0.0, "$SYS/broker/load/bytes/sent/15min", mosq_counter_bytes_sent, METRIC_LOAD_15MIN }, /* metric_load_bytes_sent_15min */
	{ 0.0, "$SYS/broker/load/sockets/1min", mosq_counter_socket_connections, METRIC_LOAD_1MIN }, /* metric_load_socket_connections_1min */
	{ 0.0, "$SYS/broker/load/sockets/5min", mosq_counter_socket_connections, METRIC_LOAD_5MIN }, /* metric_load_socket_connections_5min */
	{ 0.0, "$SYS/broker/load/sockets/15min", mosq_counter_socket_connections, METRIC_LOAD_15MIN }, /* metric_load_socket_connections_15min */
	{ 0.0, "$SYS/broker/load/connections/1min", mosq_counter_mqtt_connect_received, METRIC_LOAD_1MIN }, /* metric_load_connections_1min */
	{ 0.0, "$SYS/broker/load/connections/5min", mosq_counter_mqtt_connect_received, METRIC_LOAD_5MIN }, /* metric_load_connections_5min */
	{ 0.0, "$SYS/broker/load/connections/15min", mosq_counter_mqtt_connect_received, METRIC_LOAD_15MIN }, /* metric_load_connections_15min */
};

static time_t start_time = 0;
static time_t last_update = 0;


time_t broker_uptime(void)
{
	return db.now_s - start_time;
}


static void calc_load(char *buf, double exponent, double i_mult, struct metric_load *m, bool force)
{
	double new_value;
	uint32_t len;
	double interval;

	interval = (double)(metrics[m->load_ref].next - metrics[m->load_ref].current)*i_mult;
	new_value = interval + exponent*(m->current - interval);
	if(fabs(new_value - (m->current)) >= 0.01 || force){
		len = (uint32_t)snprintf(buf, BUFLEN, "%.2f", new_value);
		db__messages_easy_queue(NULL, m->topic, SYS_TREE_QOS, len, buf, 1, MSG_EXPIRY_INFINITE, NULL);
	}
	m->current = new_value;
}


void sys_tree__init(void)
{
	char buf[BUFLEN];
	uint32_t len;

	if(db.config->sys_interval == 0){
		return;
	}

	/* Set static $SYS messages */
	len = (uint32_t)snprintf(buf, 64, "mosquitto version %s", VERSION);
	db__messages_easy_queue(NULL, "$SYS/broker/version", SYS_TREE_QOS, len, buf, 1, MSG_EXPIRY_INFINITE, NULL);

	start_time = mosquitto_time();
	last_update = start_time;

	sys_tree__update(true);

	/* Force published load values to 0 */
	for(int i=0; i<mosq_metric_load_max; i++){
		if(metric_loads[i].interval == METRIC_LOAD_1MIN){
			calc_load(buf, 0.0, 0.0, &metric_loads[i], true);
		}else if(metric_loads[i].interval == METRIC_LOAD_5MIN){
			calc_load(buf, 0.0, 0.0, &metric_loads[i], true);
		}else{
			calc_load(buf, 0.0, 0.0, &metric_loads[i], true);
		}
	}
}


void metrics__int_inc(enum mosq_metric_type m, int64_t value)
{
	if(m < mosq_metric_max){
		metrics[m].next += value;
	}
}


void metrics__int_dec(enum mosq_metric_type m, int64_t value)
{
	if(m < mosq_metric_max){
		metrics[m].next -= value;
	}
}


/* Send messages for the $SYS hierarchy if the last update is longer than
 * 'interval' seconds ago.
 * 'interval' is the amount of seconds between updates. If 0, then no periodic
 * messages are sent for the $SYS hierarchy.
 * 'start_time' is the result of time() that the broker was started at.
 */
void sys_tree__update(bool force)
{
	time_t uptime;
	char buf[BUFLEN];
	uint32_t len;
	time_t next_event;
	static time_t last_update_real = 0;

	if(db.config->sys_interval){
		next_event = db.config->sys_interval - db.now_real_s % db.config->sys_interval - 1;
		if(next_event <= 0){
			next_event = db.config->sys_interval;
		}
		loop__update_next_event(next_event*1000);
	}

	if(db.config->sys_interval
			&& ((db.now_real_s % db.config->sys_interval == 0 && last_update_real != db.now_real_s) || force)){

		uptime = db.now_s - start_time;
		len = (uint32_t)snprintf(buf, BUFLEN, "%" PRIu64 " seconds", (uint64_t)uptime);
		db__messages_easy_queue(NULL, "$SYS/broker/uptime", SYS_TREE_QOS, len, buf, 1, MSG_EXPIRY_INFINITE, NULL);

		/*  Update metrics values where not otherwise updated */
		metrics[mosq_gauge_message_store_count].next = db.msg_store_count;
		metrics[mosq_gauge_message_store_bytes].next = (int64_t)db.msg_store_bytes;
		metrics[mosq_gauge_subscriptions].next = db.subscription_count;
		metrics[mosq_gauge_shared_subscriptions].next = db.shared_subscription_count;
		metrics[mosq_gauge_retained_messages].next = db.retained_count;
#ifdef WITH_MEMORY_TRACKING
		metrics[mosq_gauge_heap_current].next = (int64_t)mosquitto_memory_used();
		metrics[mosq_counter_heap_maximum].next = (int64_t)mosquitto_max_memory_used();
#endif
		metrics[mosq_gauge_clients_total].next = HASH_CNT(hh_id, db.contexts_by_id);
		metrics[mosq_counter_clients_maximum].next = HASH_CNT(hh_id, db.contexts_by_id);
		metrics[mosq_gauge_clients_connected].next = HASH_CNT(hh_sock, db.contexts_by_sock);
		metrics[mosq_gauge_clients_disconnected].next = HASH_CNT(hh_id, db.contexts_by_id) - HASH_CNT(hh_sock, db.contexts_by_sock);

		/* Handle loads first, because they reference other metrics and need next != current */
		if(db.now_s > last_update){
			double i_mult = 60.0/(double)(db.now_s-last_update);

			double exponent_1min = exp(-1.0*(double)(db.now_s-last_update)/60.0);
			double exponent_5min = exp(-1.0*(double)(db.now_s-last_update)/300.0);
			double exponent_15min = exp(-1.0*(double)(db.now_s-last_update)/900.0);

			for(int i=0; i<mosq_metric_load_max; i++){
				if(metric_loads[i].interval == METRIC_LOAD_1MIN){
					calc_load(buf, exponent_1min, i_mult, &metric_loads[i], false);
				}else if(metric_loads[i].interval == METRIC_LOAD_5MIN){
					calc_load(buf, exponent_5min, i_mult, &metric_loads[i], false);
				}else{
					calc_load(buf, exponent_15min, i_mult, &metric_loads[i], false);
				}
			}
		}

		for(int i=0; i<mosq_metric_max; i++){
			if((metrics[i].is_max && metrics[i].next > metrics[i].current) ||
					(!metrics[i].is_max && metrics[i].next != metrics[i].current)){

				metrics[i].current = metrics[i].next;
				len = (uint32_t)snprintf(buf, BUFLEN, "%lu", metrics[i].current);
				if(metrics[i].topic){
					db__messages_easy_queue(NULL, metrics[i].topic, SYS_TREE_QOS, len, buf, 1, MSG_EXPIRY_INFINITE, NULL);
				}
				if(metrics[i].topic_alias){
					db__messages_easy_queue(NULL, metrics[i].topic_alias, SYS_TREE_QOS, len, buf, 1, MSG_EXPIRY_INFINITE, NULL);
				}
			}
		}

		last_update = db.now_s;
		last_update_real = db.now_real_s;
	}
}

#endif
