/*
Copyright (c) 2021,2022 Roger Light <roger@atchoo.org>

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

#ifndef PERSIST_SQLITE_H
#define PERSIST_SQLITE_H

#include <sqlite3.h>
#include <time.h>
#include <stdint.h>

#ifndef UNUSED
#  define UNUSED(A) (void)(A)
#endif

struct mosquitto_sqlite {
	char *db_file;
	sqlite3 *db;
	sqlite3_stmt *client_add_stmt;
	sqlite3_stmt *client_remove_stmt;
	sqlite3_stmt *client_update_stmt;
	sqlite3_stmt *subscription_add_stmt;
	sqlite3_stmt *subscription_remove_stmt;
	sqlite3_stmt *subscription_clear_stmt;
	sqlite3_stmt *client_msg_add_stmt;
	sqlite3_stmt *client_msg_remove_stmt;
	sqlite3_stmt *client_msg_update_stmt;
	sqlite3_stmt *client_msg_clear_stmt;
	sqlite3_stmt *client_msg_clear_all_stmt;
	sqlite3_stmt *base_msg_add_stmt;
	sqlite3_stmt *base_msg_remove_stmt;
	sqlite3_stmt *base_msg_load_stmt;
	sqlite3_stmt *retain_msg_set_stmt;
	sqlite3_stmt *retain_msg_remove_stmt;
	time_t last_transaction;
	int synchronous;
	unsigned int event_count;
	unsigned int flush_period;
	unsigned int page_size;
};

int persist_sqlite__init(struct mosquitto_sqlite *ms);
void persist_sqlite__cleanup(struct mosquitto_sqlite *ms);

int persist_sqlite__restore_cb(int event, void *event_data, void *userdata);

int persist_sqlite__client_msg_remove(struct mosquitto_sqlite *ms, const char* clientid, int64_t store_id, int direction);

int persist_sqlite__client_add_cb(int event, void *event_data, void *userdata);
int persist_sqlite__client_update_cb(int event, void *event_data, void *userdata);
int persist_sqlite__client_remove_cb(int event, void *event_data, void *userdata);
int persist_sqlite__client_msg_add_cb(int event, void *event_data, void *userdata);
int persist_sqlite__client_msg_clear(struct mosquitto_sqlite *ms, const char *clientid);
int persist_sqlite__client_msg_remove_cb(int event, void *event_data, void *userdata);
int persist_sqlite__client_msg_update_cb(int event, void *event_data, void *userdata);
int persist_sqlite__base_msg_add_cb(int event, void *event_data, void *userdata);
int persist_sqlite__base_msg_load_cb(int event, void *event_data, void *userdata);
int persist_sqlite__base_msg_remove_cb(int event, void *event_data, void *userdata);
int persist_sqlite__retain_msg_set_cb(int event, void *event_data, void *userdata);
int persist_sqlite__retain_msg_remove_cb(int event, void *event_data, void *userdata);
int persist_sqlite__subscription_add_cb(int event, void *event_data, void *userdata);
int persist_sqlite__subscription_remove_cb(int event, void *event_data, void *userdata);
int persist_sqlite__tick_cb(int event, void *event_data, void *userdata);
#endif
