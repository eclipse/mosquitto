/*
Copyright (c) 2021 Roger Light <roger@atchoo.org>

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

#include <stdio.h>
#include <sqlite3.h>

#include "persist_sqlite.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"

static int create_tables(struct mosquitto_sqlite *ms)
{
	int rc;

	rc = sqlite3_exec(ms->db,
			"CREATE TABLE IF NOT EXISTS base_msgs "
			"("
				"store_id INT64 PRIMARY KEY,"
				"expiry_time INT64,"
				"topic STRING NOT NULL,"
				"payload BLOB,"
				"source_id STRING,"
				"source_username STRING,"
				"payloadlen INTEGER,"
				"source_mid INTEGER,"
				"source_port INTEGER,"
				"qos INTEGER,"
				"retain INTEGER,"
				"properties STRING"
			");",
			NULL, NULL, NULL);
	if(rc) goto fail;

	rc = sqlite3_exec(ms->db,
			"CREATE TABLE IF NOT EXISTS retains "
			"("
				"topic STRING PRIMARY KEY,"
				"store_id INT64"
				//"FOREIGN KEY (store_id) REFERENCES msg_store(store_id) "
				//"ON DELETE CASCADE"
			");",
			NULL, NULL, NULL);
	if(rc) goto fail;

	rc = sqlite3_exec(ms->db,
			"CREATE TABLE IF NOT EXISTS clients "
			"("
				"client_id TEXT PRIMARY KEY,"
				"username TEXT,"
				"connection_time INT64,"
				"will_delay_time INT64,"
				"session_expiry_time INT64,"
				"listener_port INT,"
				"max_packet_size INT,"
				"max_qos INT,"
				"retain_available INT,"
				"session_expiry_interval INT,"
				"will_delay_interval INT"
			");",
			NULL, NULL, NULL);
	if(rc) goto fail;

	rc = sqlite3_exec(ms->db,
			"CREATE TABLE IF NOT EXISTS subscriptions "
			"("
				"client_id TEXT NOT NULL,"
				"topic TEXT NOT NULL,"
				"subscription_options INTEGER,"
				"subscription_identifier INTEGER,"
				"PRIMARY KEY (client_id, topic) "
			");",
			NULL, NULL, NULL);
	if(rc) goto fail;

	rc = sqlite3_exec(ms->db,
			"CREATE TABLE IF NOT EXISTS client_msgs "
			"("
				"client_id TEXT NOT NULL,"
				"store_id INT64,"
				"dup INTEGER,"
				"direction INTEGER,"
				"mid INTEGER,"
				"qos INTEGER,"
				"retain INTEGER,"
				"state INTEGER"
				//"state INTEGER,"
				//"FOREIGN KEY (client_id) REFERENCES clients(client_id) "
				//"ON DELETE CASCADE,"
				//"FOREIGN KEY (store_id) REFERENCES msg_store(store_id) "
				//"ON DELETE CASCADE"
			");",
			NULL, NULL, NULL);
	if(rc) goto fail;

	rc = sqlite3_exec(ms->db,
			"CREATE INDEX IF NOT EXISTS client_msgs_client_id ON client_msgs(client_id);",
			NULL, NULL, NULL);
	if(rc) goto fail;
	rc = sqlite3_exec(ms->db,
			"CREATE INDEX IF NOT EXISTS client_msgs_store_id ON client_msgs(store_id);",
			NULL, NULL, NULL);
	if(rc) goto fail;

	return 0;
fail:
	mosquitto_log_printf(MOSQ_LOG_ERR, "Sqlite persistence: Error creating tables: %s", sqlite3_errstr(rc));
	sqlite3_close(ms->db);
	ms->db = NULL;
	return 1;
}


static int prepare_statements(struct mosquitto_sqlite *ms)
{
	int rc;

	/* Subscriptions */
	rc = sqlite3_prepare_v3(ms->db,
			"INSERT OR REPLACE INTO subscriptions "
				"(client_id, topic, subscription_options, subscription_identifier) "
				"VALUES (?,?,?,?)",
			-1, SQLITE_PREPARE_PERSISTENT,
			&ms->subscription_add_stmt, NULL);
	if(rc) goto fail;

	rc = sqlite3_prepare_v3(ms->db,
			"DELETE FROM subscriptions WHERE client_id=? and topic=?",
			-1, SQLITE_PREPARE_PERSISTENT,
			&ms->subscription_remove_stmt, NULL);
	if(rc) goto fail;

	rc = sqlite3_prepare_v3(ms->db,
			"DELETE FROM subscriptions WHERE client_id=?",
			-1, SQLITE_PREPARE_PERSISTENT,
			&ms->subscription_clear_stmt, NULL);
	if(rc) goto fail;


	/* Clients */
	rc = sqlite3_prepare_v3(ms->db,
			"INSERT OR REPLACE INTO clients "
				"(client_id, username, connection_time, will_delay_time, session_expiry_time, "
				"listener_port, max_packet_size, max_qos, retain_available, "
				"session_expiry_interval, will_delay_interval) "
				"VALUES(?,?,?,?,?,?,?,?,?,?,?)",
			-1, SQLITE_PREPARE_PERSISTENT,
			&ms->client_add_stmt, NULL);
	if(rc) goto fail;

	rc = sqlite3_prepare_v3(ms->db,
			"DELETE FROM clients WHERE client_id=?",
			-1, SQLITE_PREPARE_PERSISTENT,
			&ms->client_remove_stmt, NULL);
	if(rc) goto fail;

	rc = sqlite3_prepare_v3(ms->db,
			"UPDATE clients SET session_expiry_time=?, will_delay_time=? "
			"WHERE client_id=?",
			-1, SQLITE_PREPARE_PERSISTENT,
			&ms->client_update_stmt, NULL);
	if(rc) goto fail;

	/* Client messages */
	rc = sqlite3_prepare_v3(ms->db,
			"INSERT INTO client_msgs "
				"(client_id,store_id,dup,direction,mid,qos,retain,state) "
				"VALUES(?,?,?,?,?,?,?,?)",
			-1, SQLITE_PREPARE_PERSISTENT,
			&ms->client_msg_add_stmt, NULL);
	if(rc) goto fail;

	rc = sqlite3_prepare_v3(ms->db,
			"DELETE FROM client_msgs WHERE client_id=? AND store_id=? AND direction=?",
			-1, SQLITE_PREPARE_PERSISTENT,
			&ms->client_msg_remove_stmt, NULL);
	if(rc) goto fail;


	rc = sqlite3_prepare_v3(ms->db,
			"UPDATE client_msgs SET state=?,dup=? WHERE client_id=? AND store_id=?",
			-1, SQLITE_PREPARE_PERSISTENT,
			&ms->client_msg_update_stmt, NULL);
	if(rc) goto fail;

	rc = sqlite3_prepare_v3(ms->db,
			"DELETE FROM client_msgs WHERE client_id=? AND direction=?",
			-1, SQLITE_PREPARE_PERSISTENT,
			&ms->client_msg_clear_stmt, NULL);
	if(rc) goto fail;

	rc = sqlite3_prepare_v3(ms->db,
			"DELETE FROM client_msgs WHERE client_id=?",
			-1, SQLITE_PREPARE_PERSISTENT,
			&ms->client_msg_clear_all_stmt, NULL);
	if(rc) goto fail;

	/* Message store */
	rc = sqlite3_prepare_v3(ms->db,
			"INSERT INTO base_msgs "
			"(store_id, expiry_time, topic, payload, source_id, source_username, "
			"payloadlen, source_mid, source_port, qos, retain, properties) "
			"VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
			-1, SQLITE_PREPARE_PERSISTENT,
			&ms->base_msg_add_stmt, NULL);
	if(rc) goto fail;

	rc = sqlite3_prepare_v3(ms->db,
			"DELETE FROM base_msgs WHERE store_id=?",
			-1, SQLITE_PREPARE_PERSISTENT,
			&ms->base_msg_remove_stmt, NULL);
	if(rc) goto fail;

	rc = sqlite3_prepare_v3(ms->db,
			"SELECT store_id, expiry_time, topic, payload, source_id, source_username, "
			"payloadlen, source_mid, source_port, qos, retain, properties "
			"FROM base_msgs WHERE store_id=?",
			-1, SQLITE_PREPARE_PERSISTENT,
			&ms->base_msg_load_stmt, NULL);
	if(rc) goto fail;

	/* Retains */
	rc = sqlite3_prepare_v3(ms->db,
			"INSERT OR REPLACE INTO retains "
			"(topic, store_id)"
			"VALUES(?,?)",
			-1, SQLITE_PREPARE_PERSISTENT,
			&ms->retain_msg_set_stmt, NULL);
	if(rc) goto fail;

	rc = sqlite3_prepare_v3(ms->db,
			"DELETE FROM retains WHERE topic=?",
			-1, SQLITE_PREPARE_PERSISTENT,
			&ms->retain_msg_remove_stmt, NULL);
	if(rc) goto fail;

	return 0;
fail:
	mosquitto_log_printf(MOSQ_LOG_ERR, "Sqlite persistence: Error preparing statements: %s", sqlite3_errstr(rc));
	sqlite3_close(ms->db);
	ms->db = NULL;
	return 1;
}


int persist_sqlite__init(struct mosquitto_sqlite *ms)
{
	int rc;
	char buf[50];

	rc = sqlite3_open_v2(ms->db_file, &ms->db, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL);
	if(rc != SQLITE_OK){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Sqlite persistence: Error opening %s: %s",
				ms->db_file, sqlite3_errstr(rc));
		return MOSQ_ERR_UNKNOWN;
	}
	snprintf(buf, sizeof(buf), "PRAGMA page_size=%u;", ms->page_size);
	rc = sqlite3_exec(ms->db, buf, NULL, NULL, NULL);
	if(rc) goto fail;
	rc = sqlite3_exec(ms->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
	if(rc) goto fail;
	rc = sqlite3_exec(ms->db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL);
	if(rc) goto fail;
	snprintf(buf, sizeof(buf), "PRAGMA synchronous=%d;", ms->synchronous);
	rc = sqlite3_exec(ms->db, buf, NULL, NULL, NULL);
	if(rc) goto fail;

	rc = create_tables(ms);
	if(rc) return rc;

	rc = prepare_statements(ms);
	if(rc) return rc;

	sqlite3_exec(ms->db, "BEGIN;", NULL, NULL, NULL);
	return MOSQ_ERR_SUCCESS;
fail:
	mosquitto_log_printf(MOSQ_LOG_ERR, "Sqlite persistence: Error opening database: %s", sqlite3_errstr(rc));
	return MOSQ_ERR_UNKNOWN;
}

void persist_sqlite__cleanup(struct mosquitto_sqlite *ms)
{
	sqlite3_finalize(ms->client_add_stmt);
	sqlite3_finalize(ms->client_remove_stmt);
	sqlite3_finalize(ms->client_update_stmt);
	sqlite3_finalize(ms->subscription_add_stmt);
	sqlite3_finalize(ms->subscription_remove_stmt);
	sqlite3_finalize(ms->subscription_clear_stmt);
	sqlite3_finalize(ms->client_msg_add_stmt);
	sqlite3_finalize(ms->client_msg_remove_stmt);
	sqlite3_finalize(ms->client_msg_update_stmt);
	sqlite3_finalize(ms->client_msg_clear_stmt);
	sqlite3_finalize(ms->client_msg_clear_all_stmt);
	sqlite3_finalize(ms->base_msg_add_stmt);
	sqlite3_finalize(ms->base_msg_remove_stmt);
	sqlite3_finalize(ms->base_msg_load_stmt);
	sqlite3_finalize(ms->retain_msg_set_stmt);
	sqlite3_finalize(ms->retain_msg_remove_stmt);

	if(ms->db){
		sqlite3_exec(ms->db, "END;", NULL, NULL, NULL);
		sqlite3_close(ms->db);
		ms->db = NULL;
	}
}
