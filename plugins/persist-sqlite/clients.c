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

#include <string.h>
#include <sqlite3.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "persist_sqlite.h"

int persist_sqlite__client_add_cb(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_persist_client *ed = event_data;
	struct mosquitto_sqlite *ms = userdata;
	int rc = MOSQ_ERR_UNKNOWN;
	time_t now;

	UNUSED(event);

	if(sqlite3_bind_text(ms->client_add_stmt, 1,
				ed->client_id, (int)strlen(ed->client_id), SQLITE_STATIC) == SQLITE_OK){

		if(ed->username){
			sqlite3_bind_text(ms->client_add_stmt, 2,
					ed->username, (int)strlen(ed->username),
					SQLITE_STATIC);
		}else{
			sqlite3_bind_null(ms->client_add_stmt, 2);
		}

		now = time(NULL);
		if(sqlite3_bind_int64(ms->client_add_stmt, 3, now) == SQLITE_OK
				&& sqlite3_bind_int64(ms->client_add_stmt, 4, ed->will_delay_time) == SQLITE_OK
				&& sqlite3_bind_int64(ms->client_add_stmt, 5, ed->session_expiry_time) == SQLITE_OK
				&& sqlite3_bind_int(ms->client_add_stmt, 6, ed->listener_port) == SQLITE_OK
				&& sqlite3_bind_int(ms->client_add_stmt, 7, (int)ed->max_packet_size) == SQLITE_OK
				&& sqlite3_bind_int(ms->client_add_stmt, 8, ed->max_qos) == SQLITE_OK
				&& sqlite3_bind_int(ms->client_add_stmt, 9, ed->retain_available) == SQLITE_OK
				&& sqlite3_bind_int(ms->client_add_stmt, 10, (int)ed->session_expiry_interval) == SQLITE_OK
				&& sqlite3_bind_int(ms->client_add_stmt, 11, (int)ed->will_delay_interval) == SQLITE_OK
				){

			ms->event_count++;
			rc = sqlite3_step(ms->client_add_stmt);
			if(rc == SQLITE_DONE){
				rc = MOSQ_ERR_SUCCESS;
			}else{
				rc = MOSQ_ERR_UNKNOWN;
			}
		}
	}
	sqlite3_reset(ms->client_add_stmt);

	return rc;
}

int persist_sqlite__client_remove_cb(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_persist_client *ed = event_data;
	struct mosquitto_sqlite *ms = userdata;
	int rc = 1;

	UNUSED(event);

	if(sqlite3_bind_text(ms->subscription_clear_stmt, 1,
				ed->client_id, (int)strlen(ed->client_id), SQLITE_STATIC) == SQLITE_OK){

		ms->event_count++;
		rc = sqlite3_step(ms->subscription_clear_stmt);
		sqlite3_reset(ms->subscription_clear_stmt);
		if(rc == SQLITE_DONE){
			rc = MOSQ_ERR_SUCCESS;
		}else{
			rc = MOSQ_ERR_UNKNOWN;
		}
	}
	if(sqlite3_bind_text(ms->client_remove_stmt, 1,
				ed->client_id, (int)strlen(ed->client_id), SQLITE_STATIC) == SQLITE_OK){

		ms->event_count++;
		rc = sqlite3_step(ms->client_remove_stmt);
		sqlite3_reset(ms->client_remove_stmt);
		if(rc == SQLITE_DONE){
			rc = MOSQ_ERR_SUCCESS;
		}else{
			rc = MOSQ_ERR_UNKNOWN;
		}
	}
	persist_sqlite__client_msg_clear(ms, ed->client_id, mosq_bmd_all);

	return rc;
}


int persist_sqlite__client_update_cb(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_persist_client *ed = event_data;
	struct mosquitto_sqlite *ms = userdata;
	int rc = 1;

	UNUSED(event);

	if(sqlite3_bind_int64(ms->client_update_stmt, 1, ed->session_expiry_time) == SQLITE_OK
			&& sqlite3_bind_int64(ms->client_update_stmt, 2, ed->will_delay_time) == SQLITE_OK
			&& sqlite3_bind_text(ms->client_update_stmt, 3, ed->client_id,
				(int)strlen(ed->client_id), SQLITE_STATIC) == SQLITE_OK
			){

		ms->event_count++;
		rc = sqlite3_step(ms->client_update_stmt);
		if(rc == SQLITE_DONE){
			rc = MOSQ_ERR_SUCCESS;
		}else{
			rc = MOSQ_ERR_UNKNOWN;
		}
	}
	sqlite3_reset(ms->client_update_stmt);

	return rc;
}
