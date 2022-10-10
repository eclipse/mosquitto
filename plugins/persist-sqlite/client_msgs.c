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


int persist_sqlite__client_msg_add_cb(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_persist_client_msg *ed = event_data;
	struct mosquitto_sqlite *ms = userdata;
	int rc = MOSQ_ERR_UNKNOWN;

	UNUSED(event);

	if(sqlite3_bind_text(ms->client_msg_add_stmt, 1, ed->client_id, (int)strlen(ed->client_id), SQLITE_STATIC) == SQLITE_OK
			&& sqlite3_bind_int64(ms->client_msg_add_stmt, 2, (int64_t)ed->store_id) == SQLITE_OK
			&& sqlite3_bind_int(ms->client_msg_add_stmt, 3, ed->dup) == SQLITE_OK
			&& sqlite3_bind_int(ms->client_msg_add_stmt, 4, ed->direction) == SQLITE_OK
			&& sqlite3_bind_int(ms->client_msg_add_stmt, 5, ed->mid) == SQLITE_OK
			&& sqlite3_bind_int(ms->client_msg_add_stmt, 6, ed->qos) == SQLITE_OK
			&& sqlite3_bind_int(ms->client_msg_add_stmt, 7, ed->retain) == SQLITE_OK
			&& sqlite3_bind_int(ms->client_msg_add_stmt, 8, ed->state) == SQLITE_OK
			){

		ms->event_count++;
		rc = sqlite3_step(ms->client_msg_add_stmt);
		if(rc == SQLITE_DONE){
			rc = MOSQ_ERR_SUCCESS;
		}else{
			rc = MOSQ_ERR_UNKNOWN;
		}
	}
	sqlite3_reset(ms->client_msg_add_stmt);

	return rc;
}


int persist_sqlite__client_msg_remove_cb(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_persist_client_msg *ed = event_data;
	struct mosquitto_sqlite *ms = userdata;
	int rc = 1;

	UNUSED(event);

	if(sqlite3_bind_text(ms->client_msg_remove_stmt, 1, ed->client_id, (int)strlen(ed->client_id), SQLITE_STATIC) == SQLITE_OK
			&& sqlite3_bind_int64(ms->client_msg_remove_stmt, 2, (int64_t)ed->store_id) == SQLITE_OK
			&& sqlite3_bind_int(ms->client_msg_remove_stmt, 3, ed->direction) == SQLITE_OK
			){

		ms->event_count++;
		rc = sqlite3_step(ms->client_msg_remove_stmt);
		if(rc == SQLITE_DONE){
			rc = MOSQ_ERR_SUCCESS;
		}else{
			rc = MOSQ_ERR_UNKNOWN;
		}
	}
	sqlite3_reset(ms->client_msg_remove_stmt);

	return rc;
}


int persist_sqlite__client_msg_update_cb(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_persist_client_msg *ed = event_data;
	struct mosquitto_sqlite *ms = userdata;
	int rc = MOSQ_ERR_UNKNOWN;

	UNUSED(event);

	if(sqlite3_bind_int(ms->client_msg_update_stmt, 1, ed->state) == SQLITE_OK
			&& sqlite3_bind_int(ms->client_msg_update_stmt, 2, ed->dup) == SQLITE_OK
			&& sqlite3_bind_text(ms->client_msg_update_stmt, 3, ed->client_id, (int)strlen(ed->client_id), SQLITE_STATIC) == SQLITE_OK
			&& sqlite3_bind_int64(ms->client_msg_update_stmt, 4, (int64_t)ed->store_id) == SQLITE_OK
			){

		ms->event_count++;
		rc = sqlite3_step(ms->client_msg_update_stmt);
		if(rc == SQLITE_DONE){
			rc = MOSQ_ERR_SUCCESS;
		}else{
			rc = MOSQ_ERR_UNKNOWN;
		}
	}
	sqlite3_reset(ms->client_msg_update_stmt);

	return rc;
}


int persist_sqlite__client_msg_clear(struct mosquitto_sqlite *ms, const char *client_id, int direction)
{
	int rc = MOSQ_ERR_UNKNOWN;

	if(direction == mosq_bmd_all){
		if(sqlite3_bind_text(ms->client_msg_clear_all_stmt, 1, client_id, (int)strlen(client_id), SQLITE_STATIC) == SQLITE_OK){
			ms->event_count++;
			rc = sqlite3_step(ms->client_msg_clear_all_stmt);
			if(rc == SQLITE_DONE){
				rc = MOSQ_ERR_SUCCESS;
			}else{
				rc = MOSQ_ERR_UNKNOWN;
			}
		}
		sqlite3_reset(ms->client_msg_clear_all_stmt);
	}else{
		if(sqlite3_bind_text(ms->client_msg_clear_stmt, 1, client_id, (int)strlen(client_id), SQLITE_STATIC) == SQLITE_OK
				&& sqlite3_bind_int64(ms->client_msg_clear_stmt, 2, direction) == SQLITE_OK
				){

			ms->event_count++;
			rc = sqlite3_step(ms->client_msg_clear_stmt);
			if(rc == SQLITE_DONE){
				rc = MOSQ_ERR_SUCCESS;
			}else{
				rc = MOSQ_ERR_UNKNOWN;
			}
		}
		sqlite3_reset(ms->client_msg_clear_stmt);
	}

	return rc;
}
