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
#include "mosquitto/broker.h"
#include "persist_sqlite.h"


int persist_sqlite__client_msg_add_cb(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_persist_client_msg *ed = event_data;
	struct mosquitto_sqlite *ms = userdata;
	int rc = MOSQ_ERR_UNKNOWN;

	UNUSED(event);

	if(sqlite3_bind_text(ms->client_msg_add_stmt, 1, ed->data.clientid, (int)strlen(ed->data.clientid), SQLITE_STATIC) == SQLITE_OK
			&& sqlite3_bind_int64(ms->client_msg_add_stmt, 2, (int64_t)ed->data.cmsg_id) == SQLITE_OK
			&& sqlite3_bind_int64(ms->client_msg_add_stmt, 3, (int64_t)ed->data.store_id) == SQLITE_OK
			&& sqlite3_bind_int(ms->client_msg_add_stmt, 4, ed->data.dup) == SQLITE_OK
			&& sqlite3_bind_int(ms->client_msg_add_stmt, 5, ed->data.direction) == SQLITE_OK
			&& sqlite3_bind_int(ms->client_msg_add_stmt, 6, ed->data.mid) == SQLITE_OK
			&& sqlite3_bind_int(ms->client_msg_add_stmt, 7, ed->data.qos) == SQLITE_OK
			&& sqlite3_bind_int(ms->client_msg_add_stmt, 8, ed->data.retain) == SQLITE_OK
			&& sqlite3_bind_int(ms->client_msg_add_stmt, 9, ed->data.state) == SQLITE_OK
			&& sqlite3_bind_int(ms->client_msg_add_stmt, 10, (int)ed->data.subscription_identifier) == SQLITE_OK

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

	UNUSED(event);
	ms->event_count++;
	return persist_sqlite__client_msg_remove(ms, ed->data.clientid, (int64_t)ed->data.store_id, ed->data.direction);
}


int persist_sqlite__client_msg_update_cb(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_persist_client_msg *ed = event_data;
	struct mosquitto_sqlite *ms = userdata;
	int rc = MOSQ_ERR_UNKNOWN;

	UNUSED(event);

	if(sqlite3_bind_int(ms->client_msg_update_stmt, 1, ed->data.state) == SQLITE_OK
			&& sqlite3_bind_int(ms->client_msg_update_stmt, 2, ed->data.dup) == SQLITE_OK
			&& sqlite3_bind_text(ms->client_msg_update_stmt, 3, ed->data.clientid, (int)strlen(ed->data.clientid), SQLITE_STATIC) == SQLITE_OK
			&& sqlite3_bind_int64(ms->client_msg_update_stmt, 4, (int64_t)ed->data.store_id) == SQLITE_OK
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


int persist_sqlite__client_msg_clear(struct mosquitto_sqlite *ms, const char *clientid)
{
	int rc = MOSQ_ERR_UNKNOWN;

	if(sqlite3_bind_text(ms->client_msg_clear_all_stmt, 1, clientid, (int)strlen(clientid), SQLITE_STATIC) == SQLITE_OK){
		ms->event_count++;
		rc = sqlite3_step(ms->client_msg_clear_all_stmt);
		if(rc == SQLITE_DONE){
			rc = MOSQ_ERR_SUCCESS;
		}else{
			rc = MOSQ_ERR_UNKNOWN;
		}
	}
	sqlite3_reset(ms->client_msg_clear_all_stmt);

	return rc;
}
