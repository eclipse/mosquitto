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
#include <stdio.h>
#include <stdlib.h>
#include <cjson/cJSON.h>

#include "mosquitto.h"
#include "persist_sqlite.h"

static char *properties_to_json(const mosquitto_property *properties)
{
	cJSON *array;
	char *json_str;

	array = mosquitto_properties_to_json(properties);
	if(!array) return NULL;

	json_str = cJSON_PrintUnformatted(array);
	cJSON_Delete(array);
	return json_str;
}


int persist_sqlite__base_msg_add_cb(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_persist_base_msg *ed = event_data;
	struct mosquitto_sqlite *ms = userdata;
	int rc = MOSQ_ERR_UNKNOWN;
	char *str = NULL;

	UNUSED(event);

	rc = 0;
	rc += sqlite3_bind_int64(ms->base_msg_add_stmt, 1, (int64_t)ed->data.store_id);
	rc += sqlite3_bind_int64(ms->base_msg_add_stmt, 2, ed->data.expiry_time);
	rc += sqlite3_bind_text(ms->base_msg_add_stmt, 3, ed->data.topic, (int)strlen(ed->data.topic), SQLITE_STATIC);
	if(ed->data.payload){
		rc += sqlite3_bind_blob(ms->base_msg_add_stmt, 4, ed->data.payload, (int)ed->data.payloadlen, SQLITE_STATIC);
	}else{
		rc += sqlite3_bind_null(ms->base_msg_add_stmt, 4);
	}
	if(ed->data.source_id){
		rc += sqlite3_bind_text(ms->base_msg_add_stmt, 5, ed->data.source_id, (int)strlen(ed->data.source_id), SQLITE_STATIC);
	}else{
		rc += sqlite3_bind_null(ms->base_msg_add_stmt, 5);
	}
	if(ed->data.source_username){
		rc += sqlite3_bind_text(ms->base_msg_add_stmt, 6, ed->data.source_username, (int)strlen(ed->data.source_username), SQLITE_STATIC);
	}else{
		rc += sqlite3_bind_null(ms->base_msg_add_stmt, 6);
	}
	rc += sqlite3_bind_int(ms->base_msg_add_stmt, 7, (int)ed->data.payloadlen);
	rc += sqlite3_bind_int(ms->base_msg_add_stmt, 8, ed->data.source_mid);
	rc += sqlite3_bind_int(ms->base_msg_add_stmt, 9, ed->data.source_port);
	rc += sqlite3_bind_int(ms->base_msg_add_stmt, 10, ed->data.qos);
	rc += sqlite3_bind_int(ms->base_msg_add_stmt, 11, ed->data.retain);
	if(ed->data.properties){
		str = properties_to_json(ed->data.properties);
	}
	if(str){
		rc += sqlite3_bind_text(ms->base_msg_add_stmt, 12, str, (int)strlen(str), SQLITE_STATIC);
	}else{
		rc += sqlite3_bind_null(ms->base_msg_add_stmt, 12);
	}

	if(rc == 0){
		ms->event_count++;
		rc = sqlite3_step(ms->base_msg_add_stmt);
		if(rc == SQLITE_DONE){
			rc = MOSQ_ERR_SUCCESS;
		}else{
			rc = MOSQ_ERR_UNKNOWN;
		}
	}
	sqlite3_reset(ms->base_msg_add_stmt);
	free(str);

	return rc;
}

int persist_sqlite__base_msg_remove_cb(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_persist_base_msg *ed = event_data;
	struct mosquitto_sqlite *ms = userdata;
	int rc = 1;

	UNUSED(event);

	if(sqlite3_bind_int64(ms->base_msg_remove_stmt, 1, (int64_t)ed->data.store_id) == SQLITE_OK){
		ms->event_count++;
		rc = sqlite3_step(ms->base_msg_remove_stmt);
		if(rc == SQLITE_DONE){
			rc = MOSQ_ERR_SUCCESS;
		}else{
			rc = MOSQ_ERR_UNKNOWN;
		}
	}
	sqlite3_reset(ms->base_msg_remove_stmt);

	return rc;
}
