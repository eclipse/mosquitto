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


int persist_sqlite__client_msg_remove(struct mosquitto_sqlite *ms, const char* clientid, int64_t store_id, int direction)
{
	int rc = 1;

	mosquitto_log_printf(MOSQ_LOG_DEBUG, "Drop message clientid %s store_id %ld direction %d", clientid, store_id, direction);

	if(sqlite3_bind_text(ms->client_msg_remove_stmt, 1, clientid, (int)strlen(clientid), SQLITE_STATIC) == SQLITE_OK
			&& sqlite3_bind_int64(ms->client_msg_remove_stmt, 2, store_id) == SQLITE_OK
			&& sqlite3_bind_int(ms->client_msg_remove_stmt, 3, direction) == SQLITE_OK
			){
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

