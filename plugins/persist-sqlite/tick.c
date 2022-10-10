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
#include <stdlib.h>

#include "mqtt_protocol.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "persist_sqlite.h"

int persist_sqlite__tick_cb(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_tick *ed = event_data;
	struct mosquitto_sqlite *ms = userdata;

	UNUSED(event);
	if(ed->now_s > ms->last_transaction + ms->flush_period && ms->event_count > 0){
		ms->last_transaction = ed->now_s;
		ms->event_count = 0;
		sqlite3_exec(ms->db, "END;", NULL, NULL, NULL);
		sqlite3_exec(ms->db, "BEGIN;", NULL, NULL, NULL);
	}

	return MOSQ_ERR_SUCCESS;
}
