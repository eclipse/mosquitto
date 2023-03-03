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

#include "mqtt_protocol.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "persist_sqlite.h"

static char *properties_to_json(const mosquitto_property *properties)
{
	cJSON *array, *obj;
	char *json_str, *name, *value;
	uint8_t i8;
	uint16_t len;
	int propid;

	if(!properties) return NULL;

	array = cJSON_CreateArray();
	if(!array) return NULL;

	do{
		propid = mosquitto_property_identifier(properties);
		obj = cJSON_CreateObject();
		if(!obj){
			cJSON_Delete(array);
			return NULL;
		}
		cJSON_AddItemToArray(array, obj);
		/* identifier, (key), value */
		if(cJSON_AddStringToObject(obj,
					"identifier",
					mosquitto_property_identifier_to_string(propid)) == NULL
					){
			cJSON_Delete(array);
			return NULL;
		}

		switch(propid){
			case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
				/* byte */
				mosquitto_property_read_byte(properties, propid, &i8, false);
				if(cJSON_AddNumberToObject(obj, "value", i8) == NULL){
					cJSON_Delete(array);
					return NULL;
				}
				break;

			case MQTT_PROP_CONTENT_TYPE:
			case MQTT_PROP_RESPONSE_TOPIC:
			case MQTT_PROP_REASON_STRING:
				/* str */
				if(mosquitto_property_read_string(properties, propid, &value, false) == NULL){
					cJSON_Delete(array);
					return NULL;
				}
				if(cJSON_AddStringToObject(obj, "value", value) == NULL){
					free(value);
					cJSON_Delete(array);
					return NULL;
				}
				free(value);
				break;

			case MQTT_PROP_CORRELATION_DATA:
				{
					/* bin */
					void *binval = NULL;
					mosquitto_property_read_binary(properties, propid, &binval, &len, false);
					char *hexval = malloc(2*(size_t)len + 1);
					if(!hexval){
						free(binval);
						cJSON_Delete(array);
						return NULL;
					}
					for(int i=0; i<len; i++){
						sprintf(&hexval[i*2], "%02X", ((uint8_t *)binval)[i]);
					}
					hexval[2*len] = '\0';
					free(binval);

					if(cJSON_AddStringToObject(obj, "value", hexval) == NULL){
						free(hexval);
						cJSON_Delete(array);
						return NULL;
					}
					free(hexval);
				}
				break;

			case MQTT_PROP_USER_PROPERTY:
				/* pair */
				mosquitto_property_read_string_pair(properties, propid, &name, &value, false);
				if(cJSON_AddStringToObject(obj, "name", name) == NULL
						|| cJSON_AddStringToObject(obj, "value", value) == NULL){

					free(name);
					free(value);
					cJSON_Delete(array);
					return NULL;
				}
				free(name);
				free(value);
				break;

			default:
				break;
		}

		properties = mosquitto_property_next(properties);
	}while(properties);

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
