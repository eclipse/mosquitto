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
	uint16_t i16;
	uint32_t i32;
	void *binval;
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
			case MQTT_PROP_REQUEST_PROBLEM_INFORMATION:
			case MQTT_PROP_REQUEST_RESPONSE_INFORMATION:
			case MQTT_PROP_MAXIMUM_QOS:
			case MQTT_PROP_RETAIN_AVAILABLE:
			case MQTT_PROP_WILDCARD_SUB_AVAILABLE:
			case MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE:
			case MQTT_PROP_SHARED_SUB_AVAILABLE:
				/* byte */
				mosquitto_property_read_byte(properties, propid, &i8, false);
				if(cJSON_AddNumberToObject(obj, "value", i8) == NULL){
					cJSON_Delete(array);
					return NULL;
				}
				break;

			case MQTT_PROP_SERVER_KEEP_ALIVE:
			case MQTT_PROP_RECEIVE_MAXIMUM:
			case MQTT_PROP_TOPIC_ALIAS_MAXIMUM:
			case MQTT_PROP_TOPIC_ALIAS:
				/* 2 byte */
				mosquitto_property_read_int16(properties, propid, &i16, false);
				if(cJSON_AddNumberToObject(obj, "value", i16) == NULL){
					cJSON_Delete(array);
					return NULL;
				}
				break;

			case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
			case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
			case MQTT_PROP_WILL_DELAY_INTERVAL:
			case MQTT_PROP_MAXIMUM_PACKET_SIZE:
				/* 4 byte */
				mosquitto_property_read_int32(properties, propid, &i32, false);
				if(cJSON_AddNumberToObject(obj, "value", i32) == NULL){
					cJSON_Delete(array);
					return NULL;
				}
				break;

			case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
				/* var byte */
				mosquitto_property_read_varint(properties, propid, &i32, false);
				if(cJSON_AddNumberToObject(obj, "value", i32) == NULL){
					cJSON_Delete(array);
					return NULL;
				}
				break;

			case MQTT_PROP_CONTENT_TYPE:
			case MQTT_PROP_RESPONSE_TOPIC:
			case MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER:
			case MQTT_PROP_AUTHENTICATION_METHOD:
			case MQTT_PROP_RESPONSE_INFORMATION:
			case MQTT_PROP_SERVER_REFERENCE:
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
			case MQTT_PROP_AUTHENTICATION_DATA:
				/* bin */
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

				if(cJSON_AddStringToObject(obj, "value", hexval) == NULL){
					free(hexval);
					cJSON_Delete(array);
					return NULL;
				}
				free(hexval);
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
	rc += sqlite3_bind_int64(ms->base_msg_add_stmt, 1, (int64_t)ed->store_id);
	rc += sqlite3_bind_int64(ms->base_msg_add_stmt, 2, ed->expiry_time);
	rc += sqlite3_bind_text(ms->base_msg_add_stmt, 3, ed->topic, (int)strlen(ed->topic), SQLITE_STATIC);
	if(ed->payload){
		rc += sqlite3_bind_blob(ms->base_msg_add_stmt, 4, ed->payload, (int)ed->payloadlen, SQLITE_STATIC);
	}else{
		rc += sqlite3_bind_null(ms->base_msg_add_stmt, 4);
	}
	if(ed->source_id){
		rc += sqlite3_bind_text(ms->base_msg_add_stmt, 5, ed->source_id, (int)strlen(ed->source_id), SQLITE_STATIC);
	}else{
		rc += sqlite3_bind_null(ms->base_msg_add_stmt, 5);
	}
	if(ed->source_username){
		rc += sqlite3_bind_text(ms->base_msg_add_stmt, 6, ed->source_username, (int)strlen(ed->source_username), SQLITE_STATIC);
	}else{
		rc += sqlite3_bind_null(ms->base_msg_add_stmt, 6);
	}
	rc += sqlite3_bind_int(ms->base_msg_add_stmt, 7, (int)ed->payloadlen);
	rc += sqlite3_bind_int(ms->base_msg_add_stmt, 8, ed->source_mid);
	rc += sqlite3_bind_int(ms->base_msg_add_stmt, 9, ed->source_port);
	rc += sqlite3_bind_int(ms->base_msg_add_stmt, 10, ed->qos);
	rc += sqlite3_bind_int(ms->base_msg_add_stmt, 11, ed->retain);
	if(ed->properties){
		str = properties_to_json(ed->properties);
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

	if(sqlite3_bind_int64(ms->base_msg_remove_stmt, 1, (int64_t)ed->store_id) == SQLITE_OK){
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


int persist_sqlite__base_msg_load_cb(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_persist_base_msg *msg = event_data;
	struct mosquitto_sqlite *ms = userdata;

	UNUSED(event);

	if(sqlite3_bind_int64(ms->base_msg_load_stmt, 1, (int64_t)msg->store_id) == SQLITE_OK){
		if(sqlite3_step(ms->base_msg_load_stmt) == SQLITE_ROW){
			msg->expiry_time = (time_t)sqlite3_column_int64(ms->base_msg_load_stmt, 1);
			msg->topic = (char *)sqlite3_column_text(ms->base_msg_load_stmt, 2);
			msg->payload = (void *)sqlite3_column_blob(ms->base_msg_load_stmt, 3);
			msg->source_id = (char *)sqlite3_column_text(ms->base_msg_load_stmt, 4);
			msg->source_username = (char *)sqlite3_column_text(ms->base_msg_load_stmt, 5);
			msg->payloadlen = (uint32_t)sqlite3_column_int(ms->base_msg_load_stmt, 6);
			msg->source_mid = (uint16_t)sqlite3_column_int(ms->base_msg_load_stmt, 7);
			msg->source_port = (uint16_t)sqlite3_column_int(ms->base_msg_load_stmt, 8);
			msg->qos = (uint8_t)sqlite3_column_int(ms->base_msg_load_stmt, 9);
			msg->retain = sqlite3_column_int(ms->base_msg_load_stmt, 10);
			mosquitto_persist_base_msg_add(msg);
		}
	}
	sqlite3_finalize(ms->base_msg_load_stmt);
	return MOSQ_ERR_SUCCESS;
}
