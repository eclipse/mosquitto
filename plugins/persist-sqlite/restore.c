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

#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <cjson/cJSON.h>

#include "json_help.h"
#include "mosquitto.h"
#include "mosquitto/broker.h"
#include "mosquitto/mqtt_protocol.h"
#include "persist_sqlite.h"

static uint8_t hex2nibble(char c)
{
	switch(c){
		case '0': return 0;
		case '1': return 1;
		case '2': return 2;
		case '3': return 3;
		case '4': return 4;
		case '5': return 5;
		case '6': return 6;
		case '7': return 7;
		case '8': return 8;
		case '9': return 9;
		case 'A': return 10;
		case 'a': return 10;
		case 'B': return 11;
		case 'b': return 11;
		case 'C': return 12;
		case 'c': return 12;
		case 'D': return 13;
		case 'd': return 13;
		case 'E': return 14;
		case 'e': return 14;
		case 'F': return 15;
		case 'f': return 15;
		default: return 0;
	}
}

static mosquitto_property *json_to_properties(const char *json)
{
	mosquitto_property *properties = NULL;
	cJSON *array, *obj, *j_value;
	int propid, proptype;
	size_t slen;

	if(!json) return NULL;

	array = cJSON_Parse(json);
	if(!array) return NULL;
	if(!cJSON_IsArray(array)){
		cJSON_Delete(array);
		return NULL;
	}

	cJSON_ArrayForEach(obj, array){
		const char *identifier;

		j_value = cJSON_GetObjectItem(obj, "value");

		if(json_get_string(obj, "identifier", &identifier, false) != MOSQ_ERR_SUCCESS
				|| !j_value){

			mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Ignoring property whilst restoring, invalid identifier / value");
			continue;
		}
		if(mosquitto_string_to_property_info(identifier, &propid, &proptype)){
			mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Ignoring property whilst restoring, unknown identifier");
			continue;
		}
		switch(proptype){
			case MQTT_PROP_TYPE_BYTE:
				if(!cJSON_IsNumber(j_value)){
					mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Ignoring %s property whilst restoring, value is incorrect type", "byte");
					continue;
				}
				if(mosquitto_property_add_byte(&properties, propid, (uint8_t)j_value->valueint)){
					mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Out of memory whilst restoring %s property", "byte");
					continue;
				}
				break;
			case MQTT_PROP_TYPE_INT16:
				if(!cJSON_IsNumber(j_value)){
					mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Ignoring %s property whilst restoring, value is incorrect type", "int16");
					continue;
				}
				if(mosquitto_property_add_int16(&properties, propid, (uint16_t)j_value->valueint)){
					mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Out of memory whilst restoring %s property", "int16");
					continue;
				}
				break;
			case MQTT_PROP_TYPE_INT32:
				if(!cJSON_IsNumber(j_value)){
					mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Ignoring %s property whilst restoring, value is incorrect type", "int32");
					continue;
				}
				if(mosquitto_property_add_int32(&properties, propid, (uint32_t)j_value->valueint)){
					mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Out of memory whilst restoring %s property", "int32");
					continue;
				}
				break;
			case MQTT_PROP_TYPE_VARINT:
				if(!cJSON_IsNumber(j_value)){
					mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Ignoring %s property whilst restoring, value is incorrect type", "varint");
					continue;
				}
				if(mosquitto_property_add_varint(&properties, propid, (uint32_t)j_value->valueint)){
					mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Out of memory whilst restoring %s property", "varint");
					continue;
				}
				break;
			case MQTT_PROP_TYPE_BINARY:
				if(!cJSON_IsString(j_value)){
					mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Ignoring %s property whilst restoring, value is incorrect type", "binary");
					continue;
				}
				uint8_t *binstr = NULL;
				uint16_t len = 0;

				if(j_value->valuestring){
					slen = strlen(j_value->valuestring);
					if(slen/2 > UINT16_MAX){
						mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Ignoring %s property whilst restoring, value is too large", "binary");
						continue;
					}
					for(size_t i=0; i<slen; i+=2){
						((uint8_t *)j_value->valuestring)[i/2] = (uint8_t)(hex2nibble(j_value->valuestring[i])<<4) + hex2nibble(j_value->valuestring[i+1]);
					}
					binstr = (uint8_t *)j_value->valuestring;
					len = (uint16_t)slen/2;
				}
				if(mosquitto_property_add_binary(&properties, propid, binstr, len)){
					mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Out of memory whilst restoring %s property", "binary");
					continue;
				}
				break;
			case MQTT_PROP_TYPE_STRING:
				if(!cJSON_IsString(j_value)){
					mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Ignoring %s property whilst restoring, value is incorrect type", "string");
					continue;
				}
				if(mosquitto_property_add_string(&properties, propid, j_value->valuestring)){
					mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Out of memory whilst restoring %s property", "string");
					continue;
				}
				break;
			case MQTT_PROP_TYPE_STRING_PAIR:
				{
					const char *prop_name;

					if(!cJSON_IsString(j_value)){
						mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Ignoring %s property whilst restoring, value is incorrect type", "string pair");
						continue;
					}
					if(json_get_string(obj, "name", &prop_name, false) != MOSQ_ERR_SUCCESS){
						mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Ignoring string pair property whilst restoring, name is missing or incorrect type");
						continue;
					}
					if(mosquitto_property_add_string_pair(&properties, propid, prop_name, j_value->valuestring)){
						mosquitto_log_printf(MOSQ_LOG_WARNING, "Sqlite persistence: Out of memory whilst restoring %s property", "string pair");
						continue;
					}
				}
				break;
		}
	}
	cJSON_Delete(array);

	return properties;
}


static int client_restore(struct mosquitto_sqlite *ms)
{
	sqlite3_stmt *stmt;
	int rc;
	struct mosquitto_client client;
	long count = 0, failed = 0;
	const char *str;

	memset(&client, 0, sizeof(client));

	rc = sqlite3_prepare_v2(ms->db,
			"SELECT client_id,username,will_delay_time,session_expiry_time,"
			"listener_port,max_packet_size,max_qos,"
			"retain_available,session_expiry_interval,will_delay_interval "
			"FROM clients",
			-1, &stmt, NULL);

	if(rc != SQLITE_OK){
		mosquitto_log_printf(MOSQ_LOG_ERR, "sqlite: Error restoring clients: %s", sqlite3_errstr(rc));
		return MOSQ_ERR_UNKNOWN;
	}


	while(sqlite3_step(stmt) == SQLITE_ROW){
		str = (const char *)sqlite3_column_text(stmt, 0);
		if(str){
			client.clientid = mosquitto_strdup(str);
		}
		str = (const char *)sqlite3_column_text(stmt, 1);
		if(str){
			client.username = mosquitto_strdup(str);
		}
		client.will_delay_time = (time_t)sqlite3_column_int64(stmt, 2);
		client.session_expiry_time = (time_t)sqlite3_column_int64(stmt, 3);
		client.listener_port = (uint16_t)sqlite3_column_int(stmt, 4);
		client.max_packet_size = (uint32_t)sqlite3_column_int(stmt, 5);
		client.max_qos = (uint8_t)sqlite3_column_int(stmt, 6);
		client.retain_available = (bool)sqlite3_column_int(stmt, 7);
		client.session_expiry_interval = (uint32_t)sqlite3_column_int(stmt, 8);
		client.will_delay_interval = (uint32_t)sqlite3_column_int(stmt, 9);

		rc = mosquitto_persist_client_add(&client);
		if(rc == MOSQ_ERR_SUCCESS){
			count++;
		}else{
			failed++;
		}
	}
	sqlite3_finalize(stmt);

	mosquitto_log_printf(MOSQ_LOG_INFO, "sqlite: Restored %ld clients (%ld failed)", count, failed);

	return rc;
}


static int subscription_restore(struct mosquitto_sqlite *ms)
{
	sqlite3_stmt *stmt;
	struct mosquitto_subscription sub;
	int rc;
	long count = 0, failed = 0;

	rc = sqlite3_prepare_v2(ms->db,
			"SELECT client_id,topic,subscription_options,subscription_identifier "
			"FROM subscriptions",
			-1, &stmt, NULL);

	if(rc != SQLITE_OK){
		mosquitto_log_printf(MOSQ_LOG_ERR, "sqlite: Error restoring subscriptions: %s", sqlite3_errstr(rc));
		return MOSQ_ERR_UNKNOWN;
	}

	while(sqlite3_step(stmt) == SQLITE_ROW){
		memset(&sub, 0, sizeof(sub));
		sub.clientid = (char *)sqlite3_column_text(stmt, 0);
		sub.topic_filter = (char *)sqlite3_column_text(stmt, 1);
		sub.options = (uint8_t)sqlite3_column_int(stmt, 2);
		sub.identifier = (uint32_t)sqlite3_column_int(stmt, 3);

		rc = mosquitto_subscription_add(&sub);
		if(rc == MOSQ_ERR_SUCCESS){
			count++;
		}else{
			failed++;
		}
	}
	sqlite3_finalize(stmt);

	mosquitto_log_printf(MOSQ_LOG_INFO, "sqlite: Restored %ld subscriptions (%ld failed)", count, failed);

	return MOSQ_ERR_SUCCESS;
}


static int base_msg_restore(struct mosquitto_sqlite *ms)
{
	sqlite3_stmt *stmt;
	struct mosquitto_base_msg base_msg;
	int rc;
	long count = 0, failed = 0;
	const char *str;
	const void *payload;

	rc = sqlite3_prepare_v2(ms->db,
			"SELECT store_id, expiry_time, topic, payload, source_id, source_username, payloadlen, source_mid, source_port, qos, retain, properties "
			"FROM base_msgs",
			-1, &stmt, NULL);

	if(rc != SQLITE_OK){
		mosquitto_log_printf(MOSQ_LOG_ERR, "sqlite: Error restoring messages: %s", sqlite3_errstr(rc));
		return MOSQ_ERR_UNKNOWN;
	}

	while(sqlite3_step(stmt) == SQLITE_ROW){
		memset(&base_msg, 0, sizeof(base_msg));
		base_msg.store_id = (uint64_t)sqlite3_column_int64(stmt, 0);
		base_msg.expiry_time = (time_t)sqlite3_column_int64(stmt, 1);
		str = (const char *)sqlite3_column_text(stmt, 2);
		if(str){
			base_msg.topic = mosquitto_strdup(str);
			if(!base_msg.topic){
				failed++;
				continue;
			}
		}
		base_msg.source_id = (char *)sqlite3_column_text(stmt, 4);
		base_msg.source_username = (char *)sqlite3_column_text(stmt, 5);
		payload = (const void *)sqlite3_column_blob(stmt, 3);
		base_msg.payloadlen = (uint32_t)sqlite3_column_int(stmt, 6);
		if(payload && base_msg.payloadlen){
			base_msg.payload = mosquitto_malloc(base_msg.payloadlen+1);
			if(!base_msg.payload){
				mosquitto_free(base_msg.topic);
				failed++;
				continue;
			}
			memcpy(base_msg.payload, payload, base_msg.payloadlen);
			((uint8_t *)base_msg.payload)[base_msg.payloadlen] = 0;
		}

		base_msg.source_mid = (uint16_t)sqlite3_column_int(stmt, 7);
		base_msg.source_port = (uint16_t)sqlite3_column_int(stmt, 8);
		base_msg.qos = (uint8_t)sqlite3_column_int(stmt, 9);
		base_msg.retain = sqlite3_column_int(stmt, 10);
		base_msg.properties = json_to_properties((const char *)sqlite3_column_text(stmt, 11));

		rc = mosquitto_persist_base_msg_add(&base_msg);
		if(rc == MOSQ_ERR_SUCCESS){
			count++;
		}else{
			failed++;
		}
	}
	sqlite3_finalize(stmt);

	mosquitto_log_printf(MOSQ_LOG_INFO, "sqlite: Restored %ld base messages (%ld failed)", count, failed);
	return MOSQ_ERR_SUCCESS;
}


static int client_msg_restore(struct mosquitto_sqlite *ms)
{
	sqlite3_stmt *stmt;
	struct mosquitto_client_msg client_msg;
	int rc;
	long count = 0, failed = 0;

	rc = sqlite3_prepare_v2(ms->db,
			"SELECT client_id, cmsg_id, store_id, dup, direction, mid, qos, retain, state, subscription_identifier "
			"FROM client_msgs ORDER BY rowid",
			-1, &stmt, NULL);

	if(rc != SQLITE_OK){
		mosquitto_log_printf(MOSQ_LOG_ERR, "sqlite: Error restoring client messages: %s", sqlite3_errstr(rc));
		return MOSQ_ERR_UNKNOWN;
	}

	memset(&client_msg, 0, sizeof(client_msg));
	while(sqlite3_step(stmt) == SQLITE_ROW){
		client_msg.clientid = (const char *)sqlite3_column_text(stmt, 0);
		client_msg.cmsg_id = (uint64_t)sqlite3_column_int64(stmt, 1);
		client_msg.store_id = (uint64_t)sqlite3_column_int64(stmt, 2);
		client_msg.dup = (uint8_t)sqlite3_column_int(stmt, 3);
		client_msg.direction = (uint8_t)sqlite3_column_int(stmt, 4);
		client_msg.mid = (uint16_t)sqlite3_column_int(stmt, 5);
		client_msg.qos = (uint8_t)sqlite3_column_int(stmt, 6);
		client_msg.retain = sqlite3_column_int(stmt, 7);
		client_msg.state = (uint8_t)sqlite3_column_int(stmt, 8);
		client_msg.subscription_identifier = (uint32_t)sqlite3_column_int(stmt, 9);

		rc = mosquitto_persist_client_msg_add(&client_msg);
		if(rc == MOSQ_ERR_SUCCESS){
			count++;
		}else{
			failed++;
		}
	}
	sqlite3_finalize(stmt);

	mosquitto_log_printf(MOSQ_LOG_INFO, "sqlite: Restored %ld client messages (%ld failed)", count, failed);
	return MOSQ_ERR_SUCCESS;
}


static int retain_restore(struct mosquitto_sqlite *ms)
{
	sqlite3_stmt *stmt;
	int rc;
	long count = 0, failed = 0;
	const char *topic;
	uint64_t store_id;

	rc = sqlite3_prepare_v2(ms->db,
			"SELECT topic, store_id "
			"FROM retains ORDER BY topic",
			-1, &stmt, NULL);

	if(rc != SQLITE_OK){
		mosquitto_log_printf(MOSQ_LOG_ERR, "sqlite: Error restoring retained messages: %s", sqlite3_errstr(rc));
		return MOSQ_ERR_UNKNOWN;
	}

	while(sqlite3_step(stmt) == SQLITE_ROW){
		topic = (const char *)sqlite3_column_text(stmt, 0);
		if(!topic){
			failed++;
			continue;
		}
		store_id = (uint64_t)sqlite3_column_int64(stmt, 1);

		rc = mosquitto_persist_retain_msg_set(topic, store_id);
		if(rc == MOSQ_ERR_SUCCESS){
			count++;
		}else{
			failed++;
		}
	}
	sqlite3_finalize(stmt);

	mosquitto_log_printf(MOSQ_LOG_INFO, "sqlite: Restored %ld retained messages (%ld failed)", count, failed);
	return MOSQ_ERR_SUCCESS;
}


int persist_sqlite__restore_cb(int event, void *event_data, void *userdata)
{
	struct mosquitto_sqlite *ms = userdata;
	UNUSED(event);
	UNUSED(event_data);

	if(base_msg_restore(ms)) return MOSQ_ERR_UNKNOWN;
	if(retain_restore(ms)) return MOSQ_ERR_UNKNOWN;
	if(client_restore(ms)) return MOSQ_ERR_UNKNOWN;
	if(subscription_restore(ms)) return MOSQ_ERR_UNKNOWN;
	if(client_msg_restore(ms)) return MOSQ_ERR_UNKNOWN;

	return 0;
}
