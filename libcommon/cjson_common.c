/*
Copyright (c) 2009-2021 Roger Light <roger@atchoo.org>

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

#include "config.h"

#include <cjson/cJSON.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mosquitto.h"

cJSON *mosquitto_properties_to_json(const mosquitto_property *properties)
{
	cJSON *array, *obj;
	char *name, *value;
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

	return array;
}
