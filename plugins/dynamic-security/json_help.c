/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR EDL-1.0

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include <cjson/cJSON.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include "mosquitto.h"


int json_get_bool(cJSON *json, const char *name, bool *value, bool optional, bool default_value)
{
	cJSON *jtmp;

	if(optional == true){
		*value = default_value;
	}

	jtmp = cJSON_GetObjectItem(json, name);
	if(jtmp){
		if(cJSON_IsBool(jtmp) == false){
			return MOSQ_ERR_INVAL;
		}
		*value = cJSON_IsTrue(jtmp);
	}else{
		if(optional == false){
			return MOSQ_ERR_INVAL;
		}
	}
	return MOSQ_ERR_SUCCESS;
}


int json_get_int(cJSON *json, const char *name, int *value, bool optional, int default_value)
{
	cJSON *jtmp;

	if(optional == true){
		*value = default_value;
	}

	jtmp = cJSON_GetObjectItem(json, name);
	if(jtmp){
		if(cJSON_IsNumber(jtmp) == false){
			return MOSQ_ERR_INVAL;
		}
		*value  = jtmp->valueint;
	}else{
		if(optional == false){
			return MOSQ_ERR_INVAL;
		}
	}
	return MOSQ_ERR_SUCCESS;
}


int json_get_string(cJSON *json, const char *name, char **value, bool optional)
{
	cJSON *jtmp;

	*value = NULL;

	jtmp = cJSON_GetObjectItem(json, name);
	if(jtmp){
		if(cJSON_IsString(jtmp) == false){
			return MOSQ_ERR_INVAL;
		}
		*value  = jtmp->valuestring;
	}else{
		if(optional == false){
			return MOSQ_ERR_INVAL;
		}
	}
	return MOSQ_ERR_SUCCESS;
}


cJSON *cJSON_AddIntToObject(cJSON * const object, const char * const name, int number)
{
	char buf[30];

	snprintf(buf, sizeof(buf), "%d", number);
	return cJSON_AddRawToObject(object, name, buf);
}
