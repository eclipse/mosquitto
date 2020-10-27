/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include <cJSON.h>
#include <stdbool.h>
#include <stdlib.h>

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


/* Return a number as a number, or attempt to convert a string to a number, or a bool to a number */
double json_get_as_number(const cJSON *json)
{
	char *endptr = NULL;

	if(cJSON_IsNumber(json)){
		return json->valuedouble;
	}else if(cJSON_IsString(json)){
		return strtod(json->valuestring, &endptr);
	}else if(cJSON_IsBool(json)){
		return cJSON_IsTrue(json);
	}else{
		return 0.0;
	}
}
