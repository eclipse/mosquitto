/*
Copyright (c) 2019-2020 Roger Light <roger@atchoo.org>

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

#include "mosquitto.h"
#include "alias_mosq.h"
#include "memory_mosq.h"

int alias__add(struct mosquitto *mosq, const char *topic, uint16_t alias)
{
	int i;
	struct mosquitto__alias *aliases;

	for(i=0; i<mosq->alias_count; i++){
		if(mosq->aliases[i].alias == alias){
			mosquitto__free(mosq->aliases[i].topic);
			mosq->aliases[i].topic = mosquitto__strdup(topic);
			if(mosq->aliases[i].topic){
				return MOSQ_ERR_SUCCESS;
			}else{
				
				return MOSQ_ERR_NOMEM;
			}
		}
	}

	/* New alias */
	aliases = mosquitto__realloc(mosq->aliases, sizeof(struct mosquitto__alias)*(size_t)(mosq->alias_count+1));
	if(!aliases) return MOSQ_ERR_NOMEM;

	mosq->aliases = aliases;
	mosq->aliases[mosq->alias_count].alias = alias;
	mosq->aliases[mosq->alias_count].topic = mosquitto__strdup(topic);
	if(!mosq->aliases[mosq->alias_count].topic){
		return MOSQ_ERR_NOMEM;
	}
	mosq->alias_count++;

	return MOSQ_ERR_SUCCESS;
}


int alias__find(struct mosquitto *mosq, char **topic, uint16_t alias)
{
	int i;

	for(i=0; i<mosq->alias_count; i++){
		if(mosq->aliases[i].alias == alias){
			*topic = mosquitto__strdup(mosq->aliases[i].topic);
			if(*topic){
				return MOSQ_ERR_SUCCESS;
			}else{
				return MOSQ_ERR_NOMEM;
			}
		}
	}
	return MOSQ_ERR_INVAL;
}


void alias__free_all(struct mosquitto *mosq)
{
	int i;

	for(i=0; i<mosq->alias_count; i++){
		mosquitto__free(mosq->aliases[i].topic);
	}
	mosquitto__free(mosq->aliases);
	mosq->aliases = NULL;
	mosq->alias_count = 0;
}
