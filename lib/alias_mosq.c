/*
Copyright (c) 2019-2021 Roger Light <roger@atchoo.org>

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

#include <string.h>

#include "mosquitto.h"
#include "alias_mosq.h"
#include "memory_mosq.h"

static void alias__free_r2l(struct mosquitto *mosq);
static void alias__free_l2r(struct mosquitto *mosq);


int alias__add_l2r(struct mosquitto *mosq, const char *topic, uint16_t *alias)
{
	struct mosquitto__alias *aliases_new;

	if(mosq->alias_count_l2r < mosq->alias_max_l2r){
		aliases_new = mosquitto__realloc(mosq->aliases_l2r, sizeof(struct mosquitto__alias)*(size_t)(mosq->alias_count_l2r+1));
		if(!aliases_new) return MOSQ_ERR_NOMEM;
	
		mosq->aliases_l2r = aliases_new;
		mosq->alias_count_l2r++;
		*alias = mosq->alias_count_l2r;

		mosq->aliases_l2r[mosq->alias_count_l2r-1].alias = *alias;
		mosq->aliases_l2r[mosq->alias_count_l2r-1].topic = mosquitto__strdup(topic);
		if(!mosq->aliases_l2r[mosq->alias_count_l2r-1].topic){
			*alias = 0;
			return MOSQ_ERR_NOMEM;
		}
		return MOSQ_ERR_SUCCESS;
	}

	*alias = 0;
	return MOSQ_ERR_INVAL;
}


int alias__add_r2l(struct mosquitto *mosq, const char *topic, uint16_t alias)
{
	int i;
	struct mosquitto__alias *aliases_new;

	for(i=0; i<mosq->alias_count_r2l; i++){
		if(mosq->aliases_r2l[i].alias == alias){
			mosquitto__FREE(mosq->aliases_r2l[i].topic);
			mosq->aliases_r2l[i].topic = mosquitto__strdup(topic);
			if(mosq->aliases_r2l[i].topic){
				return MOSQ_ERR_SUCCESS;
			}else{
				return MOSQ_ERR_NOMEM;
			}
		}
	}

	/* New alias */
	aliases_new = mosquitto__realloc(mosq->aliases_r2l, sizeof(struct mosquitto__alias)*(size_t)(mosq->alias_count_r2l+1));
	if(!aliases_new) return MOSQ_ERR_NOMEM;

	mosq->aliases_r2l = aliases_new;
	mosq->alias_count_r2l++;

	mosq->aliases_r2l[mosq->alias_count_r2l-1].alias = alias;
	mosq->aliases_r2l[mosq->alias_count_r2l-1].topic = mosquitto__strdup(topic);
	if(!mosq->aliases_r2l[mosq->alias_count_r2l-1].topic){
		return MOSQ_ERR_NOMEM;
	}

	return MOSQ_ERR_SUCCESS;
}


int alias__find_by_alias(struct mosquitto *mosq, int direction, uint16_t alias, char **topic)
{
	int i;
	struct mosquitto__alias *aliases;
	int alias_count;

	if(direction == ALIAS_DIR_R2L){
		aliases = mosq->aliases_r2l;
		alias_count = mosq->alias_count_r2l;
	}else{
		aliases = mosq->aliases_l2r;
		alias_count = mosq->alias_count_l2r;
	}

	for(i=0; i<alias_count; i++){
		if(aliases[i].alias == alias){
			*topic = mosquitto__strdup(aliases[i].topic);
			if(*topic){
				return MOSQ_ERR_SUCCESS;
			}else{
				return MOSQ_ERR_NOMEM;
			}
		}
	}
	return MOSQ_ERR_INVAL;
}


int alias__find_by_topic(struct mosquitto *mosq, int direction, const char *topic, uint16_t *alias)
{
	int i;
	struct mosquitto__alias *aliases;
	int alias_count;

	if(direction == ALIAS_DIR_R2L){
		aliases = mosq->aliases_r2l;
		alias_count = mosq->alias_count_r2l;
	}else{
		aliases = mosq->aliases_l2r;
		alias_count = mosq->alias_count_l2r;
	}

	for(i=0; i<alias_count; i++){
		if(aliases[i].topic && !strcmp(aliases[i].topic, topic)){
			*alias = aliases[i].alias;
			return MOSQ_ERR_SUCCESS;
		}
	}
	return MOSQ_ERR_INVAL;
}


static void alias__free_r2l(struct mosquitto *mosq)
{
	int i;

	for(i=0; i<mosq->alias_count_r2l; i++){
		mosquitto__FREE(mosq->aliases_r2l[i].topic);
	}
	mosquitto__FREE(mosq->aliases_r2l);
	mosq->alias_count_r2l = 0;
}


static void alias__free_l2r(struct mosquitto *mosq)
{
	int i;

	for(i=0; i<mosq->alias_count_l2r; i++){
		mosquitto__FREE(mosq->aliases_l2r[i].topic);
	}
	mosquitto__FREE(mosq->aliases_l2r);
	mosq->alias_count_l2r = 0;
}

void alias__free_all(struct mosquitto *mosq)
{
	alias__free_r2l(mosq);
	alias__free_l2r(mosq);
}
