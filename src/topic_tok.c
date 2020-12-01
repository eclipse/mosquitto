/*
Copyright (c) 2010-2019 Roger Light <roger@atchoo.org>

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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "util_mosq.h"

#include "utlist.h"


static char *strtok_hier(char *str, char **saveptr)
{
	char *c;

	if(str != NULL){
		*saveptr = str;
	}

	if(*saveptr == NULL){
		return NULL;
	}

	c = strchr(*saveptr, '/');
	if(c){
		str = *saveptr;
		*saveptr = c+1;
		c[0] = '\0';
	}else if(*saveptr){
		/* No match, but surplus string */
		str = *saveptr;
		*saveptr = NULL;
	}
	return str;
}


int sub__topic_tokenise(const char *subtopic, char **local_sub, char ***topics, const char **sharename)
{
	char *saveptr = NULL;
	char *token;
	int count;
	int topic_index = 0;
	int i;
	size_t len;

	len = strlen(subtopic);
	if(len == 0){
		return MOSQ_ERR_INVAL;
	}

	*local_sub = mosquitto__strdup(subtopic);
	if((*local_sub) == NULL) return MOSQ_ERR_NOMEM;

	count = 0;
	saveptr = *local_sub;
	while(saveptr){
		saveptr = strchr(&saveptr[1], '/');
		count++;
	}
	*topics = mosquitto__calloc((size_t)(count+3) /* 3=$shared,sharename,NULL */, sizeof(char *));
	if((*topics) == NULL){
		mosquitto__free(*local_sub);
		return MOSQ_ERR_NOMEM;
	}

	if((*local_sub)[0] != '$'){
		(*topics)[topic_index] = "";
		topic_index++;
	}

	token = strtok_hier((*local_sub), &saveptr);
	while(token){
		(*topics)[topic_index] = token;
		topic_index++;
		token = strtok_hier(NULL, &saveptr);
	}

	if(!strcmp((*topics)[0], "$share")){
		if(count < 2){
			mosquitto__free(*local_sub);
			mosquitto__free(*topics);
			return MOSQ_ERR_PROTOCOL;
		}

		if(sharename){
			(*sharename) = (*topics)[1];
		}

		for(i=1; i<count-1; i++){
			(*topics)[i] = (*topics)[i+1];
		}
		(*topics)[0] = "";
		(*topics)[count-1] = NULL;
	}
	return MOSQ_ERR_SUCCESS;
}
