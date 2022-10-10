/*
Copyright (c) 2020-2021 Roger Light <roger@atchoo.org>

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

#include <stdio.h>
#include <utlist.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"

#include "dynamic_security.h"

int dynsec_kicklist__add(struct dynsec__data *data, const char *username)
{
	struct dynsec__kicklist *kick;
	size_t slen;

	if(username){
		slen = strlen(username);
	}else{
		slen = 0;
	}
	kick = malloc(sizeof(struct dynsec__kicklist)+slen+1);
	if(!kick){
		return MOSQ_ERR_NOMEM;
	}
	if(username){
		strcpy(kick->username, username);
	}else{
		kick->username[0] = '\0';
	}
	DL_APPEND(data->kicklist, kick);

	return MOSQ_ERR_SUCCESS;
}

void dynsec_kicklist__kick(struct dynsec__data *data)
{
	struct dynsec__kicklist *kick, *tmp;

	DL_FOREACH_SAFE(data->kicklist, kick, tmp){
		DL_DELETE(data->kicklist, kick);
		if(strlen(kick->username)){
			mosquitto_kick_client_by_username(kick->username, false);
		}else{
			mosquitto_kick_client_by_username(NULL, false);
		}
		free(kick);
	}
}

void dynsec_kicklist__cleanup(struct dynsec__data *data)
{
	struct dynsec__kicklist *kick, *tmp;

	DL_FOREACH_SAFE(data->kicklist, kick, tmp){
		DL_DELETE(data->kicklist, kick);
		free(kick);
	}
}
