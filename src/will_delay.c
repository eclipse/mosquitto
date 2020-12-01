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

#include <math.h>
#include <stdio.h>
#include <utlist.h>

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "time_mosq.h"

static struct will_delay_list *delay_list = NULL;
static time_t last_check = 0;


static int will_delay__cmp(struct will_delay_list *i1, struct will_delay_list *i2)
{
	return (int)(i1->context->will_delay_interval - i2->context->will_delay_interval);
}


int will_delay__add(struct mosquitto *context)
{
	struct will_delay_list *item;

	item = mosquitto__calloc(1, sizeof(struct will_delay_list));
	if(!item) return MOSQ_ERR_NOMEM;

	item->context = context;
	context->will_delay_entry = item;
	item->context->will_delay_time = db.now_real_s + item->context->will_delay_interval;

	DL_INSERT_INORDER(delay_list, item, will_delay__cmp);

	return MOSQ_ERR_SUCCESS;
}


/* Call on broker shutdown only */
void will_delay__send_all(void)
{
	struct will_delay_list *item, *tmp;

	DL_FOREACH_SAFE(delay_list, item, tmp){
		DL_DELETE(delay_list, item);
		item->context->will_delay_interval = 0;
		item->context->will_delay_entry = NULL;
		context__send_will(item->context);
		mosquitto__free(item);
	}
	
}

void will_delay__check(void)
{
	struct will_delay_list *item, *tmp;

	if(db.now_real_s <= last_check) return;

	last_check = db.now_real_s;

	DL_FOREACH_SAFE(delay_list, item, tmp){
		if(item->context->will_delay_time < db.now_real_s){
			DL_DELETE(delay_list, item);
			item->context->will_delay_interval = 0;
			item->context->will_delay_entry = NULL;
			context__send_will(item->context);
			if(item->context->session_expiry_interval == 0){
				context__add_to_disused(item->context);
			}
			mosquitto__free(item);
		}else{
			return;
		}
	}
	
}


void will_delay__remove(struct mosquitto *mosq)
{
	if(mosq->will_delay_entry != NULL){
		DL_DELETE(delay_list, mosq->will_delay_entry);
		mosquitto__free(mosq->will_delay_entry);
		mosq->will_delay_entry = NULL;
	}
}

