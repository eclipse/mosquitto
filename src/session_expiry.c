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

#include <math.h>
#include <stdio.h>
#include <utlist.h>

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "sys_tree.h"
#include "time_mosq.h"

static struct session_expiry_list *expiry_list = NULL;
static time_t last_check = 0;


static int session_expiry__cmp(struct session_expiry_list *i1, struct session_expiry_list *i2)
{
	if(i1->context->session_expiry_time == i2->context->session_expiry_time){
		return 0;
	}else if(i1->context->session_expiry_time > i2->context->session_expiry_time){
		return 1;
	}else{
		return -1;
	}
}


static void set_session_expiry_time(struct mosquitto *context)
{
	context->session_expiry_time = db.now_real_s;

	if(db.config->persistent_client_expiration == 0){
		/* No global expiry, so use the client expiration interval */
		context->session_expiry_time += context->session_expiry_interval;
	}else{
		/* We have a global expiry interval */
		if(db.config->persistent_client_expiration < context->session_expiry_interval){
			/* The client expiry is longer than the global expiry, so use the global */
			context->session_expiry_time += db.config->persistent_client_expiration;
		}else{
			/* The global expiry is longer than the client expiry, so use the client */
			context->session_expiry_time += context->session_expiry_interval;
		}
	}
}


int session_expiry__add(struct mosquitto *context)
{
	struct session_expiry_list *item;

	if(db.config->persistent_client_expiration == 0){
		if(context->session_expiry_interval == UINT32_MAX){
			/* There isn't a global expiry set, and the client has asked to
			 * never expire, so we don't add it to the list. */
			return MOSQ_ERR_SUCCESS;
		}
	}

	item = mosquitto__calloc(1, sizeof(struct session_expiry_list));
	if(!item) return MOSQ_ERR_NOMEM;

	item->context = context;
	set_session_expiry_time(item->context);
	context->expiry_list_item = item;

	DL_INSERT_INORDER(expiry_list, item, session_expiry__cmp);

	plugin_persist__handle_client_update(context);

	return MOSQ_ERR_SUCCESS;
}


int session_expiry__add_from_persistence(struct mosquitto *context, time_t expiry_time)
{
	struct session_expiry_list *item;

	if(db.config->persistent_client_expiration == 0){
		if(context->session_expiry_interval == UINT32_MAX){
			/* There isn't a global expiry set, and the client has asked to
			 * never expire, so we don't add it to the list. */
			return MOSQ_ERR_SUCCESS;
		}
	}

	item = mosquitto__calloc(1, sizeof(struct session_expiry_list));
	if(!item) return MOSQ_ERR_NOMEM;

	item->context = context;
	if(expiry_time){
		item->context->session_expiry_time = expiry_time;
	}else{
		set_session_expiry_time(item->context);

	}
	context->expiry_list_item = item;

	DL_INSERT_INORDER(expiry_list, item, session_expiry__cmp);

	return MOSQ_ERR_SUCCESS;
}


void session_expiry__remove(struct mosquitto *context)
{
	if(context->expiry_list_item){
		DL_DELETE(expiry_list, context->expiry_list_item);
		mosquitto__FREE(context->expiry_list_item);
	}
}


/* Call on broker shutdown only */
void session_expiry__remove_all(void)
{
	struct session_expiry_list *item, *tmp;
	struct mosquitto *context;

	DL_FOREACH_SAFE(expiry_list, item, tmp){
		context = item->context;
		session_expiry__remove(context);
		context->session_expiry_interval = 0;
		context->will_delay_interval = 0;
		will_delay__remove(context);
		context__disconnect(context);
	}
}

void session_expiry__check(void)
{
	struct session_expiry_list *item, *tmp;
	struct mosquitto *context;
	time_t timeout;

	if(db.now_real_s <= last_check){
		if(expiry_list){
			/* Next event is the first item of the list, we must set the timeout even if we aren't 
			 * checking the full list */
			timeout = (expiry_list->context->session_expiry_time - db.now_real_s) * 1000;
			if(timeout <= 0){
				timeout = 100;
			}
			loop__update_next_event(timeout);
		}
		return;
	}

	last_check = db.now_real_s;

	DL_FOREACH_SAFE(expiry_list, item, tmp){
		if(item->context->session_expiry_time < db.now_real_s){

			context = item->context;
			session_expiry__remove(context);

			if(context->id){
				log__printf(NULL, MOSQ_LOG_NOTICE, "Expiring client %s due to timeout.", context->id);
			}
			G_CLIENTS_EXPIRED_INC();

			/* Session has now expired, so clear interval */
			context->session_expiry_interval = 0;
			/* Session has expired, so will delay should be cleared. */
			context->will_delay_interval = 0;
			will_delay__remove(context);
			context__send_will(context);
			plugin_persist__handle_client_delete(context);
			context__add_to_disused(context);
		}else{
			timeout = (item->context->session_expiry_time - db.now_real_s + 1) * 1000;
			if(timeout <= 0){
				timeout = 100;
			}
			loop__update_next_event(timeout);
			return;
		}
	}
}
