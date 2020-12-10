/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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
#include <time.h>

#include "mosquitto_broker_internal.h"
#include "alias_mosq.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "time_mosq.h"
#include "util_mosq.h"
#include "will_mosq.h"

#include "uthash.h"

struct mosquitto *context__init(mosq_sock_t sock)
{
	struct mosquitto *context;
	char address[1024];

	context = mosquitto__calloc(1, sizeof(struct mosquitto));
	if(!context) return NULL;
	
#ifdef WITH_EPOLL
	context->ident = id_client;
#else
	context->pollfd_index = -1;
#endif
	mosquitto__set_state(context, mosq_cs_new);
	context->sock = sock;
	context->last_msg_in = db.now_s;
	context->next_msg_out = db.now_s + 60;
	context->keepalive = 60; /* Default to 60s */
	context->clean_start = true;
	context->id = NULL;
	context->last_mid = 0;
	context->will = NULL;
	context->username = NULL;
	context->password = NULL;
	context->listener = NULL;
	context->acl_list = NULL;
	context->retain_available = true;

	/* is_bridge records whether this client is a bridge or not. This could be
	 * done by looking at context->bridge for bridges that we create ourself,
	 * but incoming bridges need some other way of being recorded. */
	context->is_bridge = false;

	context->in_packet.payload = NULL;
	packet__cleanup(&context->in_packet);
	context->out_packet = NULL;
	context->current_out_packet = NULL;

	context->address = NULL;
	if((int)sock >= 0){
		if(!net__socket_get_address(sock, address, 1024, &context->remote_port)){
			context->address = mosquitto__strdup(address);
		}
		if(!context->address){
			/* getpeername and inet_ntop failed and not a bridge */
			mosquitto__free(context);
			return NULL;
		}
	}
	context->bridge = NULL;
	context->msgs_in.inflight_maximum = db.config->max_inflight_messages;
	context->msgs_out.inflight_maximum = db.config->max_inflight_messages;
	context->msgs_in.inflight_quota = db.config->max_inflight_messages;
	context->msgs_out.inflight_quota = db.config->max_inflight_messages;
	context->max_qos = 2;
#ifdef WITH_TLS
	context->ssl = NULL;
#endif

	if((int)context->sock >= 0){
		HASH_ADD(hh_sock, db.contexts_by_sock, sock, sizeof(context->sock), context);
	}
	return context;
}

/*
 * This will result in any outgoing packets going unsent. If we're disconnected
 * forcefully then it is usually an error condition and shouldn't be a problem,
 * but it will mean that CONNACK messages will never get sent for bad protocol
 * versions for example.
 */
void context__cleanup(struct mosquitto *context, bool force_free)
{
	struct mosquitto__packet *packet;

	if(!context) return;

	if(force_free){
		context->clean_start = true;
	}

#ifdef WITH_BRIDGE
	if(context->bridge){
		bridge__cleanup(context);
	}
#endif

	alias__free_all(context);

	mosquitto__free(context->auth_method);
	context->auth_method = NULL;

	mosquitto__free(context->username);
	context->username = NULL;

	mosquitto__free(context->password);
	context->password = NULL;

	net__socket_close(context);
	if(force_free){
		sub__clean_session(context);
	}
	db__messages_delete(context, force_free);

	mosquitto__free(context->address);
	context->address = NULL;

	context__send_will(context);

	if(context->id){
		context__remove_from_by_id(context);
		mosquitto__free(context->id);
		context->id = NULL;
	}
	packet__cleanup(&(context->in_packet));
	if(context->current_out_packet){
		packet__cleanup(context->current_out_packet);
		mosquitto__free(context->current_out_packet);
		context->current_out_packet = NULL;
	}
	while(context->out_packet){
		packet__cleanup(context->out_packet);
		packet = context->out_packet;
		context->out_packet = context->out_packet->next;
		mosquitto__free(packet);
	}
#if defined(WITH_BROKER) && defined(__GLIBC__) && defined(WITH_ADNS)
	if(context->adns){
		gai_cancel(context->adns);
		mosquitto__free((struct addrinfo *)context->adns->ar_request);
		mosquitto__free(context->adns);
	}
#endif
	if(force_free){
		mosquitto__free(context);
	}
}


void context__send_will(struct mosquitto *ctxt)
{
	if(ctxt->state != mosq_cs_disconnecting && ctxt->will){
		if(ctxt->will_delay_interval > 0){
			will_delay__add(ctxt);
			return;
		}

		if(mosquitto_acl_check(ctxt,
					ctxt->will->msg.topic,
					(uint32_t)ctxt->will->msg.payloadlen,
					ctxt->will->msg.payload,
					(uint8_t)ctxt->will->msg.qos,
					ctxt->will->msg.retain,
					MOSQ_ACL_WRITE) == MOSQ_ERR_SUCCESS){

			/* Unexpected disconnect, queue the client will. */
			db__messages_easy_queue(ctxt,
					ctxt->will->msg.topic,
					(uint8_t)ctxt->will->msg.qos,
					(uint32_t)ctxt->will->msg.payloadlen,
					ctxt->will->msg.payload,
					ctxt->will->msg.retain,
					ctxt->will->expiry_interval,
					&ctxt->will->properties);
		}
	}
	will__clear(ctxt);
}


void context__disconnect(struct mosquitto *context)
{
	if(mosquitto__get_state(context) == mosq_cs_disconnected){
		return;
	}

	plugin__handle_disconnect(context, -1);

	net__socket_close(context);

	context__send_will(context);
	if(context->session_expiry_interval == 0){
		/* Client session is due to be expired now */
#ifdef WITH_BRIDGE
		if(context->bridge == NULL)
#endif
		{
			if(context->will_delay_interval == 0){
				/* This will be done later, after the will is published for delay>0. */
				context__add_to_disused(context);
			}
		}
	}else{
		session_expiry__add(context);
	}
	keepalive__remove(context);
	mosquitto__set_state(context, mosq_cs_disconnected);
}

void context__add_to_disused(struct mosquitto *context)
{
	if(context->state == mosq_cs_disused) return;

	mosquitto__set_state(context, mosq_cs_disused);

	if(context->id){
		context__remove_from_by_id(context);
		mosquitto__free(context->id);
		context->id = NULL;
	}

	context->for_free_next = db.ll_for_free;
	db.ll_for_free = context;
}

void context__free_disused(void)
{
	struct mosquitto *context, *next;
#ifdef WITH_WEBSOCKETS
	struct mosquitto *last = NULL;
#endif

	context = db.ll_for_free;
	db.ll_for_free = NULL;
	while(context){
#ifdef WITH_WEBSOCKETS
		if(context->wsi){
			/* Don't delete yet, lws hasn't finished with it */
			if(last){
				last->for_free_next = context;
			}else{
				db.ll_for_free = context;
			}
			next = context->for_free_next;
			context->for_free_next = NULL;
			last = context;
			context = next;
		}else
#endif
		{
			next = context->for_free_next;
			context__cleanup(context, true);
			context = next;
		}
	}
}


void context__remove_from_by_id(struct mosquitto *context)
{
	struct mosquitto *context_found;

	if(context->removed_from_by_id == false && context->id){
		HASH_FIND(hh_id, db.contexts_by_id, context->id, strlen(context->id), context_found);
		if(context_found){
			HASH_DELETE(hh_id, db.contexts_by_id, context_found);
		}
		context->removed_from_by_id = true;
	}
}

