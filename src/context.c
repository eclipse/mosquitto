/*
Copyright (c) 2009-2019 Roger Light <roger@atchoo.org>

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

struct mosquitto *context__init(struct mosquitto_db *db, mosq_sock_t sock)
{
	struct mosquitto *context;
	char address[1024];

	context = mosquitto__calloc(1, sizeof(struct mosquitto));
	if(!context) return NULL;
	
	context->pollfd_index = -1;
	mosquitto__set_state(context, mosq_cs_new);
	context->sock = sock;
	context->last_msg_in = mosquitto_time();
	context->next_msg_out = mosquitto_time() + 60;
	context->keepalive = 60; /* Default to 60s */
	context->clean_start = true;
	context->id = NULL;
	context->last_mid = 0;
	context->will = NULL;
	context->username = NULL;
	context->password = NULL;
	context->listener = NULL;
	context->acl_list = NULL;

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
		if(!net__socket_get_address(sock, address, 1024)){
			context->address = mosquitto__strdup(address);
		}
		if(!context->address){
			/* getpeername and inet_ntop failed and not a bridge */
			mosquitto__free(context);
			return NULL;
		}
	}
	context->bridge = NULL;
	context->msgs_in.inflight_maximum = db->config->max_inflight_messages;
	context->msgs_out.inflight_maximum = db->config->max_inflight_messages;
	context->msgs_in.inflight_quota = db->config->max_inflight_messages;
	context->msgs_out.inflight_quota = db->config->max_inflight_messages;
	context->maximum_qos = 2;
#ifdef WITH_TLS
	context->ssl = NULL;
#endif

	if((int)context->sock >= 0){
		HASH_ADD(hh_sock, db->contexts_by_sock, sock, sizeof(context->sock), context);
	}
	return context;
}

/*
 * This will result in any outgoing packets going unsent. If we're disconnected
 * forcefully then it is usually an error condition and shouldn't be a problem,
 * but it will mean that CONNACK messages will never get sent for bad protocol
 * versions for example.
 */
void context__cleanup(struct mosquitto_db *db, struct mosquitto *context, bool do_free)
{
	struct mosquitto__packet *packet;
#ifdef WITH_BRIDGE
	int i;
#endif

	if(!context) return;

#ifdef WITH_BRIDGE
	if(context->bridge){
		for(i=0; i<db->bridge_count; i++){
			if(db->bridges[i] == context){
				db->bridges[i] = NULL;
			}
		}
		mosquitto__free(context->bridge->local_clientid);
		context->bridge->local_clientid = NULL;

		mosquitto__free(context->bridge->local_username);
		context->bridge->local_username = NULL;

		mosquitto__free(context->bridge->local_password);
		context->bridge->local_password = NULL;

		if(context->bridge->remote_clientid != context->id){
			mosquitto__free(context->bridge->remote_clientid);
		}
		context->bridge->remote_clientid = NULL;

		if(context->bridge->remote_username != context->username){
			mosquitto__free(context->bridge->remote_username);
		}
		context->bridge->remote_username = NULL;

		if(context->bridge->remote_password != context->password){
			mosquitto__free(context->bridge->remote_password);
		}
		context->bridge->remote_password = NULL;
	}
#endif

	alias__free_all(context);

	mosquitto__free(context->auth_method);
	context->auth_method = NULL;

	mosquitto__free(context->username);
	context->username = NULL;

	mosquitto__free(context->password);
	context->password = NULL;

	net__socket_close(db, context);
	if(do_free || context->clean_start){
		sub__clean_session(db, context);
		db__messages_delete(db, context);
	}

	mosquitto__free(context->address);
	context->address = NULL;

	context__send_will(db, context);

	if(context->id){
		context__remove_from_by_id(db, context);
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
	if(do_free || context->clean_start){
		db__messages_delete(db, context);
	}
	
	net__adns_cancel(&context->adns);

#ifdef WITH_TLS
	if(context->ssl_ctx){
		SSL_CTX_free(context->ssl_ctx);
	}
#endif

	if(do_free){
		mosquitto__free(context);
	}
}


void context__send_will(struct mosquitto_db *db, struct mosquitto *ctxt)
{
	if(ctxt->state != mosq_cs_disconnecting && ctxt->will){
		if(ctxt->will_delay_interval > 0){
			will_delay__add(ctxt);
			return;
		}

		if(mosquitto_acl_check(db, ctxt,
					ctxt->will->msg.topic,
					ctxt->will->msg.payloadlen,
					ctxt->will->msg.payload,
					ctxt->will->msg.qos,
					ctxt->will->msg.retain,
					MOSQ_ACL_WRITE) == MOSQ_ERR_SUCCESS){

			/* Unexpected disconnect, queue the client will. */
			db__messages_easy_queue(db, ctxt,
					ctxt->will->msg.topic,
					ctxt->will->msg.qos,
					ctxt->will->msg.payloadlen,
					ctxt->will->msg.payload,
					ctxt->will->msg.retain,
					ctxt->will->expiry_interval,
					&ctxt->will->properties);
		}
	}
	will__clear(ctxt);
}


void context__disconnect(struct mosquitto_db *db, struct mosquitto *context)
{
	net__socket_close(db, context);

	context__send_will(db, context);
	if(context->session_expiry_interval == 0){
		/* Client session is due to be expired now */
#ifdef WITH_BRIDGE
		if(!context->bridge)
#endif
		{
			if(context->will_delay_interval == 0){
				/* This will be done later, after the will is published for delay>0. */
				context__add_to_disused(db, context);
			}
		}
	}else{
		session_expiry__add(db, context);
	}
	mosquitto__set_state(context, mosq_cs_disconnected);
}

void context__add_to_disused(struct mosquitto_db *db, struct mosquitto *context)
{
	if(context->state == mosq_cs_disused) return;

	mosquitto__set_state(context, mosq_cs_disused);

	if(context->id){
		context__remove_from_by_id(db, context);
		mosquitto__free(context->id);
		context->id = NULL;
	}

	context->for_free_next = db->ll_for_free;
	db->ll_for_free = context;
}

void context__free_disused(struct mosquitto_db *db)
{
	struct mosquitto *context, *next;
#ifdef WITH_WEBSOCKETS
	struct mosquitto *last = NULL;
#endif
	assert(db);

	context = db->ll_for_free;
	db->ll_for_free = NULL;
	while(context){
#ifdef WITH_WEBSOCKETS
		if(context->wsi){
			/* Don't delete yet, lws hasn't finished with it */
			if(last){
				last->for_free_next = context;
			}else{
				db->ll_for_free = context;
			}
			next = context->for_free_next;
			context->for_free_next = NULL;
			last = context;
			context = next;
		}else
#endif
		{
			next = context->for_free_next;
			context__cleanup(db, context, true);
			context = next;
		}
	}
}


void context__remove_from_by_id(struct mosquitto_db *db, struct mosquitto *context)
{
	if(context->removed_from_by_id == false && context->id){
		HASH_DELETE(hh_id, db->contexts_by_id, context);
		context->removed_from_by_id = true;
	}
}

