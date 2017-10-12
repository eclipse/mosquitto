/*
Copyright (c) 2009-2014 Roger Light <roger@atchoo.org>

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

#include <assert.h>
#include <time.h>

#include <config.h>

#include <mosquitto_broker.h>
#include <memory_mosq.h>
#include <time_mosq.h>

#include "uthash.h"

struct mosquitto *mqtt3_context_init(struct mosquitto_db *db, mosq_sock_t sock)
{
	struct mosquitto *context;
	char address[1024];

	context = _mosquitto_calloc(1, sizeof(struct mosquitto));
	if(!context) return NULL;
	
	context->state = mosq_cs_new;
	context->sock = sock;
	context->last_msg_in = mosquitto_time();
	context->next_msg_out = mosquitto_time() + 60;
	context->keepalive = 60; /* Default to 60s */
	context->clean_session = true;
	context->disconnect_t = 0;
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
	_mosquitto_packet_cleanup(&context->in_packet);
	context->out_packet = NULL;
	context->current_out_packet = NULL;

	context->address = NULL;
	if((int)sock >= 0){
		if(!_mosquitto_socket_get_address(sock, address, 1024)){
			context->address = _mosquitto_strdup(address);
		}
		if(!context->address){
			/* getpeername and inet_ntop failed and not a bridge */
			_mosquitto_free(context);
			return NULL;
		}
	}
	context->bridge = NULL;
	context->msgs = NULL;
	context->last_msg = NULL;
	context->msg_count = 0;
	context->msg_count12 = 0;
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
void mqtt3_context_cleanup(struct mosquitto_db *db, struct mosquitto *context, bool do_free)
{
	struct _mosquitto_packet *packet;
	struct mosquitto_client_msg *msg, *next;
	int i;

	if(!context) return;

	if(context->username){
		_mosquitto_free(context->username);
		context->username = NULL;
	}
	if(context->password){
		_mosquitto_free(context->password);
		context->password = NULL;
	}
#ifdef WITH_BRIDGE
	if(context->bridge){
		for(i=0; i<db->bridge_count; i++){
			if(db->bridges[i] == context){
				db->bridges[i] = NULL;
			}
		}
		if(context->bridge->local_clientid){
			_mosquitto_free(context->bridge->local_clientid);
			context->bridge->local_clientid = NULL;
		}
		if(context->bridge->remote_username){
			context->bridge->remote_username = NULL;
		}
		if(context->bridge->remote_password){
			context->bridge->remote_password = NULL;
		}
		if(context->bridge->local_username){
			context->bridge->local_username = NULL;
		}
		if(context->bridge->local_password){
			context->bridge->local_password = NULL;
		}
		if(context->bridge->local_clientid){
			context->bridge->local_clientid = NULL;
		}
	}
#endif
	_mosquitto_socket_close(db, context);
	if((do_free || context->clean_session) && db){
		mqtt3_subs_clean_session(db, context);
		mqtt3_db_messages_delete(db, context);
	}
	if(context->address){
		_mosquitto_free(context->address);
		context->address = NULL;
	}

	mqtt3_context_send_will(db, context);

	if(context->id){
		assert(db); /* db can only be NULL here if the client hasn't sent a
					   CONNECT and hence wouldn't have an id. */

		HASH_DELETE(hh_id, db->contexts_by_id, context);
		_mosquitto_free(context->id);
		context->id = NULL;
	}
	_mosquitto_packet_cleanup(&(context->in_packet));
	if(context->current_out_packet){
		_mosquitto_packet_cleanup(context->current_out_packet);
		_mosquitto_free(context->current_out_packet);
		context->current_out_packet = NULL;
	}
	while(context->out_packet){
		_mosquitto_packet_cleanup(context->out_packet);
		packet = context->out_packet;
		context->out_packet = context->out_packet->next;
		_mosquitto_free(packet);
	}
	if(do_free || context->clean_session){
		msg = context->msgs;
		while(msg){
			next = msg->next;
			mosquitto__db_msg_store_deref(db, &msg->store);
			_mosquitto_free(msg);
			msg = next;
		}
		context->msgs = NULL;
		context->last_msg = NULL;
	}
	if(do_free){
		_mosquitto_free(context);
	}
}


void mqtt3_context_send_will(struct mosquitto_db *db, struct mosquitto *ctxt)
{
	if(ctxt->state != mosq_cs_disconnecting && ctxt->will){
		if(mosquitto_acl_check(db, ctxt, ctxt->will->topic, MOSQ_ACL_WRITE) == MOSQ_ERR_SUCCESS){
			/* Unexpected disconnect, queue the client will. */
			mqtt3_db_messages_easy_queue(db, ctxt, ctxt->will->topic, ctxt->will->qos, ctxt->will->payloadlen, ctxt->will->payload, ctxt->will->retain);
		}
	}
	if(ctxt->will){
		if(ctxt->will->topic) _mosquitto_free(ctxt->will->topic);
		if(ctxt->will->payload) _mosquitto_free(ctxt->will->payload);
		_mosquitto_free(ctxt->will);
		ctxt->will = NULL;
	}
}


void mqtt3_context_disconnect(struct mosquitto_db *db, struct mosquitto *ctxt)
{
	mqtt3_context_send_will(db, ctxt);

	ctxt->disconnect_t = time(NULL);
	_mosquitto_socket_close(db, ctxt);
}

void mosquitto__add_context_to_disused(struct mosquitto_db *db, struct mosquitto *context)
{
	if(db->ll_for_free){
		context->for_free_next = db->ll_for_free;
		db->ll_for_free = context;
	}else{
		db->ll_for_free = context;
	}
}

void mosquitto__free_disused_contexts(struct mosquitto_db *db)
{
	struct mosquitto *context, *next;
	assert(db);

	context = db->ll_for_free;
	while(context){
		next = context->for_free_next;
		mqtt3_context_cleanup(db, context, true);
		context = next;
	}
	db->ll_for_free = NULL;
}

