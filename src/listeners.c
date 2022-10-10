/*
Copyright (c) 2009-2021 Roger Light <roger@atchoo.org>

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
#include "memory_mosq.h"
#include "net_mosq.h"
#include "mosquitto_broker_internal.h"

static int listensock_index = 0;
extern int g_run;

void listener__set_defaults(struct mosquitto__listener *listener)
{
	listener->security_options.allow_anonymous = -1;
	listener->security_options.allow_zero_length_clientid = true;
	listener->protocol = mp_mqtt;
	listener->max_connections = -1;
	listener->max_qos = 2;
	listener->max_topic_alias = 10;
	listener->max_topic_alias_broker = 10;
}


void listeners__reload_all_certificates(void)
{
#ifdef WITH_TLS
	int i;
	int rc;
	struct mosquitto__listener *listener;

	for(i=0; i<db.config->listener_count; i++){
		listener = &db.config->listeners[i];
		if(listener->ssl_ctx && listener->certfile && listener->keyfile){
			rc = net__load_certificates(listener);
			if(rc){
				log__printf(NULL, MOSQ_LOG_ERR, "Error when reloading certificate '%s' or key '%s'.",
						listener->certfile, listener->keyfile);
			}
		}
	}
#endif
}


static int listeners__start_single_mqtt(struct mosquitto__listener *listener)
{
	int i;
	struct mosquitto__listener_sock *listensock_new;

	if(net__socket_listen(listener)){
		return 1;
	}
	g_listensock_count += listener->sock_count;
	listensock_new = mosquitto__realloc(g_listensock, sizeof(struct mosquitto__listener_sock)*(size_t)g_listensock_count);
	if(!listensock_new){
		return 1;
	}
	g_listensock = listensock_new;

	for(i=0; i<listener->sock_count; i++){
		if(listener->socks[i] == INVALID_SOCKET){
			return 1;
		}
		g_listensock[listensock_index].sock = listener->socks[i];
		g_listensock[listensock_index].listener = listener;
#if defined(WITH_EPOLL) || defined(WITH_KQUEUE)
		g_listensock[listensock_index].ident = id_listener;
#endif
		listensock_index++;
	}
	return MOSQ_ERR_SUCCESS;
}


#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_LWS
void listeners__add_websockets(struct lws_context *ws_context, mosq_sock_t fd)
{
	int i;
	struct mosquitto__listener *listener = NULL;
	struct mosquitto__listener_sock *listensock_new;

	/* Don't add more listeners after we've started the main loop */
	if(g_run || ws_context == NULL) return;

	/* Find context */
	for(i=0; i<db.config->listener_count; i++){
		if(db.config->listeners[i].ws_in_init){
			listener = &db.config->listeners[i];
			break;
		}
	}
	if(listener == NULL){
		return;
	}

	g_listensock_count++;
	listensock_new = mosquitto__realloc(g_listensock, sizeof(struct mosquitto__listener_sock)*(size_t)g_listensock_count);
	if(!listensock_new){
		return;
	}
	g_listensock = listensock_new;

	g_listensock[listensock_index].sock = fd;
	g_listensock[listensock_index].listener = listener;
#if defined(WITH_EPOLL) || defined(WITH_KQUEUE)
	g_listensock[listensock_index].ident = id_listener_ws;
#endif
	listensock_index++;
}
#endif


static int listeners__add_local(const char *host, uint16_t port)
{
	struct mosquitto__listener *listeners;
	listeners = db.config->listeners;

	listener__set_defaults(&listeners[db.config->listener_count]);
	listeners[db.config->listener_count].security_options.allow_anonymous = true;
	listeners[db.config->listener_count].port = port;
	listeners[db.config->listener_count].host = mosquitto__strdup(host);
	if(listeners[db.config->listener_count].host == NULL){
		return MOSQ_ERR_NOMEM;
	}
	if(listeners__start_single_mqtt(&listeners[db.config->listener_count])){
		mosquitto__FREE(listeners[db.config->listener_count].host);
		return MOSQ_ERR_UNKNOWN;
	}
	db.config->listener_count++;
	return MOSQ_ERR_SUCCESS;
}


static int listeners__start_local_only(void)
{
	/* Attempt to open listeners bound to 127.0.0.1 and ::1 only */
	int i;
	int rc;
	struct mosquitto__listener *listeners;

	listeners = mosquitto__realloc(db.config->listeners, 2*sizeof(struct mosquitto__listener));
	if(listeners == NULL){
		return MOSQ_ERR_NOMEM;
	}
	memset(listeners, 0, 2*sizeof(struct mosquitto__listener));
	db.config->listener_count = 0;
	db.config->listeners = listeners;

	log__printf(NULL, MOSQ_LOG_WARNING, "Starting in local only mode. Connections will only be possible from clients running on this machine.");
	log__printf(NULL, MOSQ_LOG_WARNING, "Create a configuration file which defines a listener to allow remote access.");
	log__printf(NULL, MOSQ_LOG_WARNING, "For more details see https://mosquitto.org/documentation/authentication-methods/");
	if(db.config->cmd_port_count == 0){
		rc = listeners__add_local("127.0.0.1", 1883);
		if(rc == MOSQ_ERR_NOMEM) return MOSQ_ERR_NOMEM;
		rc = listeners__add_local("::1", 1883);
		if(rc == MOSQ_ERR_NOMEM) return MOSQ_ERR_NOMEM;
	}else{
		for(i=0; i<db.config->cmd_port_count; i++){
			rc = listeners__add_local("127.0.0.1", db.config->cmd_port[i]);
			if(rc == MOSQ_ERR_NOMEM) return MOSQ_ERR_NOMEM;
			rc = listeners__add_local("::1", db.config->cmd_port[i]);
			if(rc == MOSQ_ERR_NOMEM) return MOSQ_ERR_NOMEM;
		}
	}

	if(db.config->listener_count > 0){
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_UNKNOWN;
	}
}


int listeners__start(void)
{
	int i;

	g_listensock_count = 0;

	if(db.config->local_only){
		if(listeners__start_local_only()){
			db__close();
			if(db.config->pid_file){
				(void)remove(db.config->pid_file);
			}
			return 1;
		}
		mux__add_listeners(g_listensock, g_listensock_count);
		return MOSQ_ERR_SUCCESS;
	}

	for(i=0; i<db.config->listener_count; i++){
		if(db.config->listeners[i].protocol == mp_mqtt){
			if(listeners__start_single_mqtt(&db.config->listeners[i])){
				db__close();
				if(db.config->pid_file){
					(void)remove(db.config->pid_file);
				}
				return 1;
			}
		}else if(db.config->listeners[i].protocol == mp_websockets){
#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_LWS
			mosq_websockets_init(&db.config->listeners[i], db.config);
			if(!db.config->listeners[i].ws_context){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to create websockets listener on port %d.", db.config->listeners[i].port);
				return 1;
			}
#elif defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_BUILTIN
			if(listeners__start_single_mqtt(&db.config->listeners[i])){
				db__close();
				if(db.config->pid_file){
					(void)remove(db.config->pid_file);
				}
				return 1;
			}
#endif
		}
	}
	if(g_listensock == NULL){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to start any listening sockets, exiting.");
		return 1;
	}

	mux__add_listeners(g_listensock, g_listensock_count);
	return MOSQ_ERR_SUCCESS;
}


void listeners__stop(void)
{
	int i;

	mux__delete_listeners(g_listensock, g_listensock_count);

	for(i=0; i<db.config->listener_count; i++){
#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_LWS
		if(db.config->listeners[i].ws_context){
			lws_context_destroy(db.config->listeners[i].ws_context);
		}
		mosquitto__FREE(db.config->listeners[i].ws_protocol);
#endif
#ifdef WITH_UNIX_SOCKETS
		if(db.config->listeners[i].unix_socket_path != NULL){
			unlink(db.config->listeners[i].unix_socket_path);
		}
#endif
	}

	for(i=0; i<g_listensock_count; i++){
		if(g_listensock[i].sock != INVALID_SOCKET){
			COMPAT_CLOSE(g_listensock[i].sock);
		}
	}
	mosquitto__FREE(g_listensock);
	g_listensock_count = 0;
	listensock_index = 0;
}
