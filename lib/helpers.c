/*
Copyright (c) 2016-2020 Roger Light <roger@atchoo.org>

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

#include <errno.h>
#include <stdbool.h>

#include "mosquitto.h"
#include "mosquitto_internal.h"

struct userdata__callback {
	const char *topic;
	int (*callback)(struct mosquitto *, void *, const struct mosquitto_message *);
	void *userdata;
	int qos;
};

struct userdata__simple {
	struct mosquitto_message *messages;
	int max_msg_count;
	int message_count;
	bool want_retained;
};


static void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	struct userdata__callback *userdata = obj;

	UNUSED(rc);

	mosquitto_subscribe(mosq, NULL, userdata->topic, userdata->qos);
}


static void on_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	int rc;
	struct userdata__callback *userdata = obj;

	rc = userdata->callback(mosq, userdata->userdata, message);
	if(rc){
		mosquitto_disconnect(mosq);
	}
}

static int on_message_simple(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	struct userdata__simple *userdata = obj;
	int rc;

	if(userdata->max_msg_count == 0){
		return 0;
	}

	/* Don't process stale retained messages if 'want_retained' was false */
	if(!userdata->want_retained && message->retain){
		return 0;
	}

	userdata->max_msg_count--;

	rc = mosquitto_message_copy(&userdata->messages[userdata->message_count], message);
	if(rc){
		return rc;
	}
	userdata->message_count++;
	if(userdata->max_msg_count == 0){
		mosquitto_disconnect(mosq);
	}
	return 0;
}


libmosq_EXPORT int mosquitto_subscribe_simple(
		struct mosquitto_message **messages,
		int msg_count,
		bool want_retained,
		const char *topic,
		int qos,
		const char *host,
		int port,
		const char *client_id,
		int keepalive,
		bool clean_session,
		const char *username,
		const char *password,
		const struct libmosquitto_will *will,
		const struct libmosquitto_tls *tls)
{
	struct userdata__simple userdata;
	int rc;
	int i;

	if(!topic || msg_count < 1 || !messages){
		return MOSQ_ERR_INVAL;
	}

	*messages = NULL;

	userdata.messages = calloc(sizeof(struct mosquitto_message), (size_t)msg_count);
	if(!userdata.messages){
		return MOSQ_ERR_NOMEM;
	}
	userdata.message_count = 0;
	userdata.max_msg_count = msg_count;
	userdata.want_retained = want_retained;

	rc = mosquitto_subscribe_callback(
			on_message_simple, &userdata,
			topic, qos,
			host, port,
			client_id, keepalive, clean_session,
			username, password,
			will, tls);

	if(!rc && userdata.max_msg_count == 0){
		*messages = userdata.messages;
		return MOSQ_ERR_SUCCESS;
	}else{
		for(i=0; i<msg_count; i++){
			mosquitto_message_free_contents(&userdata.messages[i]);
		}
		free(userdata.messages);
		userdata.messages = NULL;
		return rc;
	}
}


libmosq_EXPORT int mosquitto_subscribe_callback(
		int (*callback)(struct mosquitto *, void *, const struct mosquitto_message *),
		void *userdata,
		const char *topic,
		int qos,
		const char *host,
		int port,
		const char *client_id,
		int keepalive,
		bool clean_session,
		const char *username,
		const char *password,
		const struct libmosquitto_will *will,
		const struct libmosquitto_tls *tls)
{
	struct mosquitto *mosq;
	struct userdata__callback cb_userdata;
	int rc;

	if(!callback || !topic){
		return MOSQ_ERR_INVAL;
	}

	cb_userdata.topic = topic;
	cb_userdata.qos = qos;
	cb_userdata.userdata = userdata;
	cb_userdata.callback = callback;

	mosq = mosquitto_new(client_id, clean_session, &cb_userdata);
	if(!mosq){
		return MOSQ_ERR_NOMEM;
	}

	if(will){
		rc = mosquitto_will_set(mosq, will->topic, will->payloadlen, will->payload, will->qos, will->retain);
		if(rc){
			mosquitto_destroy(mosq);
			return rc;
		}
	}
	if(username){
		rc = mosquitto_username_pw_set(mosq, username, password);
		if(rc){
			mosquitto_destroy(mosq);
			return rc;
		}
	}
	if(tls){
		rc = mosquitto_tls_set(mosq, tls->cafile, tls->capath, tls->certfile, tls->keyfile, tls->pw_callback);
		if(rc){
			mosquitto_destroy(mosq);
			return rc;
		}
		rc = mosquitto_tls_opts_set(mosq, tls->cert_reqs, tls->tls_version, tls->ciphers);
		if(rc){
			mosquitto_destroy(mosq);
			return rc;
		}
	}

	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_message_callback_set(mosq, on_message_callback);

	rc = mosquitto_connect(mosq, host, port, keepalive);
	if(rc){
		mosquitto_destroy(mosq);
		return rc;
	}
	rc = mosquitto_loop_forever(mosq, -1, 1);
	mosquitto_destroy(mosq);
	return rc;
}

