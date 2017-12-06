/*
Copyright (c) 2017 Viktor Gotwig <viktor.gotwig@q-loud.de>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

Contributors:
   Viktor Gotwig <viktor.gotwig@q-loud.de> - http plugable extension
*/

#ifndef HTTP_PLUGABLE_H
#define HTTP_PLUGABLE_H

#include "mosquitto_broker.h"

#define mosquitto_http_buffer_size 8196

int mosquitto_http_module_init(struct mosquitto_db *db, struct mosquitto__listener *listener);
int mosquitto_http_module_cleanup(struct mosquitto_db *db);

#if defined(LWS_LIBRARY_VERSION_NUMBER)
int http_plugable_callback(
#else
int http_plugable_callback(struct libwebsocket_context *context,
#endif
	struct lws *wsi,
	enum lws_callback_reasons reason,
	void *session,
	void *in,
	size_t len);

#endif /* HTTP_PLUGABLE_H */

