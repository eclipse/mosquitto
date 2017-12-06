/*
Copyright (c) 2012-2014 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

Contributors:
   Roger Light - initial implementation and documentation of the authentication plugin.
   Viktor Gotwig <viktor.gotwig@q-loud.de> - http plugin extension
*/

#ifndef MOSQUITTO_HTTP_PLUGIN_H
#define MOSQUITTO_HTTP_PLUGIN_H

#include <stdint.h>

#define MOSQ_HTTP_PLUGIN_VERSION 1

/* =========================================================================
 *
 * Type Definitions
 *
 * ========================================================================= */

/*
 * http methods
 */
typedef enum {
  HTTP_METHOD_GET,
  HTTP_METHOD_POST,
  HTTP_METHOD_PUT,
  HTTP_METHOD_DELETE,
  HTTP_METHOD_OPTIONS,
  HTTP_METHOD_PATCH
} HTTP_METHODS;

/*
 * request header enumeration, similar to libwebsockets definitions
 */
typedef enum {
	HTTP_GET_URI,
	HTTP_POST_URI,
	HTTP_OPTIONS_URI,
	HTTP_PUT_URI,
	HTTP_DELETE_URI,
	HTTP_PATCH_URI,
  HTTP_URI_ARGS,

	HTTP_HOST,
	HTTP_USER_AGENT,
	HTTP_REFERER,
	HTTP_COOKIE,
	HTTP_CONTENT_LENGTH,
	HTTP_CONTENT_TYPE,
	HTTP_ACCEPT,
	HTTP_ACCEPT_CHARSET,
	HTTP_ACCEPT_ENCODING,
	HTTP_ACCEPT_LANGUAGE,
	HTTP_IF_MODIFIED_SINCE,
	HTTP_IF_NONE_MATCH,
	HTTP_PRAGMA,
	HTTP_CACHE_CONTROL,
	HTTP_AUTHORIZATION,
	HTTP_DATE,
	HTTP_EXPECT,
	HTTP_RANGE,
	HTTP_FROM,
	HTTP_IF_MATCH,
	HTTP_IF_UNMODIFIED_SINCE,
	HTTP_MAX_FORWARDS,
	HTTP_TRANSFER_ENCODING,
	HTTP_VIA,
	HTTP_PROXY_AUTHORIZATION,
} HTTP_REQUEST_HEADERS;

/*
 * log levels
 */
typedef enum {
  HTTP_LOG_INFO,
  HTTP_LOG_NOTICE,
  HTTP_LOG_WARNING,
  HTTP_LOG_ERR,
  HTTP_LOG_DEBUG
} HTTP_LOG_LEVELS;

/* =========================================================================
 *
 * Server API
 *
 * These methods can be used from the plugin to access the server functionality
 *
 * ========================================================================= */

/*
 * Logger method
 *
 * Write a log message using the broker configured logging.
 *
 * Parameters:
 * 	level -    Log message priority. Can currently be one of:
 *
 *             HTTP_LOG_INFO
 *             HTTP_LOG_NOTICE
 *             HTTP_LOG_WARNING
 *             HTTP_LOG_ERR
 *             HTTP_LOG_DEBUG
 *
 *	fmt, ... - printf style format and arguments.
 */
typedef void (*mosquitto_http_logger)(HTTP_LOG_LEVELS level, const char *fmt, ...);

/**
 * Method to get a request header
 *
 * Parameters:
 *
 *  session		: pointer to the session object
 *  header_id	: enumerated header id
 *  val				: value var ptr
 *
 * Return value: header length, -1 if not found or error
 */
typedef int (*mosquitto_http_get_header)(void *session, HTTP_REQUEST_HEADERS header_id, char **val);

/**
 * Method to add response header
 *
 * Parameters:
 *
 *  session	: pointer to the session object
 *  key			: header key
 *  val			: header value
 *
 * Return value: 0 on success, !=0 on error
 */
typedef int (*mosquitto_http_add_header)(void *session, char *key, char *val);

/**
 * Method to publish messages
 *
 * Parameters:
 *
 *  topic				: message topic
 *  qos					: qos value
 *  payloadlen	: payload length
 *  payload			: the payload
 *  retain			: retain flag
 *
 * Return value: 0 on success, !=0 on error
 */
typedef int (*mosquitto_http_publish)(const char *topic, int qos, uint32_t payloadlen, const void *payload, int retain);

/**
 * Method to open a file, relative to the http_dir directory
 *
 * Parameters:
 *
 *  session	: pointer to the session object
 *  name		: relative file name
 *
 * Return value: 0 on success, !=0 on error
 * Side effect: on success the session->response.file struct will be filled with appropriate values
 */
typedef int (*mosquitto_http_open_file)(void *session, char *name);

/* =========================================================================
 *
 * HTTP Session
 *
 * ========================================================================= */

/*
 * a variable list entry
 */
typedef struct http_var_s {
  char * key;
  char * val;
	struct http_var_s *next;
} http_var_t;

/*
 * headers container
 */
typedef struct {
	http_var_t *first;
	http_var_t *last;
} http_headers_t;

/*
 * http request
 */
typedef struct {
  HTTP_METHODS method;
  char *path;
  http_var_t *get_query_var;
  http_var_t *post_query_var;
  char *content_type;
	long int content_length;
  int is_form_urlencoded;
  int is_form_multipart;
	http_headers_t headers;
} http_request_t;

/*
 * http response
 */
typedef struct {
	// response status code
	int code;
	// content length
	long int content_length;
	// content offset
	long int offset;
	// response headers list, filled by the session->add_response_header api call
	http_headers_t headers;
	// body text
	char *body;
	// file to serve out
	struct {
		char *realpath;
		const char *mimetype;
		int fh;
	} file;
} http_response_t;

/*
 * http session
 */
typedef struct {
  /*
	 * free defined data ptr for plugins own session data
	 */
  void *var;

  /*
	 * config options
	 */
  struct {
    const char *host;
    uint16_t port;
    const char *http_dir;
  } config;

  /*
	 * request data, provided by the server
	 */
  http_request_t request;

  /*
	 * response data, must be set by the plugin
	 */
  http_response_t response;

	/*
	 * libwebsockets context
	 */
	struct libwebsocket *wsi;

	/*
	 * server API methods
	 */

  // logger
  mosquitto_http_logger log;
  // get request header
  mosquitto_http_get_header get_request_header;
  // add response header
  mosquitto_http_add_header add_response_header;
  // publish a message
  mosquitto_http_publish mqtt_publish;
  // open file
  mosquitto_http_open_file open_file;

} http_session_t;

/*
 * HTTP var list lookup macro
 *
 * Parameters:
 *
 *	list	: list entry ptr; will be set to the found var or to NULL otherwise
 *	key		: the key to search for
 */
#define HTTP_VAR_LOOKUP(list, key) while (list && (! list->key || strcmp(list->key, key) != 0)) {list = list->next;}

/* =========================================================================
 *
 * Plugin Functions
 *
 * To create the plugin you must implement the functions listed below.
 * The resulting code should then be compiled as a shared library. Using
 * gcc this can be achieved as follows:
 *
 * gcc -I<path to mosquitto_http_plugin.h> -fPIC -shared plugin.c -o plugin.so
 *
 * On Mac OS X:
 *
 * gcc -I<path to mosquitto_http_plugin.h> -fPIC -shared plugin.c -undefined dynamic_lookup -o plugin.so
 *
 *
 * ========================================================================= */

/*
 * Function: mosquitto_http_plugin_version
 *
 * The broker will call this function immediately after loading the plugin to
 * check it is a supported plugin version. Your code must simply return
 * MOSQ_HTTP_PLUGIN_VERSION.
 */
int mosquitto_http_plugin_version(void);
typedef int (*mosquitto_http_plugin_version_f)(void);

/*
 * Function: mosquitto_http_plugin_init
 *
 * Called after the plugin has been loaded and <mosquitto_http_plugin_version>
 * has been called. This will only ever be called once and can be used to
 * initialise the plugin.
 *
 * Return value:
 *	Return 0 on success
 *	Return >0 on failure.
 */
int mosquitto_http_plugin_init();
typedef int (*mosquitto_http_plugin_init_f)();

/*
 * Function: mosquitto_http_plugin_cleanup
 *
 * Called when the broker is shutting down. This will only ever be called once.
 *
 */
void mosquitto_http_plugin_cleanup();
typedef void (*mosquitto_http_plugin_cleanup_f)();

/*
 * Function: mosquitto_http_plugin_accept
 *
 * Called on http request event LWS_CALLBACK_FILTER_HTTP_CONNECTION to validate the request
 *
 * Parameters:
 *
 *  session : the session object
 *
 * Return value: 0 on accept, !=0 on decline
 * The session.response.code should be set to an appropriate HTTP STATUS value, otherwise code 500 will be returned
 */
int mosquitto_http_plugin_accept(http_session_t *session);
typedef int (*mosquitto_http_plugin_accept_f)(http_session_t *session);

/*
 * Function: mosquitto_http_plugin_add_req_body_chunk
 *
 * Called on POST and PUT requests to process the request body submitted chunkwise, e.g for a file upload
 *
 * Parameters:
 *
 *  session	: the session object
 *  data		: chunk data
 *  len			: chunk length
 *
 * Return value: 0 on accept, !=0 on decline or error
 */
int mosquitto_http_plugin_add_req_body_chunk(http_session_t *session, char *data, size_t len);
typedef int (*mosquitto_http_plugin_add_req_body_chunk_f)(http_session_t *session, char *data, size_t len);

/*
 * Function: mosquitto_http_plugin_process
 *
 * Called on http request event LWS_CALLBACK_HTTP to process the request
 * The call occurs after the successfull <mosquitto_http_plugin_accept> response,
 * for POST and PUT after receiving the request body
 *
 * Parameters:
 *
 *  session : the session object
 *
 * Return value: 0 on accept, !=0 on decline or error
 * The session.response.code should be set to an appropriate HTTP STATUS value, otherwise code 500 used by default
 */
int mosquitto_http_plugin_process_request(http_session_t *session);
typedef int (*mosquitto_http_plugin_process_request_f)(http_session_t *session);

/*
 * Function: mosquitto_http_plugin_get_response_chunk
 *
 * Called on http request after <mosquitto_http_plugin_process> to get the next response chunk
 * The method will be called repeatedly until total response data length (incl. the response.body) equals the content_size value
 *
 * Parameters:
 *
 *	session : the session object
 *	offset	: content offset ptr
 *	buf_ptr	: result buffer ptr
 *	buf_len	: result buffer length
 *
 * Return value: 0 on accept, !=0 on abort or error
 */
int mosquitto_http_plugin_get_response_chunk(http_session_t *session, long int *offset, char *buf_ptr, int buf_len);
typedef int (*mosquitto_http_plugin_get_response_chunk_f)(http_session_t *session, long int *offset, char *buf_ptr, int buf_len);

/*
 * Function: mosquitto_http_plugin_connection_cleanup
 *
 * Called at session data cleanup
 *
 * Parameters:
 *
 *	session : the session object
 *
 */
void mosquitto_http_plugin_connection_cleanup(http_session_t *session);
typedef void (*mosquitto_http_plugin_connection_cleanup_f)(http_session_t *session);

#endif
