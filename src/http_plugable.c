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

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <libwebsockets.h>
#include <memory_mosq.h>
#include <mosquitto_broker_internal.h>
#include "mosquitto_http_plugin.h"
#include "libwebsockets.h"
#include "lib_load.h"
#include "http_plugable.h"

#ifdef WITH_LIBMAGIC
#	include <magic.h>
#endif

/*
 * header enumeration mapping
 */
static const int header_enum_map[] = {
	// request methods
	HTTP_GET_URI,                   WSI_TOKEN_GET_URI,
	HTTP_POST_URI,                  WSI_TOKEN_POST_URI,
	HTTP_OPTIONS_URI,               WSI_TOKEN_OPTIONS_URI,
	HTTP_PUT_URI,                   WSI_TOKEN_PUT_URI,
	HTTP_DELETE_URI,                WSI_TOKEN_DELETE_URI,
	HTTP_PATCH_URI,                 WSI_TOKEN_PATCH_URI,

	// uri arguments header
	HTTP_URI_ARGS,                  WSI_TOKEN_HTTP_URI_ARGS,

	// request headers
	HTTP_HOST,                      WSI_TOKEN_HOST,
	HTTP_USER_AGENT,                WSI_TOKEN_HTTP_USER_AGENT,
	HTTP_REFERER,                   WSI_TOKEN_HTTP_REFERER,
	HTTP_COOKIE,                    WSI_TOKEN_HTTP_COOKIE,
	HTTP_CONTENT_LENGTH,            WSI_TOKEN_HTTP_CONTENT_LENGTH,
	HTTP_CONTENT_TYPE,              WSI_TOKEN_HTTP_CONTENT_TYPE,
	HTTP_ACCEPT,                    WSI_TOKEN_HTTP_ACCEPT,
	HTTP_ACCEPT_CHARSET,            WSI_TOKEN_HTTP_ACCEPT_CHARSET,
	HTTP_ACCEPT_ENCODING,           WSI_TOKEN_HTTP_ACCEPT_ENCODING,
	HTTP_ACCEPT_LANGUAGE,           WSI_TOKEN_HTTP_ACCEPT_LANGUAGE,
	HTTP_IF_MODIFIED_SINCE,         WSI_TOKEN_HTTP_IF_MODIFIED_SINCE,
	HTTP_IF_NONE_MATCH,             WSI_TOKEN_HTTP_IF_NONE_MATCH,
	HTTP_PRAGMA,                    WSI_TOKEN_HTTP_PRAGMA,
	HTTP_CACHE_CONTROL,             WSI_TOKEN_HTTP_CACHE_CONTROL,
	HTTP_AUTHORIZATION,             WSI_TOKEN_HTTP_AUTHORIZATION,
	HTTP_DATE,                      WSI_TOKEN_HTTP_DATE,
	HTTP_EXPECT,                    WSI_TOKEN_HTTP_EXPECT,
	HTTP_RANGE,                     WSI_TOKEN_HTTP_RANGE,
	HTTP_FROM,                      WSI_TOKEN_HTTP_FROM,
	HTTP_IF_MATCH,                  WSI_TOKEN_HTTP_IF_MATCH,
	HTTP_IF_UNMODIFIED_SINCE,       WSI_TOKEN_HTTP_IF_UNMODIFIED_SINCE,
	HTTP_MAX_FORWARDS,              WSI_TOKEN_HTTP_MAX_FORWARDS,
	HTTP_TRANSFER_ENCODING,         WSI_TOKEN_HTTP_TRANSFER_ENCODING,
	HTTP_VIA,                       WSI_TOKEN_HTTP_VIA,
	HTTP_PROXY_AUTHORIZATION,       WSI_TOKEN_HTTP_PROXY_AUTHORIZATION,

	/*
	 * lws response headers, for reference only
	HTTP_ACCEPT_RANGES,             WSI_TOKEN_HTTP_ACCEPT_RANGES,
	HTTP_ACCESS_CONTROL_ALLOW_ORIGIN, WSI_TOKEN_HTTP_ACCESS_CONTROL_ALLOW_ORIGIN,
	HTTP_AGE,                       WSI_TOKEN_HTTP_AGE,
	HTTP_ALLOW,                     WSI_TOKEN_HTTP_ALLOW,
	HTTP_CONTENT_DISPOSITION,       WSI_TOKEN_HTTP_CONTENT_DISPOSITION,
	HTTP_CONTENT_ENCODING,          WSI_TOKEN_HTTP_CONTENT_ENCODING,
	HTTP_CONTENT_LANGUAGE,          WSI_TOKEN_HTTP_CONTENT_LANGUAGE,
	HTTP_CONTENT_LOCATION,          WSI_TOKEN_HTTP_CONTENT_LOCATION,
	HTTP_CONTENT_RANGE,             WSI_TOKEN_HTTP_CONTENT_RANGE,
	HTTP_ETAG,                      WSI_TOKEN_HTTP_ETAG,
	HTTP_EXPIRES,                   WSI_TOKEN_HTTP_EXPIRES,
	HTTP_LAST_MODIFIED,             WSI_TOKEN_HTTP_LAST_MODIFIED,
	HTTP_LINK,                      WSI_TOKEN_HTTP_LINK,
	HTTP_LOCATION,                  WSI_TOKEN_HTTP_LOCATION,
	HTTP_PROXY_AUTHENTICATE,        WSI_TOKEN_HTTP_PROXY_AUTHENTICATE,
	HTTP_REFRESH,                   WSI_TOKEN_HTTP_REFRESH,
	HTTP_RETRY_AFTER,               WSI_TOKEN_HTTP_RETRY_AFTER,
	HTTP_SERVER,                    WSI_TOKEN_HTTP_SERVER,
	HTTP_SET_COOKIE,                WSI_TOKEN_HTTP_SET_COOKIE,
	HTTP_STRICT_TRANSPORT_SECURITY, WSI_TOKEN_HTTP_STRICT_TRANSPORT_SECURITY,
	HTTP_VARY,                      WSI_TOKEN_HTTP_VARY,
	HTTP_WWW_AUTHENTICATE,          WSI_TOKEN_HTTP_WWW_AUTHENTICATE
	*/
};

static const int header_enum_map_len = sizeof(header_enum_map) / sizeof(header_enum_map[0]) / 2;

/*
 * method enumeration mapping
 */
static const int method_enum_map[] = {
	// request methods
	HTTP_METHOD_GET,                   WSI_TOKEN_GET_URI,
	HTTP_METHOD_POST,                  WSI_TOKEN_POST_URI,
	HTTP_METHOD_PUT,                   WSI_TOKEN_PUT_URI,
	HTTP_METHOD_DELETE,                WSI_TOKEN_DELETE_URI,
	HTTP_METHOD_OPTIONS,               WSI_TOKEN_OPTIONS_URI,
	HTTP_METHOD_PATCH,                 WSI_TOKEN_PATCH_URI,
};
static const int method_enum_map_len = sizeof(method_enum_map) / sizeof(method_enum_map[0]) / 2;

// mosquitto log level map
static const int mosquitto_log_map[] = {
	MOSQ_LOG_INFO,
	MOSQ_LOG_NOTICE,
	MOSQ_LOG_WARNING,
	MOSQ_LOG_ERR,
	MOSQ_LOG_DEBUG
};

// preallocate a number of post var items
static const int _post_vars_prealloc = 2;

// session prototype
static http_session_t mosquitto_http_session_prototype;

int log__vprintf(int priority, const char *fmt, va_list va);

static void LIB_ERROR(void) {
#ifdef WIN32
	char *buf;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING, NULL, GetLastError(), LANG_NEUTRAL, &buf, 0, NULL);
	mosquitto_log_printf(MOSQ_LOG_ERR, "Load error: %s", buf);
	LocalFree(buf);
#else
	mosquitto_log_printf(MOSQ_LOG_ERR, "Load error: %s", dlerror());
#endif
}

static int _mosquitto_publish(const char *topic, int qos, uint32_t payloadlen, const void *payload, int retain) {
	struct mosquitto_db *db = mosquitto__get_db();
	return db__messages_easy_queue(db, NULL, topic, qos, payloadlen, payload, retain);
}

/**
 * get request header
 */
static int _http_get_header(void *s, HTTP_REQUEST_HEADERS header_id, char **val) {
	http_session_t *session = s;
	if (header_id >= header_enum_map_len || header_enum_map[header_id * 2] != header_id) {
		return -1;
	}
	int wsi_id = header_enum_map[header_id * 2 + 1];
	int total = lws_hdr_total_length(session->wsi, wsi_id);

	if (total == 0) {
		return -1;
	}

	typedef struct {
		http_var_t var;
		char text[];
	} var_pack;
	var_pack *next = malloc(sizeof(var_pack) + total + 1);
	if (! next) {
		return -1;
	}
	int len = lws_hdr_copy(session->wsi, next->text, total + 1, wsi_id);

	next->var.key = NULL;
	next->var.val = next->text;
	next->var.next = session->request.headers.last;
	session->request.headers.last = &next->var;
	if (! session->request.headers.first) {
		session->request.headers.first = &next->var;
	}

	*val = next->text;

	return len;
}

/**
 * add a response header
 */
static int _http_add_header(void *s, char *key, char *val) {
	http_session_t *session = s;
	if (! key || ! val) {
		return -1;
	}
	if (strncasecmp(key, "content-length", 14) == 0) {
		errno = 0;
		session->response.content_length = strtol(val, NULL, 10);
		if (errno) {
			return -1;
		}
		return 0;
	}

	int key_len = strlen(key) + 1;
	int val_len = strlen(val) + 1;

	typedef struct {
		http_var_t var;
		char text[];
	} var_pack;
	var_pack *next = malloc(sizeof(var_pack) + key_len + val_len + 1);
	if (! next) {
		return -1;
	}

	next->var.next = NULL;
	next->var.key = next->text;
	next->var.val = next->text + key_len + 1;
	if (! session->response.headers.first) {
		session->response.headers.first = &next->var;
	}
	if (session->response.headers.last) {
		session->response.headers.last->next = &next->var;
	}
	session->response.headers.last = &next->var;
//	mosquitto_log_printf(MOSQ_LOG_DEBUG, "LINE %d: next->var.next = %p", __LINE__, next->var.next);

	memcpy(next->var.key, key, key_len);
	memcpy(next->var.val, val, val_len);
	if (! strchr(next->var.key, ':')) {
		next->var.key[key_len - 1] = ':';
		key_len++;
	}
	next->var.key[key_len - 1] = '\0';

	return 0;
}

#ifdef WITH_LIBMAGIC
	static magic_t magic_db = NULL;
	static bool magic_failed = false;
	static const char *get_content_type(char *path) {
		if (magic_db == NULL) {
			magic_db = magic_open(MAGIC_MIME_TYPE);
			if (magic_db && (magic_load(magic_db, NULL) != 0 || magic_compile(magic_db, NULL) != 0)) {
				magic_close(magic_db);
				magic_failed = true;
			}
		}
		if (magic_db && ! magic_failed) {
			const char *mime = magic_file(magic_db, path);
			if (mime) {
				return mime;
			}
		}
		return "application/octet-stream";
	}
#else
	static char *get_content_type(char *path) {
		static char* types[] = {
			".html", "text/html",
			".htm", "text/html",
			".js", "application/javascript",
			".png", "image/png",
			".jpg", "image/jpeg",
			".gif", "image/gif",
			".css", "text/css",
			".txt", "text/plain"
		};
		int i, cnt;
		int path_len = strlen(path);
		for (i = 0, cnt = sizeof(types)/sizeof(types[0]); i < cnt; i++) {
			char *match = types[i++];
			int match_len = strlen(match);
			if (strncasecmp(match, &path[path_len - match_len], match_len) == 0) {
				return types[i];
			}
		}
		return "application/octet-stream";
	}
#endif

/*
 * open a file, inside of http_dir configured directory
 */
static int _open_file(void *s, char *name) {
	http_session_t *session = s;
	int dir_len = strlen(session->config.http_dir);
	int name_len = strlen(name);
  char fname[dir_len + name_len + 2];
  memcpy(fname, session->config.http_dir, dir_len);
	fname[dir_len++] = '/';
  memcpy(fname + dir_len, name, name_len + 1);
  char *fpath = realpath(fname, NULL);
  if (fpath == NULL) {
    return -1;
  }
  if (strncmp(fpath, fname, dir_len) == 0) {
		session->response.file.fh = open(fpath, O_RDONLY);
		if (session->response.file.fh > 0) {
			session->response.file.realpath = fpath;
			session->response.file.mimetype = get_content_type(fpath);
			return 0;
		}
	}
	free(fpath);
	return -1;
}

static char * _compile_file_headers(http_session_t *session, int *len) {
	const int buf_len = 8192;
	unsigned char *buffer = malloc(buf_len);
	if (! buffer) {
		return NULL;
	}
	unsigned char *p = buffer;
	unsigned char *end = p + buf_len;

	http_var_t * entry = session->response.headers.first;
	while (entry) {
		if (lws_add_http_header_by_name(session->wsi, entry->key, entry->val, strlen(entry->val), &p, end) != 0) {
			free(buffer);
			return NULL;
		}
		entry = entry->next;
	}
	*len = p - buffer;

	return buffer;
}

static int send_headers(http_session_t *session) {

	const int buf_len = 8192 + LWS_PRE;
	unsigned char *buffer = malloc(buf_len);
	if (! buffer) {
		return -1;
	}
	unsigned char *p = buffer + LWS_PRE;
	unsigned char *end = p + buf_len - LWS_PRE;

	if (lws_add_http_header_status(session->wsi, session->response.code, &p, end)) {
		goto _failed_send_headers;
	}
	if (lws_add_http_header_content_length(session->wsi, session->response.content_length, &p, end) != 0) {
		goto _failed_send_headers;
	}

	http_var_t * entry = session->response.headers.first;
	while (entry) {
		if (lws_add_http_header_by_name(session->wsi, entry->key, entry->val, strlen(entry->val), &p, end) != 0) {
			goto _failed_send_headers;
		}
		entry = entry->next;
	}

	if (lws_finalize_http_header(session->wsi, &p, end)){
		goto _failed_send_headers;
	}

	*p = '\0';
	if (lws_write(session->wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0
	) {
		goto _failed_send_headers;
	}
	free(buffer);
	return 0;

_failed_send_headers:
	free(buffer);
	return -1;
}

static void _http_logger(HTTP_LOG_LEVELS level, const char *fmt, ...) {
	if (level >= sizeof(mosquitto_log_map)/sizeof(mosquitto_log_map[0])) {
		level = 0;
	}

	va_list va;

	va_start(va, fmt);
	log__vprintf(mosquitto_log_map[level], fmt, va);
	va_end(va);
}

int mosquitto_http_module_init(struct mosquitto_db *db, struct mosquitto__listener *listener) {

	int i = 0;

	struct {void **var; char *name;} func_list[] = {
		{&db->http_plugin.plugin_version, "mosquitto_http_plugin_version"},
		{&db->http_plugin.plugin_init, "mosquitto_http_plugin_init"},
		{&db->http_plugin.plugin_cleanup, "mosquitto_http_plugin_cleanup"},
		{&db->http_plugin.plugin_accept, "mosquitto_http_plugin_accept"},
		{&db->http_plugin.plugin_add_req_body_chunk, "mosquitto_http_plugin_add_req_body_chunk"},
		{&db->http_plugin.plugin_process_request, "mosquitto_http_plugin_process_request"},
		{&db->http_plugin.plugin_get_response_chunk, "mosquitto_http_plugin_get_response_chunk"},
		{&db->http_plugin.plugin_connection_cleanup, "mosquitto_http_plugin_connection_cleanup"},
		{NULL}
	};
	void *lib;
	int version;

	db->http_plugin.lib = NULL;

	if(! db->config->http_plugin){
		memset(&db->http_plugin, 0, sizeof(http_plugin_t));
		return MOSQ_ERR_NOT_FOUND;
	}
	// load the plugin
	lib = LIB_LOAD(db->config->http_plugin);
	if(!lib){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Unable to load http plugin \"%s\".", db->config->http_plugin);
		LIB_ERROR();
		return MOSQ_ERR_NOT_FOUND;
	}
	// load listed functions
	for (i = 0; func_list[i].var != NULL; i++) {
		if(!(*(func_list[i].var) = LIB_SYM(lib, func_list[i].name))){
			mosquitto_log_printf(MOSQ_LOG_ERR,
			"Error: Unable to load http plugin %s().", func_list[i].name);
			LIB_ERROR();
			LIB_CLOSE(lib);
			return MOSQ_ERR_NOMEM;
		}
	}

	version = ((mosquitto_http_plugin_version_f)db->http_plugin.plugin_version)();
	if(version != MOSQ_HTTP_PLUGIN_VERSION){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Incorrect http plugin version (got %d, expected %d).",
			version, MOSQ_HTTP_PLUGIN_VERSION
		);
		return MOSQ_ERR_NOMEM;
	}

	// set the session defaults
	memset(&mosquitto_http_session_prototype, 0, sizeof(mosquitto_http_session_prototype));
	mosquitto_http_session_prototype.response.code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
	mosquitto_http_session_prototype.response.body = NULL;
	mosquitto_http_session_prototype.log = _http_logger;
	mosquitto_http_session_prototype.add_response_header = _http_add_header;
	mosquitto_http_session_prototype.get_request_header = _http_get_header;
	mosquitto_http_session_prototype.mqtt_publish = _mosquitto_publish;
	mosquitto_http_session_prototype.open_file = _open_file;

	// add config setting
	mosquitto_http_session_prototype.config.port = listener->port;
	mosquitto_http_session_prototype.config.host = listener->host;

	char *http_dir = NULL;
	if(listener->http_dir){
#ifdef WIN32
		http_dir = _fullpath(NULL, listener->http_dir, 0);
#else
		http_dir = realpath(listener->http_dir, NULL);
#endif
		if (! http_dir) {
			mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Unable to open http dir \"%s\".", listener->http_dir);
			return MOSQ_ERR_NOT_FOUND;
		}
	}

	mosquitto_http_session_prototype.config.http_dir = http_dir;

	if(((mosquitto_http_plugin_init_f)db->http_plugin.plugin_init)() != 0){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: HTTP plugin failed when initialising.");
		return MOSQ_ERR_NOMEM;
	}

	db->http_plugin.lib = lib;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_http_module_cleanup(struct mosquitto_db *db)
{
	if (db->http_plugin.lib == NULL) {
		return MOSQ_ERR_SUCCESS;
	}

	((mosquitto_http_plugin_cleanup_f)db->http_plugin.plugin_cleanup)();

	LIB_CLOSE(db->http_plugin.lib);
	db->http_plugin.lib = NULL;
	return MOSQ_ERR_SUCCESS;
}

/**
 * parse query string
 */
static int _parse_query_string(http_session_t *session) {
	int total = lws_hdr_total_length(session->wsi, WSI_TOKEN_HTTP_URI_ARGS);
	if (total == 0) {
		return 0;
	}

	int frag_id = 0;
	int var_count = 0;
	int sum = 0;
	do {
		int f_len = lws_hdr_fragment_length(session->wsi, WSI_TOKEN_HTTP_URI_ARGS, frag_id++);
		if (f_len == 0) {
			continue;
		}
		sum += f_len;
		var_count++;
	} while (sum < total);

// allocate the list space at once
	int list_len = sizeof(http_var_t) * (var_count + 1);
	http_var_t *list = malloc(list_len);
	if (! list) {
		return -1;
	}

	int data_len = total + var_count;
	char *data = malloc(data_len);
	if (! data) {
		free(list);
		return -1;
	}

	int var_id;
	for (var_id = 0, frag_id = 0; data_len > 0 && var_id < var_count; frag_id++) {
		int f_len = lws_hdr_copy_fragment(session->wsi, data, data_len, WSI_TOKEN_HTTP_URI_ARGS, frag_id);
		if (f_len == -1) {
			goto _abort;
		}
		if (f_len == 0) {
			continue;
		}
		http_var_t *current = &list[var_id];
		if (var_id > 0) {
			list[var_id - 1].next = current;
		}
		current->next = NULL;
		data[f_len] = '\0';
		current->key = data;
		char *val = strchr(data, '=');
		if (val == NULL) {
			current->val = NULL;
			break;
		}
		*val = '\0';
		current->val = val + 1;
		data += f_len + 1;
		data_len -= f_len + 1;
		var_id++;
	}
	session->request.get_query_var = list;
	return 0;

_abort:
	free(list);
	free(data);
	return -1;
}

/**
 * a media type decoder according rfc1866, section 8.2.1
 */
static int _x_form_url_decode(char *str, size_t len) {
	static const char t[256] = {
	//0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  a,  b,  c,  d,  e,  f,
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,//0
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,//1
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,//2
		0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  0,  0,  0,  0,  0,  0,//3
		0,  0xa,0xb,0xc,0xd,0xe,0xf,0,  0,  0,  0,  0,  0,  0,  0,  0,//4
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,//5
		0,  0xa,0xb,0xc,0xd,0xe,0xf,0,  0,  0,  0,  0,  0,  0,  0,  0,//6
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,//7
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,//8
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,//9
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,//a
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,//b
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,//c
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,//d
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,//e
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,//f
	};

	int i = 0;
	int p;
	for (p = 0; i < len; i++, p++) {
		switch (str[i]) {
			case '%':
				str[p] = (t[str[i + 1]] << 4) | t[str[i + 2]];
				i += 2;
				break;
			case '+':
				str[p] = ' ';
				break;
			default:
				str[p] = str[i];
		}
	}
	str[p] = '\0';
	return p;
}

static int _parse_form_urlencoded(http_session_t *session) {
	http_var_t *current = session->request.post_query_var;
	if (! current) {
		return 0;
	}

	char *data = current->key;
	if (! data) {
		return 0;
	}
	int var_count;
	for (var_count = 1; data = strchr(data, '&'); var_count++) {
		data++;
	}
	data = current->key;
	if (var_count > _post_vars_prealloc) {
		http_var_t *new_list = realloc(current, sizeof(http_var_t) * var_count);
		if (! new_list) {
			return -1;
		}
		session->request.post_query_var = new_list;
		current = new_list;
	}

	char *val = NULL;
	int len;
	do {
		current->next = NULL;
		current->key = data;
		val = strchr(data, '=');
		if (val == NULL) {
			break;
		}
		*val = '\0';
		current->val = ++val;
		data = val;
		val = strchr(val, '&');
		if (val == NULL) {
			len = strlen(data);
		} else {
			len = val - data;
		}
		if (len > 0) {
			_x_form_url_decode(current->val, len);
		}
		data += len + 1;

		if (val == NULL) {
			break;
		}

		current->next = current + 1;
		current++;
	} while (true);
  return 0;
}

#if defined(LWS_LIBRARY_VERSION_NUMBER)
int http_plugable_callback(
#else
int http_plugable_callback(struct libwebsocket_context *context,
#endif
	struct lws *wsi,
	enum lws_callback_reasons reason,
	void *s,
	void *in,
	size_t len)
{
	struct mosquitto_db *db = mosquitto__get_db();
	if (db->http_plugin.lib == NULL) {
		return -1;
	}
	http_session_t *session = s;

	switch (reason) {
		// when the request has been received, to check and eventually reject the connection
		case LWS_CALLBACK_FILTER_HTTP_CONNECTION: {
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "LWS_CALLBACK_FILTER_HTTP_CONNECTION");
			if (! session || ! in) {
				goto try_to_reuse;
			}
      memcpy(session, &mosquitto_http_session_prototype, sizeof(http_session_t));
      session->wsi = wsi;
      session->request.path = strdup(in);
			if (! session->request.path) {
				return -1;
			}
      int found = 0;
      int n;
      for (n = 0; n < method_enum_map_len * 2; n += 2) {
        if (lws_hdr_total_length(wsi, method_enum_map[n + 1])) {
          session->request.method = method_enum_map[n];
          found = 1;
          break;
        }
      }
      if (! found) {
        lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, NULL);
        goto try_to_reuse;
      }

			char *ct = NULL;
			int ct_len = _http_get_header(session, HTTP_CONTENT_TYPE, &ct);
			if (ct_len > 0) {
				session->request.content_type = ct;
				char *s = "multipart/form-data";
				if (strncmp(ct, s, strlen(s)) == 0) {
					session->request.is_form_multipart = 1;
				} else {
					s = "application/x-www-form-urlencoded";
					if (strncmp(ct, s, strlen(s)) == 0) {
						session->request.is_form_urlencoded = 1;
					}
				}
			}
			ct_len = _http_get_header(session, HTTP_CONTENT_LENGTH, &ct);
			if (ct_len > 0) {
				session->request.content_length = strtol(ct, NULL, 10);
			}

      if (_parse_query_string(session) != 0) {
				goto internal_server_error;
      }

      if (((mosquitto_http_plugin_accept_f)db->http_plugin.plugin_accept)(session) != 0) {
        lws_return_http_status(wsi, session->response.code, session->response.body);
        goto try_to_reuse;
      }
    }
    return 0;

    // request body chunk
    case LWS_CALLBACK_HTTP_BODY:
      if (! session) {
        return -1;
      }
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "LWS_CALLBACK_HTTP_BODY");
      if (session->request.is_form_urlencoded) {
				if (! session->request.post_query_var) {
					session->request.post_query_var = calloc(_post_vars_prealloc, sizeof(http_var_t));
					if (! session->request.post_query_var) {
						goto internal_server_error;
					}
				}
				if (session->request.post_query_var->key) {
					int prev_len = strlen(session->request.post_query_var->key);
					char *new_text = realloc(session->request.post_query_var->key, prev_len + len);
					if (! new_text) {
						goto internal_server_error;
					}
					memcpy(new_text + prev_len, in, len);
					new_text[prev_len + len] = '\0';
					session->request.post_query_var->key = new_text;
				} else {
					session->request.post_query_var->key = strdup(in);
					if (! session->request.post_query_var->key) {
						goto internal_server_error;
					}
				}
      } else if (((mosquitto_http_plugin_add_req_body_chunk_f)db->http_plugin.plugin_add_req_body_chunk)(session, in, len) != 0) {
        lws_return_http_status(wsi, session->response.code, session->response.body);
        goto try_to_reuse;
      }
      break;

    // request body complete
    case LWS_CALLBACK_HTTP_BODY_COMPLETION:
      if (! session) {
        goto try_to_reuse;
      }
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "LWS_CALLBACK_HTTP_BODY_COMPLETION");
      if (session->request.method == HTTP_METHOD_POST && session->request.is_form_urlencoded) {
        if (_parse_form_urlencoded(session) != 0) {
					goto internal_server_error;
        }
      }
//			break;

    // http request complete
    case LWS_CALLBACK_HTTP:
		{
      if (! session) {
        goto try_to_reuse;
      }
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "LWS_CALLBACK_HTTP");
			if (reason == LWS_CALLBACK_HTTP
				&& (session->request.method == HTTP_METHOD_POST || session->request.method == HTTP_METHOD_PUT)
				&& session->request.content_length > 0
			){
				// skip and wait for the LWS_CALLBACK_HTTP_BODY call
				break;
			}

			if (((mosquitto_http_plugin_process_request_f)db->http_plugin.plugin_process_request)(session) != 0) {
				lws_return_http_status(wsi, session->response.code, session->response.body);
				goto try_to_reuse;
			}

			if (session->response.file.fh > 0) {
				int fhdr_len = 0;
				char *file_headers = _compile_file_headers(session, &fhdr_len);
				if (file_headers == NULL) {
					goto internal_server_error;
				}
				int res = lws_serve_http_file(wsi, session->response.file.realpath, session->response.file.mimetype, file_headers, fhdr_len);
				free(file_headers);
				if (res < 0 || ((res > 0) && lws_http_transaction_completed(wsi))) {
					return -1; /* error or can't reuse connection: close the socket */
				}
				return 0;
			}

      if (send_headers(session)) {
        goto internal_server_error;
      }

			lws_callback_on_writable(wsi);
		}
			break;

//////////////////

    // ready to send response
		case LWS_CALLBACK_HTTP_WRITEABLE: {
      if (! session) {
        return -1;
      }
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "LWS_CALLBACK_HTTP_WRITEABLE");
			char *buffer = malloc(mosquitto_http_buffer_size + LWS_PRE);
			if (! buffer) {
				return -1;
			}

      if (session->response.body) {
				int len = strlen(session->response.body);
				if (len > 0) {
					int sent = 0;
					do {
						int chunk_len = len > mosquitto_http_buffer_size ? mosquitto_http_buffer_size : len;
						memcpy(buffer + LWS_PRE, session->response.body + sent, chunk_len);
						int res = lws_write(session->wsi, buffer + LWS_PRE, chunk_len, LWS_WRITE_HTTP);
						if (res == -1) {
							free(buffer);
							return -1;
						}
						if (res == 0) {
							break;
						}
						sent += res;
						len -= res;
					} while (!lws_send_pipe_choked(wsi) && len > 0);
					if (len > 0) {
						memmove(session->response.body, session->response.body + sent, len + 1);
					}
					lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT, 5);
					session->response.offset += sent;
					lws_callback_on_writable(wsi);
					free(buffer);
					return 0;
				}
      }

			while (session->response.offset < session->response.content_length) {
				long int len = session->response.offset;
				if (((mosquitto_http_plugin_get_response_chunk_f)db->http_plugin.plugin_get_response_chunk)(
					session,
					&session->response.offset,
					buffer + LWS_PRE,
					mosquitto_http_buffer_size
				)) {
					// !!!some error occured in the last stage
					free(buffer);
					goto try_to_reuse;
				}
				len = session->response.offset - len;
				if (len == 0) {
					break;
				}
				int res = lws_write(session->wsi, buffer + LWS_PRE, len, LWS_WRITE_HTTP);
				if (res == -1) {
					free(buffer);
					return -1;
				}
				if (res == 0) {
					break;
				}
				session->response.offset -= len - res;
				if (lws_send_pipe_choked(wsi)) {
					lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT, 5);
					break;
				}
			}
			lws_callback_on_writable(wsi);
			free(buffer);
		}
			break;

	case LWS_CALLBACK_HTTP_FILE_COMPLETION:
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "LWS_CALLBACK_HTTP_FILE_COMPLETION");
		goto try_to_reuse;

    // session ends
//		case LWS_CALLBACK_CLOSED:
//		case LWS_CALLBACK_CLOSED_HTTP:
//      return 0;

    // mosquitto polling loop stuff
		case LWS_CALLBACK_ADD_POLL_FD:
		case LWS_CALLBACK_DEL_POLL_FD:
		case LWS_CALLBACK_CHANGE_MODE_POLL_FD:{
      struct mosquitto *mosq;
      struct lws_pollargs *pollargs = (struct lws_pollargs *)in;
			HASH_FIND(hh_sock, db->contexts_by_sock, &pollargs->fd, sizeof(pollargs->fd), mosq);
			if(mosq && (pollargs->events & POLLOUT)){
				mosq->ws_want_write = true;
			}
    }
			break;

    case LWS_CALLBACK_WSI_DESTROY:
      if (! session) {
        return -1;
      }
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "LWS_CALLBACK_WSI_DESTROY");
      ((mosquitto_http_plugin_connection_cleanup_f)db->http_plugin.plugin_connection_cleanup)(session);

			if (session->response.file.fh > 0) {
				close(session->response.file.fh);
			}
			if (session->response.file.realpath) {
				free(session->response.file.realpath);
			}
      if (session->request.get_query_var != NULL) {
        free(session->request.get_query_var->key);
        free(session->request.get_query_var);
      }
      if (session->request.post_query_var != NULL) {
        free(session->request.post_query_var->key);
        free(session->request.post_query_var);
      }
      if (session->request.headers.first != NULL) {
				http_var_t *entry = session->request.headers.first;
				while (entry) {
					http_var_t *next = entry->next;
					free(entry);
					entry = next;
				}
      }
      break;
		default:
			return 0;

  }
  return 0;

try_to_reuse:
	if (lws_http_transaction_completed(wsi)){
		return -1;
  }
	return 0;

internal_server_error:
	lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
	return -1;
}
