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
   Viktor Gotwig <viktor.gotwig@q-loud.de> - example implementation for a http plugin
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "../../../src/mosquitto_http_plugin.h"

/*
 * response buffer, should be large enough for the public_html/large.txt file
 */
#define buff_size 100000
static char buff[buff_size];

/*
 * exdended session data
 */
typedef struct {
	int fh;
} session_data_t;

/**
 * API, required: get the plugin version
 *
 * @return
 */
int mosquitto_http_plugin_version() {
  return MOSQ_HTTP_PLUGIN_VERSION;
}

/**
 * API, required: initialize the plugin
 *
 * @return
 */
int mosquitto_http_plugin_init() {
  return 0;
}

/*
 * helper: get the file size
 */
static long int _get_file_size(int fh) {
  struct stat s;
  if (fstat(fh, &s) == -1) {
    return -1;
  }
  return s.st_size;
}

/*
 * helper: read a file by handle, return resulting length or -1 on failure
 */
static int _read_file(int fh, char *buf, int len) {
  int offset = 0;
  do {
    int res = read(fh, buf + offset, len - offset);
    if (res <= 0) {
      break;
    }
    offset += res;
  } while (offset < len);
  buf[offset] = '\0';
  return len;
}

/**
 * API, required: plugin cleanuip
 */
void mosquitto_http_plugin_cleanup() {
}

/**
 * API, required: check to accept a http request
 *
 * @param session
 * @return
 */
int mosquitto_http_plugin_accept(http_session_t *session) {
	session_data_t *data = calloc(1, sizeof(session_data_t));
	if (! data) {
		return -1;
	}
	session->var = data;

	session->response.code = 404;
	if (strcmp(session->request.path, "/string") == 0) {
		session->response.code = 200;
		session->response.body = "TEST";
		session->response.content_length = strlen(session->response.body);
		return 0;
	}
	if (strcmp(session->request.path, "/get_vars") == 0) {
		session->response.code = 200;
		return 0;
	}
	if (strcmp(session->request.path, "/large.txt") == 0) {
		int fh = 0;
		if (session->open_file(session, "/large.txt") == 0) {
			fh = session->response.file.fh;
		}
		if (fh > 0) {
			((session_data_t *)session->var)->fh = fh;
			session->response.content_length = _get_file_size(fh);
			session->add_response_header(session, "content-type", (char *)session->response.file.mimetype);
			session->response.file.fh = -1;
			session->response.code = 200;
			return 0;
		}
		return -1;
	}
	if (session->open_file(session, session->request.path) == 0) {
		session->add_response_header(session, "x-test1", "111");
		session->add_response_header(session, "x-test2:", "222");
		session->add_response_header(session, "x-test3", "333");
		session->add_response_header(session, "x-test4:", "444");
		session->add_response_header(session, "x-test5", "555");
		session->response.code = 200;
		return 0;
	}
	return -1;
}

/**
 * API, required: process a request body chunk
 *
 * @param session
 * @param data
 * @param len
 * @return
 */
int mosquitto_http_plugin_add_req_body_chunk(http_session_t *session, char *data, size_t len) {
	if (len >= buff_size) {
		len = buff_size - 1;
	}
	memcpy(buff, data, len);
	buff[len] = '\0';
	session->response.body = buff;
	session->response.content_length = strlen(session->response.body);
  return 0;
}

/**
 * API, required: process the request
 * @param session
 * @return
 */
int mosquitto_http_plugin_process_request(http_session_t *session) {
	if (session->response.body != NULL || ((session_data_t *)session->var)->fh > 0) {
		return 0;
	}
	buff[0] = '\0';
	session->response.body = buff;
	char *body = buff;
	http_var_t *var = session->request.get_query_var;
	while(var) {
		int len = sprintf(body, "%s:%s,", var->key, var->val);
		body += len;
		var = var->next;
	}
	var = session->request.post_query_var;
	while(var) {
		int len = sprintf(body, "%s:%s,", var->key, var->val);
		body += len;
		var = var->next;
	}
	session->response.code = 200;
	session->response.content_length = strlen(session->response.body);
  return 0;
}

/**
 * API, required: return a response body chunk
 *
 * @param session
 * @param offset
 * @param buf_ptr
 * @param buf_len
 * @return
 */
int mosquitto_http_plugin_get_response_chunk(http_session_t *session, long int *offset, char *buf_ptr, int buf_len) {
	int fh = ((session_data_t *)session->var)->fh;
	if (fh <= 0) {
		return 0;
	}
	if (lseek(fh, *offset, SEEK_SET) == -1) {
		session->response.code = 400;
		return -1;
	}
	int len = session->response.content_length - *offset;
	if (len == 0) {
		return -1;
	}
	if (len > buf_len) {
		len = buf_len;
	}
	len = _read_file(fh, buf_ptr, len);
	*offset += len;
  return 0;
}

/**
 * API, required: connection cleanup
 *
 * @param session
 */
void mosquitto_http_plugin_connection_cleanup(http_session_t *session) {
	int fh = ((session_data_t *)session->var)->fh;
	if (fh) {
		close(fh);
	}
	free(session->var);
}