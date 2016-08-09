/*
Copyright (c) 2014 Roger Light <roger@atchoo.org>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the name of mosquitto nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

#ifdef WITH_WEBSOCKETS

#include <libwebsockets.h>
#include "mosquitto_internal.h"
#include "mosquitto_broker.h"
#include "mqtt3_protocol.h"
#include "memory_mosq.h"

#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>

#ifdef WITH_SYS_TREE
extern uint64_t g_bytes_received;
extern uint64_t g_bytes_sent;
extern unsigned long g_msgs_received;
extern unsigned long g_msgs_sent;
extern unsigned long g_pub_msgs_received;
extern unsigned long g_pub_msgs_sent;
#endif
extern struct mosquitto_db int_db;

#if defined(LWS_LIBRARY_VERSION_NUMBER)
static int callback_mqtt(
#else
static int callback_mqtt(struct libwebsocket_context *context,
#endif
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
		void *user,
		void *in,
		size_t len);

#if defined(LWS_LIBRARY_VERSION_NUMBER)
static int callback_http(
#else
static int callback_http(struct libwebsocket_context *context,
#endif
	struct libwebsocket *wsi,
	enum libwebsocket_callback_reasons reason,
	void *user,
	void *in,
	size_t len);

enum mosq_ws_protocols {
	PROTOCOL_HTTP = 0,
	PROTOCOL_MQTT,
	DEMO_PROTOCOL_COUNT
};

struct libws_http_data {
	FILE *fptr;
};

#ifndef LWS_FEATURE_SERVE_HTTP_FILE_HAS_OTHER_HEADERS_ARG
	/* This is libwebsockets 1.2.x or earlier, we have to degrade our capabilities.
	 * Once lws 1.3 is widely available this should be removed. */
#	define LWS_IS_OLD
#	define HTTP_STATUS_FORBIDDEN 403
#	define HTTP_STATUS_NOT_FOUND 404
#	define HTTP_STATUS_METHOD_NOT_ALLOWED 405
#	define HTTP_STATUS_REQ_URI_TOO_LONG 414
#	define HTTP_STATUS_INTERNAL_SERVER_ERROR 500
#	define libwebsockets_return_http_status(A, B, C, D)
#endif

static struct libwebsocket_protocols protocols[] = {
	/* first protocol must always be HTTP handler */
	{
		"http-only",
		callback_http,
		sizeof (struct libws_http_data),
		0,
#ifdef LWS_FEATURE_PROTOCOLS_HAS_ID_FIELD
		0,
#endif
		NULL,
#if !defined(LWS_LIBRARY_VERSION_NUMBER)
		0
#endif
	},
	{
		"mqtt",
		callback_mqtt,
		sizeof(struct libws_mqtt_data),
		0,
#ifdef LWS_FEATURE_PROTOCOLS_HAS_ID_FIELD
		1,
#endif
		NULL,
#if !defined(LWS_LIBRARY_VERSION_NUMBER)
		0
#endif
	},
	{
		"mqttv3.1",
		callback_mqtt,
		sizeof(struct libws_mqtt_data),
		0,
#ifdef LWS_FEATURE_PROTOCOLS_HAS_ID_FIELD
		1,
#endif
		NULL,
#if !defined(LWS_LIBRARY_VERSION_NUMBER)
		0
#endif
	},
#ifdef LWS_FEATURE_PROTOCOLS_HAS_ID_FIELD
#  if defined(LWS_LIBRARY_VERSION_NUMBER)
	{ NULL, NULL, 0, 0, 0, NULL}
#  else
	{ NULL, NULL, 0, 0, 0, NULL, 0}
#  endif
#else
	{ NULL, NULL, 0, 0, NULL, 0}
#endif
};

static void easy_address(int sock, struct mosquitto *mosq)
{
	char address[1024];

	if(!_mosquitto_socket_get_address(sock, address, 1024)){
		mosq->address = _mosquitto_strdup(address);
	}
}

#if defined(LWS_LIBRARY_VERSION_NUMBER)
static int callback_mqtt(
#else
static int callback_mqtt(struct libwebsocket_context *context,
#endif
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
		void *user,
		void *in,
		size_t len)
{
	struct mosquitto_db *db;
	struct mosquitto *mosq = NULL;
	struct _mosquitto_packet *packet;
	int count, i, j;
	const struct libwebsocket_protocols *p;
	struct libws_mqtt_data *u = (struct libws_mqtt_data *)user;
	size_t pos;
	uint8_t *buf;
	int rc;
	uint8_t byte;

	db = &int_db;

	switch (reason) {
		case LWS_CALLBACK_ESTABLISHED:
			mosq = mqtt3_context_init(db, WEBSOCKET_CLIENT);
			if(mosq){
				p = libwebsocket_get_protocol(wsi);
				for (i=0; i<db->config->listener_count; i++){
					if (db->config->listeners[i].protocol == mp_websockets) {
						for (j=0; db->config->listeners[i].ws_protocol[j].name; j++){
							if (p == &db->config->listeners[i].ws_protocol[j]){
								mosq->listener = &db->config->listeners[i];
								mosq->listener->client_count++;
							}
						}
					}
				}

#if !defined(LWS_LIBRARY_VERSION_NUMBER)
				mosq->ws_context = context;
#endif
				mosq->wsi = wsi;
				u->mosq = mosq;
			}else{
				return -1;
			}
			easy_address(libwebsocket_get_socket_fd(wsi), mosq);
			if(!mosq->address){
				/* getpeername and inet_ntop failed and not a bridge */
				_mosquitto_free(mosq);
				u->mosq = NULL;
				return -1;
			}
			break;

		case LWS_CALLBACK_CLOSED:
			if(!u){
				return -1;
			}
			mosq = u->mosq;
			if(mosq){
				mosq->wsi = NULL;
				do_disconnect(db, mosq);
			}
			break;

		case LWS_CALLBACK_SERVER_WRITEABLE:
			if(!u){
				return -1;
			}
			mosq = u->mosq;
			if(!mosq || mosq->state == mosq_cs_disconnect_ws || mosq->state == mosq_cs_disconnecting){
				return -1;
			}

			mqtt3_db_message_write(db, mosq);

			if(mosq->out_packet && !mosq->current_out_packet){
				mosq->current_out_packet = mosq->out_packet;
				mosq->out_packet = mosq->out_packet->next;
				if(!mosq->out_packet){
					mosq->out_packet_last = NULL;
				}
			}

			while(mosq->current_out_packet && !lws_send_pipe_choked(mosq->wsi)){
				packet = mosq->current_out_packet;

				if(packet->pos == 0 && packet->to_process == packet->packet_length){
					/* First time this packet has been dealt with.
					 * libwebsockets requires that the payload has
					 * LWS_SEND_BUFFER_PRE_PADDING space available before the
					 * actual data and LWS_SEND_BUFFER_POST_PADDING afterwards.
					 * We've already made the payload big enough to allow this,
					 * but need to move it into position here. */
					memmove(&packet->payload[LWS_SEND_BUFFER_PRE_PADDING], packet->payload, packet->packet_length);
					packet->pos += LWS_SEND_BUFFER_PRE_PADDING;
				}
				count = libwebsocket_write(wsi, &packet->payload[packet->pos], packet->to_process, LWS_WRITE_BINARY);
#ifdef LWS_IS_OLD
				/* lws < 1.3 doesn't return a valid count, assume everything sent. */
				count = packet->to_process;
#endif
				if(count < 0){
					return 0;
				}
				packet->to_process -= count;
				packet->pos += count;
				if(packet->to_process > 0){
					break;
				}

				/* Free data and reset values */
				mosq->current_out_packet = mosq->out_packet;
				if(mosq->out_packet){
					mosq->out_packet = mosq->out_packet->next;
					if(!mosq->out_packet){
						mosq->out_packet_last = NULL;
					}
				}

				_mosquitto_packet_cleanup(packet);
				_mosquitto_free(packet);

				mosq->next_msg_out = mosquitto_time() + mosq->keepalive;

				if(mosq->current_out_packet){
					libwebsocket_callback_on_writable(mosq->ws_context, mosq->wsi);
				}
			}
			if(mosq->current_out_packet){
				libwebsocket_callback_on_writable(mosq->ws_context, mosq->wsi);
			}
			break;

		case LWS_CALLBACK_RECEIVE:
			if(!u || !u->mosq){
				return -1;
			}
			mosq = u->mosq;
			pos = 0;
			buf = (uint8_t *)in;
#ifdef WITH_SYS_TREE
			g_bytes_received += len;
#endif
			while(pos < len){
				if(!mosq->in_packet.command){
					mosq->in_packet.command = buf[pos];
					pos++;
					/* Clients must send CONNECT as their first command. */
					if(mosq->state == mosq_cs_new && (mosq->in_packet.command&0xF0) != CONNECT){
						return -1;
					}
				}
				if(mosq->in_packet.remaining_count <= 0){
					do{
						if(pos == len){
							return 0;
						}
						byte = buf[pos];
						pos++;

						mosq->in_packet.remaining_count--;
						/* Max 4 bytes length for remaining length as defined by protocol.
						* Anything more likely means a broken/malicious client.
						*/
						if(mosq->in_packet.remaining_count < -4){
							return -1;
						}

						mosq->in_packet.remaining_length += (byte & 127) * mosq->in_packet.remaining_mult;
						mosq->in_packet.remaining_mult *= 128;
					}while((byte & 128) != 0);
					mosq->in_packet.remaining_count *= -1;

					if(mosq->in_packet.remaining_length > 0){
						mosq->in_packet.payload = _mosquitto_malloc(mosq->in_packet.remaining_length*sizeof(uint8_t));
						if(!mosq->in_packet.payload){
							return -1;
						}
						mosq->in_packet.to_process = mosq->in_packet.remaining_length;
					}
				}
				if(mosq->in_packet.to_process>0){
					if(len - pos >= mosq->in_packet.to_process){
						memcpy(&mosq->in_packet.payload[mosq->in_packet.pos], &buf[pos], mosq->in_packet.to_process);
						mosq->in_packet.pos += mosq->in_packet.to_process;
						pos += mosq->in_packet.to_process;
						mosq->in_packet.to_process = 0;
					}else{
						memcpy(&mosq->in_packet.payload[mosq->in_packet.pos], &buf[pos], len-pos);
						mosq->in_packet.pos += len-pos;
						mosq->in_packet.to_process -= len-pos;
						return 0;
					}
				}
				/* All data for this packet is read. */
				mosq->in_packet.pos = 0;
#ifdef WITH_SYS_TREE
				g_msgs_received++;
				if(((mosq->in_packet.command)&0xF5) == PUBLISH){
					g_pub_msgs_received++;
				}
#endif
				rc = mqtt3_packet_handle(db, mosq);

				/* Free data and reset values */
				_mosquitto_packet_cleanup(&mosq->in_packet);

				mosq->last_msg_in = mosquitto_time();

				if(rc){
					do_disconnect(db, mosq);
					return -1;
				}
			}
			break;

		default:
			break;
	}

	return 0;
}


#if defined(LWS_LIBRARY_VERSION_NUMBER)
static int callback_http(
#else
static int callback_http(struct libwebsocket_context *context,
#endif
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
		void *user,
		void *in,
		size_t len)
{
	struct libws_http_data *u = (struct libws_http_data *)user;
	struct libws_mqtt_hack *hack;
	char *http_dir;
	size_t buflen, slen;
#ifndef LWS_IS_OLD
	size_t wlen;
#endif
	char *filename, *filename_canonical;
	unsigned char buf[4096];
	struct stat filestat;

	/* FIXME - ssl cert verification is done here. */

	switch (reason) {
		case LWS_CALLBACK_HTTP:
			if(!u){
				return -1;
			}

#if defined(LWS_LIBRARY_VERSION_NUMBER)
			hack = (struct libws_mqtt_hack *)lws_context_user(lws_get_context(wsi));
#else
			hack = (struct libws_mqtt_hack *)libwebsocket_context_user(context);
#endif
			if(!hack){
				return -1;
			}
			http_dir = hack->http_dir;

			if(!http_dir){
				/* http disabled */
				return -1;
			}

#ifndef LWS_IS_OLD
			/* Forbid POST */
			if(lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)){
				libwebsockets_return_http_status(context, wsi, HTTP_STATUS_METHOD_NOT_ALLOWED, NULL);
				return -1;
			}
#endif

			if(!strcmp((char *)in, "/")){
				slen = strlen(http_dir) + strlen("/index.html") + 2;
			}else{
				slen = strlen(http_dir) + strlen((char *)in) + 2;
			}
			filename = _mosquitto_malloc(slen);
			if(!filename){
				libwebsockets_return_http_status(context, wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
				return -1;
			}
			if(!strcmp((char *)in, "/")){
				snprintf(filename, slen, "%s/index.html", http_dir);
			}else{
				snprintf(filename, slen, "%s%s", http_dir, (char *)in);
			}


			/* Get canonical path and check it is within our http_dir */
#ifdef WIN32
			filename_canonical = _fullpath(NULL, filename, 0);
			if(!filename_canonical){
				_mosquitto_free(filename);
				libwebsockets_return_http_status(context, wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
				return -1;
			}
#else
			filename_canonical = realpath(filename, NULL);
			if(!filename_canonical){
				_mosquitto_free(filename);
				if(errno == EACCES){
					libwebsockets_return_http_status(context, wsi, HTTP_STATUS_FORBIDDEN, NULL);
				}else if(errno == EINVAL || errno == EIO || errno == ELOOP){
					libwebsockets_return_http_status(context, wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
				}else if(errno == ENAMETOOLONG){
					libwebsockets_return_http_status(context, wsi, HTTP_STATUS_REQ_URI_TOO_LONG, NULL);
				}else if(errno == ENOENT || errno == ENOTDIR){
					libwebsockets_return_http_status(context, wsi, HTTP_STATUS_NOT_FOUND, NULL);
				}
				return -1;
			}
#endif
			if(strncmp(http_dir, filename_canonical, strlen(http_dir))){
				/* Requested file isn't within http_dir, deny access. */
				free(filename_canonical);
				_mosquitto_free(filename);
				libwebsockets_return_http_status(context, wsi, HTTP_STATUS_FORBIDDEN, NULL);
				return -1;
			}
			free(filename_canonical);

			_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "http serving file \"%s\".", filename);
			u->fptr = fopen(filename, "rb");
			_mosquitto_free(filename);
			if(!u->fptr){
				libwebsockets_return_http_status(context, wsi, HTTP_STATUS_NOT_FOUND, NULL);
				return -1;
			}
			if(fstat(fileno(u->fptr), &filestat) < 0){
				libwebsockets_return_http_status(context, wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
				fclose(u->fptr);
				return -1;
			}
#ifdef WIN32
			if((filestat.st_mode & S_IFREG) != S_IFREG){
#else
			if(!S_ISREG(filestat.st_mode)){
#endif
				libwebsockets_return_http_status(context, wsi, HTTP_STATUS_FORBIDDEN, NULL);
				return -1;
			}

			buflen = snprintf((char *)buf, 4096, "HTTP/1.0 200 OK\r\n"
												"Server: mosquitto\r\n"
												"Content-Length: %u\r\n\r\n",
												(unsigned int)filestat.st_size);
            if(libwebsocket_write(wsi, buf, buflen, LWS_WRITE_HTTP) < 0){
				fclose(u->fptr);
				return -1;
			}
			libwebsocket_callback_on_writable(context, wsi);
			break;

#ifndef LWS_IS_OLD
		case LWS_CALLBACK_HTTP_BODY:
			/* For extra POST data? */
			return -1;

		case LWS_CALLBACK_HTTP_BODY_COMPLETION:
			/* For end of extra POST data? */
			return -1;

		case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
			/* Access control here */
			return 0;

		case LWS_CALLBACK_HTTP_WRITEABLE:
			/* Send our data here */
			if(u && u->fptr){
				do{
					buflen = fread(buf, 1, sizeof(buf), u->fptr);
					if(buflen < 1){
						fclose(u->fptr);
						return -1;
					}
					wlen = libwebsocket_write(wsi, buf, buflen, LWS_WRITE_HTTP);
					if(wlen < buflen){
						if(fseek(u->fptr, buflen-wlen, SEEK_CUR) < 0){
							fclose(u->fptr);
							u->fptr = NULL;
							return -1;
						}
					}else{
						if(buflen < sizeof(buf)){
							fclose(u->fptr);
							u->fptr = NULL;
						}
					}
				}while(u->fptr && !lws_send_pipe_choked(wsi));
				libwebsocket_callback_on_writable(context, wsi);
			}else{
				return -1;
			}
#endif

		default:
			return 0;
	}

	return 0;
}

static void log_wrap(int level, const char *line)
{
	char *l = (char *)line;
	l[strlen(line)-1] = '\0'; // Remove \n
	_mosquitto_log_printf(NULL, MOSQ_LOG_WEBSOCKETS, "%s", l);
}

struct libwebsocket_context *mosq_websockets_init(struct _mqtt3_listener *listener, int log_level)
{
	struct lws_context_creation_info info;
	struct libwebsocket_protocols *p;
	int protocol_count;
	int i;
	struct libws_mqtt_hack *user;

	/* Count valid protocols */
	for(protocol_count=0; protocols[protocol_count].name; protocol_count++);

	p = _mosquitto_calloc(protocol_count+1, sizeof(struct libwebsocket_protocols));
	if(!p){
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Out of memory.");
		return NULL;
	}
	for(i=0; protocols[i].name; i++){
		p[i].name = protocols[i].name;
		p[i].callback = protocols[i].callback;
		p[i].per_session_data_size = protocols[i].per_session_data_size;
		p[i].rx_buffer_size = protocols[i].rx_buffer_size;
	}

	memset(&info, 0, sizeof(info));
	info.iface = listener->host;
	info.port = listener->port;
	info.protocols = p;
	info.gid = -1;
	info.uid = -1;
#ifdef WITH_TLS
	info.ssl_ca_filepath = listener->cafile;
	info.ssl_cert_filepath = listener->certfile;
	info.ssl_private_key_filepath = listener->keyfile;
#ifndef LWS_IS_OLD
	info.ssl_cipher_list = listener->ciphers;
#endif
	if(listener->require_certificate){
		info.options |= LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;
	}
#endif
#ifndef LWS_IS_OLD
	info.options |= LWS_SERVER_OPTION_DISABLE_IPV6;
#endif
#if LWS_LIBRARY_VERSION_MAJOR>1
	info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
#endif

	user = _mosquitto_calloc(1, sizeof(struct libws_mqtt_hack));
	if(!user){
		_mosquitto_free(p);
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Out of memory.");
		return NULL;
	}

	if(listener->http_dir){
#ifdef WIN32
		user->http_dir = _fullpath(NULL, listener->http_dir, 0);
#else
		user->http_dir = realpath(listener->http_dir, NULL);
#endif
		if(!user->http_dir){
			_mosquitto_free(user);
			_mosquitto_free(p);
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open http dir \"%s\".", user->http_dir);
			return NULL;
		}
	}

	info.user = user;
	listener->ws_protocol = p;

	lws_set_log_level(log_level, log_wrap);

	_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Opening websockets listen socket on port %d.", listener->port);
	return libwebsocket_create_context(&info);
}


#endif
