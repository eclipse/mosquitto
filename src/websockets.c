/*
Copyright (c) 2014-2018 Roger Light <roger@atchoo.org>
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

#include "config.h"

#include <libwebsockets.h>
#include "mosquitto_internal.h"
#include "mosquitto_broker_internal.h"
#include "mqtt3_protocol.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "sys_tree.h"

#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>

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

	if(!net__socket_get_address(sock, address, 1024)){
		mosq->address = mosquitto__strdup(address);
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
	struct mosquitto__packet *packet;
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
			mosq = context__init(db, WEBSOCKET_CLIENT);
			if(mosq){
				p = libwebsockets_get_protocol(wsi);
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
				if(!mosq->listener){
					mosquitto__free(mosq);
					return -1;
				}
#if !defined(LWS_LIBRARY_VERSION_NUMBER)
				mosq->ws_context = context;
#endif
				mosq->wsi = wsi;
#ifdef WITH_TLS
				if(in){
					mosq->ssl = (SSL *)in;
					if(!mosq->listener->ssl_ctx){
						mosq->listener->ssl_ctx = SSL_get_SSL_CTX(mosq->ssl);
					}
				}
#endif
				u->mosq = mosq;
			}else{
				return -1;
			}
			easy_address(libwebsocket_get_socket_fd(wsi), mosq);
			if(!mosq->address){
				/* getpeername and inet_ntop failed and not a bridge */
				mosquitto__free(mosq);
				u->mosq = NULL;
				return -1;
			}
			if(mosq->listener->max_connections > 0 && mosq->listener->client_count > mosq->listener->max_connections){
				log__printf(NULL, MOSQ_LOG_NOTICE, "Client connection from %s denied: max_connections exceeded.", mosq->address);
				mosquitto__free(mosq);
				u->mosq = NULL;
				return -1;
			}
			mosq->sock = libwebsocket_get_socket_fd(wsi);
			HASH_ADD(hh_sock, db->contexts_by_sock, sock, sizeof(mosq->sock), mosq);
			break;

		case LWS_CALLBACK_CLOSED:
			if(!u){
				return -1;
			}
			mosq = u->mosq;
			if(mosq){
				if(mosq->sock > 0){
					HASH_DELETE(hh_sock, db->contexts_by_sock, mosq);
					mosq->sock = INVALID_SOCKET;
					mosq->pollfd_index = -1;
				}
				mosq->wsi = NULL;
#ifdef WITH_TLS
				mosq->ssl = NULL;
#endif
				do_disconnect(db, mosq);
			}
			break;

		case LWS_CALLBACK_SERVER_WRITEABLE:
			if(!u){
				return -1;
			}
			mosq = u->mosq;
			if(!mosq){
				return -1;
			}

			db__message_write(db, mosq);

			if(mosq->out_packet && !mosq->current_out_packet){
				mosq->current_out_packet = mosq->out_packet;
				mosq->out_packet = mosq->out_packet->next;
				if(!mosq->out_packet){
					mosq->out_packet_last = NULL;
				}
			}

			if(mosq->current_out_packet && !lws_send_pipe_choked(mosq->wsi)){
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
				if(count < 0){
					if (mosq->state == mosq_cs_disconnect_ws || mosq->state == mosq_cs_disconnecting){
						return -1;
					}
					return 0;
				}
#ifdef WITH_SYS_TREE
				g_bytes_sent += count;
#endif
				packet->to_process -= count;
				packet->pos += count;
				if(packet->to_process > 0){
					if (mosq->state == mosq_cs_disconnect_ws || mosq->state == mosq_cs_disconnecting){
						return -1;
					}
					break;
				}

#ifdef WITH_SYS_TREE
				g_msgs_sent++;
				if(((packet->command)&0xF6) == PUBLISH){
					g_pub_msgs_sent++;
				}
#endif

				/* Free data and reset values */
				mosq->current_out_packet = mosq->out_packet;
				if(mosq->out_packet){
					mosq->out_packet = mosq->out_packet->next;
					if(!mosq->out_packet){
						mosq->out_packet_last = NULL;
					}
				}

				packet__cleanup(packet);
				mosquitto__free(packet);

				mosq->next_msg_out = mosquitto_time() + mosq->keepalive;
			}
			if (mosq->state == mosq_cs_disconnect_ws || mosq->state == mosq_cs_disconnecting){
				return -1;
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
			G_BYTES_RECEIVED_INC(len);
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
						mosq->in_packet.payload = mosquitto__malloc(mosq->in_packet.remaining_length*sizeof(uint8_t));
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
				G_MSGS_RECEIVED_INC(1);
				if(((mosq->in_packet.command)&0xF5) == PUBLISH){
					G_PUB_MSGS_RECEIVED_INC(1);
				}
#endif
				rc = handle__packet(db, mosq);

				/* Free data and reset values */
				packet__cleanup(&mosq->in_packet);

				mosq->last_msg_in = mosquitto_time();

				if(rc && (mosq->out_packet || mosq->current_out_packet)) {
					if(mosq->state != mosq_cs_disconnecting){
						mosq->state = mosq_cs_disconnect_ws;
					}
					libwebsocket_callback_on_writable(mosq->ws_context, mosq->wsi);
				} else if (rc) {
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


static char *http__canonical_filename(
		struct libwebsocket *wsi,
		const char *in,
		const char *http_dir)
{
	size_t inlen, slen;
	char *filename, *filename_canonical;

	inlen = strlen(in);
	if(in[inlen-1] == '/'){
		slen = strlen(http_dir) + inlen + strlen("/index.html") + 2;
	}else{
		slen = strlen(http_dir) + inlen + 2;
	}
	filename = mosquitto__malloc(slen);
	if(!filename){
		libwebsockets_return_http_status(context, wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
		return NULL;
	}
	if(((char *)in)[inlen-1] == '/'){
		snprintf(filename, slen, "%s%sindex.html", http_dir, (char *)in);
	}else{
		snprintf(filename, slen, "%s%s", http_dir, (char *)in);
	}


	/* Get canonical path and check it is within our http_dir */
#ifdef WIN32
	filename_canonical = _fullpath(NULL, filename, 0);
	mosquitto__free(filename);
	if(!filename_canonical){
		libwebsockets_return_http_status(context, wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
		return NULL;
	}
#else
	filename_canonical = realpath(filename, NULL);
	mosquitto__free(filename);
	if(!filename_canonical){
		if(errno == EACCES){
			libwebsockets_return_http_status(context, wsi, HTTP_STATUS_FORBIDDEN, NULL);
		}else if(errno == EINVAL || errno == EIO || errno == ELOOP){
			libwebsockets_return_http_status(context, wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
		}else if(errno == ENAMETOOLONG){
			libwebsockets_return_http_status(context, wsi, HTTP_STATUS_REQ_URI_TOO_LONG, NULL);
		}else if(errno == ENOENT || errno == ENOTDIR){
			libwebsockets_return_http_status(context, wsi, HTTP_STATUS_NOT_FOUND, NULL);
		}
		return NULL;
	}
#endif
	if(strncmp(http_dir, filename_canonical, strlen(http_dir))){
		/* Requested file isn't within http_dir, deny access. */
		free(filename_canonical);
		libwebsockets_return_http_status(context, wsi, HTTP_STATUS_FORBIDDEN, NULL);
		return NULL;
	}

	return filename_canonical;
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
	size_t buflen;
	size_t wlen;
	char *filename_canonical;
	unsigned char buf[4096];
	struct stat filestat;
	struct mosquitto_db *db = &int_db;
	struct mosquitto *mosq;
	struct lws_pollargs *pollargs = (struct lws_pollargs *)in;

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

			/* Forbid POST */
			if(lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)){
				libwebsockets_return_http_status(context, wsi, HTTP_STATUS_METHOD_NOT_ALLOWED, NULL);
				return -1;
			}

			filename_canonical = http__canonical_filename(wsi, (char *)in, http_dir);
			if(!filename_canonical) return -1;

			u->fptr = fopen(filename_canonical, "rb");
			if(!u->fptr){
				free(filename_canonical);
				libwebsockets_return_http_status(context, wsi, HTTP_STATUS_NOT_FOUND, NULL);
				return -1;
			}
			if(fstat(fileno(u->fptr), &filestat) < 0){
				free(filename_canonical);
				libwebsockets_return_http_status(context, wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
				fclose(u->fptr);
				u->fptr = NULL;
				return -1;
			}


			if((filestat.st_mode & S_IFDIR) == S_IFDIR){
				fclose(u->fptr);
				u->fptr = NULL;
				free(filename_canonical);

				/* FIXME - use header functions from lws 2.x */
				buflen = snprintf((char *)buf, 4096, "HTTP/1.0 302 OK\r\n"
												"Location: %s/\r\n\r\n",
												(char *)in);
				return libwebsocket_write(wsi, buf, buflen, LWS_WRITE_HTTP);
			}

			if((filestat.st_mode & S_IFREG) != S_IFREG){
				libwebsockets_return_http_status(context, wsi, HTTP_STATUS_FORBIDDEN, NULL);
				fclose(u->fptr);
				u->fptr = NULL;
				free(filename_canonical);
				return -1;
			}

			log__printf(NULL, MOSQ_LOG_DEBUG, "http serving file \"%s\".", filename_canonical);
			free(filename_canonical);
			/* FIXME - use header functions from lws 2.x */
			buflen = snprintf((char *)buf, 4096, "HTTP/1.0 200 OK\r\n"
												"Server: mosquitto\r\n"
												"Content-Length: %u\r\n\r\n",
												(unsigned int)filestat.st_size);
            if(libwebsocket_write(wsi, buf, buflen, LWS_WRITE_HTTP) < 0){
				fclose(u->fptr);
				u->fptr = NULL;
				return -1;
			}
			libwebsocket_callback_on_writable(context, wsi);
			break;

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
						u->fptr = NULL;
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
			break;

		case LWS_CALLBACK_CLOSED:
		case LWS_CALLBACK_CLOSED_HTTP:
		case LWS_CALLBACK_HTTP_FILE_COMPLETION:
			if(u && u->fptr){
				fclose(u->fptr);
				u->fptr = NULL;
			}
			break;

		case LWS_CALLBACK_ADD_POLL_FD:
		case LWS_CALLBACK_DEL_POLL_FD:
		case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
			HASH_FIND(hh_sock, db->contexts_by_sock, &pollargs->fd, sizeof(pollargs->fd), mosq);
			if(mosq && (pollargs->events & POLLOUT)){
				mosq->ws_want_write = true;
			}
			break;

		default:
			return 0;
	}

	return 0;
}

static void log_wrap(int level, const char *line)
{
	char *l = (char *)line;
	l[strlen(line)-1] = '\0'; // Remove \n
	log__printf(NULL, MOSQ_LOG_WEBSOCKETS, "%s", l);
}

struct libwebsocket_context *mosq_websockets_init(struct mosquitto__listener *listener, int log_level)
{
	struct lws_context_creation_info info;
	struct libwebsocket_protocols *p;
	int protocol_count;
	int i;
	struct libws_mqtt_hack *user;

	/* Count valid protocols */
	for(protocol_count=0; protocols[protocol_count].name; protocol_count++);

	p = mosquitto__calloc(protocol_count+1, sizeof(struct libwebsocket_protocols));
	if(!p){
		log__printf(NULL, MOSQ_LOG_ERR, "Out of memory.");
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
	info.ssl_cipher_list = listener->ciphers;
	if(listener->require_certificate){
		info.options |= LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;
	}
#endif

#if LWS_LIBRARY_VERSION_MAJOR>1
	info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
#endif

	user = mosquitto__calloc(1, sizeof(struct libws_mqtt_hack));
	if(!user){
		mosquitto__free(p);
		log__printf(NULL, MOSQ_LOG_ERR, "Out of memory.");
		return NULL;
	}

	if(listener->http_dir){
#ifdef WIN32
		user->http_dir = _fullpath(NULL, listener->http_dir, 0);
#else
		user->http_dir = realpath(listener->http_dir, NULL);
#endif
		if(!user->http_dir){
			mosquitto__free(user);
			mosquitto__free(p);
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open http dir \"%s\".", listener->http_dir);
			return NULL;
		}
	}

	info.user = user;
	listener->ws_protocol = p;

	lws_set_log_level(log_level, log_wrap);

	log__printf(NULL, MOSQ_LOG_INFO, "Opening websockets listen socket on port %d.", listener->port);
	return libwebsocket_create_context(&info);
}


#endif
