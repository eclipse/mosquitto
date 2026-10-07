/*
Copyright (c) 2014-2021 Roger Light <roger@atchoo.org>

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

#ifdef WITH_WEBSOCKETS

#include "config.h"

#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_LWS
#  include <libwebsockets.h>
#endif
#include "mosquitto_internal.h"
#include "mosquitto_broker_internal.h"
#include "mosquitto/mqtt_protocol.h"
#include "packet_mosq.h"
#include "sys_tree.h"
#include "util_mosq.h"

#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>

#ifndef WIN32
#  include <sys/socket.h>
#endif

#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_LWS
/* Be careful if changing these, if TX is not bigger than SERV then there can
 * be very large write performance penalties.
 */
#define WS_SERV_BUF_SIZE 4096
#define WS_TX_BUF_SIZE (WS_SERV_BUF_SIZE*2)

static int callback_mqtt(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user,
		void *in,
		size_t len);

static int callback_http(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user,
		void *in,
		size_t len);

enum mosq_ws_protocols {
	PROTOCOL_HTTP = 0,
	PROTOCOL_MQTT,
	DEMO_PROTOCOL_COUNT,
};

struct libws_http_data {
	FILE *fptr;
};

static struct lws_protocols protocols[] = {
	/* first protocol must always be HTTP handler */
	{
		"http-only",                        /* name */
		callback_http,                      /* lws_callback_function */
		sizeof (struct libws_http_data),    /* per_session_data_size */
		0,                                  /* rx_buffer_size */
		0,                                  /* id */
		NULL,                               /* user v1.4 on */
		WS_TX_BUF_SIZE                      /* tx_packet_size v2.3.0 */
	},
	{
		"mqtt",
		callback_mqtt,
		sizeof(struct libws_mqtt_data),
		0,                                  /* rx_buffer_size */
		1,                                  /* id */
		NULL,                               /* user v1.4 on */
		WS_TX_BUF_SIZE                      /* tx_packet_size v2.3.0 */
	},
	{
		"mqttv3.1",
		callback_mqtt,
		sizeof(struct libws_mqtt_data),
		0,                                  /* rx_buffer_size */
		2,                                  /* id */
		NULL,                               /* user v1.4 on */
		WS_TX_BUF_SIZE                      /* tx_packet_size v2.3.0 */
	},
	{
		NULL,
		NULL,
		0,
		0,                                  /* rx_buffer_size */
		0,                                  /* id */
		NULL,                               /* user v1.4 on */
		0                                   /* tx_packet_size v2.3.0 */
	}
};


static void easy_address(int sock, struct mosquitto *mosq)
{
	char address[1024];

	if(!net__socket_get_address(sock, address, 1024, &mosq->remote_port)){
		mosq->address = mosquitto_strdup(address);
	}
}


static int callback_mqtt(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user,
		void *in,
		size_t len)
{
	struct mosquitto *mosq = NULL;
	struct mosquitto__packet *packet;
	int count;
	unsigned int ucount;
	const struct lws_protocols *p;
	struct libws_mqtt_data *u = (struct libws_mqtt_data *)user;
	size_t pos;
	uint8_t *buf;
	int rc;
	uint8_t byte;
	char ip_addr_buff[1024];

	switch(reason){
		case LWS_CALLBACK_ESTABLISHED:
			mosq = context__init();
			if(mosq){
				p = lws_get_protocol(wsi);
				mosq->listener = p->user;
				if(!mosq->listener){
					mosquitto_FREE(mosq);
					return -1;
				}
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

			easy_address(lws_get_socket_fd(wsi), mosq);
			if(!mosq->address){
				/* getpeername and inet_ntop failed and not a bridge */
				mosquitto_FREE(mosq);
				u->mosq = NULL;
				return -1;
			}
			mosq->listener->client_count++;
			if((mosq->listener->max_connections > 0 && mosq->listener->client_count > mosq->listener->max_connections)
					|| (db.config->global_max_connections > 0 && HASH_CNT(hh_sock, db.contexts_by_sock) > (unsigned int)db.config->global_max_connections)){

				if(db.config->connection_messages == true){
					log__printf(NULL, MOSQ_LOG_NOTICE, "Client connection from %s denied: max_connections exceeded.", mosq->address);
				}
				mosq->listener->client_count--;
				mosquitto_FREE(mosq->address);
				mosquitto_FREE(mosq);
				u->mosq = NULL;
				return -1;
			}
			mosq->sock = lws_get_socket_fd(wsi);
			HASH_ADD(hh_sock, db.contexts_by_sock, sock, sizeof(mosq->sock), mosq);
			mux__new(mosq);
			break;

		case LWS_CALLBACK_CLOSED:
			if(!u){
				return -1;
			}
			mosq = u->mosq;
			if(mosq){
				if(mosq->sock != INVALID_SOCKET){
					HASH_DELETE(hh_sock, db.contexts_by_sock, mosq);
					mosq->sock = INVALID_SOCKET;
					mux__delete(mosq);
				}
				mosq->wsi = NULL;
#ifdef WITH_TLS
				mosq->ssl = NULL;
#endif
				do_disconnect(mosq, MOSQ_ERR_CONN_LOST);
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

			rc = db__message_write_inflight_out_latest(mosq);
			if(rc){
				return -1;
			}
			rc = db__message_write_queued_out(mosq);
			if(rc){
				return -1;
			}

			while(mosq->out_packet && !lws_send_pipe_choked(mosq->wsi)){
				packet = mosq->out_packet;
				count = lws_write(wsi, &packet->payload[packet->pos], packet->to_process, LWS_WRITE_BINARY);
				if(count < 0){
					if(mosq->state == mosq_cs_disconnect_ws
							|| mosq->state == mosq_cs_disconnecting
							|| mosq->state == mosq_cs_disused){

						return -1;
					}
					return 0;
				}
				ucount = (unsigned int)count;
#ifdef WITH_SYS_TREE
				metrics__int_inc(mosq_counter_bytes_sent, ucount);
#endif
				packet->to_process -= ucount;
				packet->pos += ucount;
				if(packet->to_process > 0){
					if(mosq->state == mosq_cs_disconnect_ws
							|| mosq->state == mosq_cs_disconnecting
							|| mosq->state == mosq_cs_disused){

						return -1;
					}
					break;
				}

#ifdef WITH_SYS_TREE
				metrics__int_inc(mosq_counter_messages_sent, 1);
				if(((packet->command)&0xF0) == CMD_PUBLISH){
					metrics__int_inc(mosq_counter_mqtt_publish_sent, 1);
				}
#endif

				packet__get_next_out(mosq);
				mosquitto_FREE(packet);

				mosq->next_msg_out = db.now_s + mosq->keepalive;
			}
			if(mosq->state == mosq_cs_disconnect_ws
					|| mosq->state == mosq_cs_disconnecting
					|| mosq->state == mosq_cs_disused){

				return -1;
			}
			if(mosq->out_packet){
				lws_callback_on_writable(mosq->wsi);
			}
			break;

		case LWS_CALLBACK_RECEIVE:
			if(!u || !u->mosq){
				return -1;
			}
			mosq = u->mosq;
			pos = 0;
			buf = (uint8_t *)in;
			metrics__int_inc(mosq_counter_bytes_received, (int64_t)len);
			while(pos < len){
				if(!mosq->in_packet.command){
					mosq->in_packet.command = buf[pos];
					pos++;
					/* Clients must send CONNECT as their first command. */
					if(mosq->state == mosq_cs_new && (mosq->in_packet.command&0xF0) != CMD_CONNECT){
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
					mosq->in_packet.remaining_count = (int8_t)(mosq->in_packet.remaining_count * -1);

					if(mosq->in_packet.remaining_length > 0){
						mosq->in_packet.payload = mosquitto_malloc(mosq->in_packet.remaining_length*sizeof(uint8_t));
						if(!mosq->in_packet.payload){
							return -1;
						}
						mosq->in_packet.to_process = mosq->in_packet.remaining_length;
					}
				}
				if(mosq->in_packet.to_process>0){
					if((uint32_t)len - pos >= mosq->in_packet.to_process){
						memcpy(&mosq->in_packet.payload[mosq->in_packet.pos], &buf[pos], mosq->in_packet.to_process);
						mosq->in_packet.pos += mosq->in_packet.to_process;
						pos += mosq->in_packet.to_process;
						mosq->in_packet.to_process = 0;
					}else{
						memcpy(&mosq->in_packet.payload[mosq->in_packet.pos], &buf[pos], len-pos);
						mosq->in_packet.pos += (uint32_t)(len-pos);
						mosq->in_packet.to_process -= (uint32_t)(len-pos);
						return 0;
					}
				}
				/* All data for this packet is read. */
				mosq->in_packet.pos = 0;

#ifdef WITH_SYS_TREE
				metrics__int_inc(mosq_counter_messages_received, 1);
#endif
				rc = handle__packet(mosq);

				/* Free data and reset values */
				packet__cleanup(&mosq->in_packet);

				keepalive__update(mosq);

				if(rc && mosq->out_packet){
					if(mosq->state != mosq_cs_disconnecting){
						mosquitto__set_state(mosq, mosq_cs_disconnect_ws);
					}
					lws_callback_on_writable(mosq->wsi);
				}else if(rc){
					do_disconnect(mosq, MOSQ_ERR_CONN_LOST);
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
		struct lws *wsi,
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
	filename = mosquitto_malloc(slen);
	if(!filename){
		lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
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
	mosquitto_FREE(filename);
	if(!filename_canonical){
		lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
		return NULL;
	}
#else
	filename_canonical = realpath(filename, NULL);
	mosquitto_FREE(filename);
	if(!filename_canonical){
		if(errno == EACCES){
			lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);
		}else if(errno == EINVAL || errno == EIO || errno == ELOOP){
			lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
		}else if(errno == ENAMETOOLONG){
			lws_return_http_status(wsi, HTTP_STATUS_REQ_URI_TOO_LONG, NULL);
		}else if(errno == ENOENT || errno == ENOTDIR){
			lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
		}
		return NULL;
	}
#endif
	if(strncmp(http_dir, filename_canonical, strlen(http_dir))){
		/* Requested file isn't within http_dir, deny access. */
		SAFE_FREE(filename_canonical);
		lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);
		return NULL;
	}

	return filename_canonical;
}


static int callback_http(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user,
		void *in,
		size_t len)
{
	struct libws_http_data *u = (struct libws_http_data *)user;
	struct libws_mqtt_hack *hack;
	char *http_dir;
	size_t buflen;
	size_t wlen;
	int rc;
	char *filename_canonical;
	unsigned char buf[4096];
	struct stat filestat;
	struct mosquitto *mosq;
	struct lws_pollargs *pollargs = (struct lws_pollargs *)in;
	int hlen;

	/* FIXME - ssl cert verification is done here. */

	switch(reason){
		case LWS_CALLBACK_HTTP:
			if(!u){
				return -1;
			}

			hack = (struct libws_mqtt_hack *)lws_context_user(lws_get_context(wsi));
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
				lws_return_http_status(wsi, HTTP_STATUS_METHOD_NOT_ALLOWED, NULL);
				return -1;
			}

			filename_canonical = http__canonical_filename(wsi, (char *)in, http_dir);
			if(!filename_canonical){
				return -1;
			}

			u->fptr = fopen(filename_canonical, "rb");
			if(!u->fptr){
				SAFE_FREE(filename_canonical);
				lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
				return -1;
			}
			if(fstat(fileno(u->fptr), &filestat) < 0){
				SAFE_FREE(filename_canonical);
				lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
				fclose(u->fptr);
				u->fptr = NULL;
				return -1;
			}


			if((filestat.st_mode & S_IFDIR) == S_IFDIR){
				fclose(u->fptr);
				u->fptr = NULL;
				SAFE_FREE(filename_canonical);

				/* FIXME - use header functions from lws 2.x */
				buflen = (size_t)snprintf((char *)buf, 4096, "HTTP/1.0 302 OK\r\n"
						"Location: %s/\r\n\r\n",
						(char *)in);
				return lws_write(wsi, buf, buflen, LWS_WRITE_HTTP);
			}

			if((filestat.st_mode & S_IFREG) != S_IFREG){
				lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);
				fclose(u->fptr);
				u->fptr = NULL;
				SAFE_FREE(filename_canonical);
				return -1;
			}

			log__printf(NULL, MOSQ_LOG_DEBUG, "http serving file \"%s\".", filename_canonical);
			SAFE_FREE(filename_canonical);
			/* FIXME - use header functions from lws 2.x */
			buflen = (size_t)snprintf((char *)buf, 4096, "HTTP/1.0 200 OK\r\n"
					"Server: mosquitto\r\n"
					"Content-Length: %u\r\n\r\n",
					(unsigned int)filestat.st_size);
			if(lws_write(wsi, buf, buflen, LWS_WRITE_HTTP) < 0){
				fclose(u->fptr);
				u->fptr = NULL;
				return -1;
			}
			lws_callback_on_writable(wsi);
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

#if LWS_LIBRARY_VERSION_NUMBER >= 3001000
		case LWS_CALLBACK_HTTP_CONFIRM_UPGRADE:
			hack = lws_context_user(lws_get_context(wsi));
			if(hack->listener->ws_origin_count){
				hlen = lws_hdr_total_length(wsi, WSI_TOKEN_ORIGIN);
				if(hlen <= 0 || hlen >= (int)sizeof(buf)){
					return -1;
				}
				for(int i=0; i<hack->listener->ws_origin_count; i++){
					lws_hdr_copy(wsi, (char *)buf, sizeof(buf), WSI_TOKEN_ORIGIN);
					if((!strcmp(hack->listener->ws_origins[i], (char *)buf))){
						return 0;
					}
				}
				return -1;
			}else{
				return 0;
			}
#endif

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
					rc = lws_write(wsi, buf, buflen, LWS_WRITE_HTTP);
					if(rc < 0){
						return -1;
					}
					wlen = (size_t)rc;
					/* while still active, extend timeout */
					if(wlen){
						lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT, 10);
					}
					if(wlen < buflen){
						if(fseek(u->fptr, (long)(buflen-wlen), SEEK_CUR) < 0){
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
				lws_callback_on_writable(wsi);
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
			HASH_FIND(hh_sock, db.contexts_by_sock, &pollargs->fd, sizeof(pollargs->fd), mosq);
			if(mosq){
				if(pollargs->events & LWS_POLLOUT){
					mux__add_out(mosq);
				}else{
					mux__remove_out(mosq);
				}
			}else{
				if(pollargs->events & POLLIN){
					/* Assume this is a new listener */
					listeners__add_websockets(lws_get_context(wsi), pollargs->fd);
				}
			}
			break;

		case LWS_CALLBACK_DEL_POLL_FD:
			HASH_FIND(hh_sock, db.contexts_by_sock, &pollargs->fd, sizeof(pollargs->fd), mosq);
			if(mosq){
				mux__delete(mosq);
			}
			break;

		case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
			HASH_FIND(hh_sock, db.contexts_by_sock, &pollargs->fd, sizeof(pollargs->fd), mosq);
			if(mosq){
				if(pollargs->events & LWS_POLLHUP){
					return 1;
				}else if(pollargs->events & LWS_POLLOUT){
					mux__add_out(mosq);
				}else{
					mux__remove_out(mosq);
				}
			}
			break;

#ifdef WITH_TLS
		case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
			if(!len || (SSL_get_verify_result((SSL *)in) != X509_V_OK)){
				return 1;
			}
			break;
#endif

		default:
			return 0;
	}

	return 0;
}


static void log_wrap(int level, const char *line)
{
	char *l = (char *)line;
	UNUSED(level);
	l[strlen(line)-1] = '\0'; /* Remove \n */
	log__printf(NULL, MOSQ_LOG_WEBSOCKETS, "%s", l);
}


void mosq_websockets_init(struct mosquitto__listener *listener, const struct mosquitto__config *conf)
{
	struct lws_context_creation_info info;
	struct lws_protocols *p;
	size_t protocol_count;
	int i;
	struct libws_mqtt_hack *user;

	/* Count valid protocols */
	for(protocol_count=0; protocols[protocol_count].name; protocol_count++){
		;
	}

	p = mosquitto_calloc(protocol_count+1, sizeof(struct lws_protocols));
	if(!p){
		log__printf(NULL, MOSQ_LOG_ERR, "Out of memory.");
		return;
	}
	for(i=0; protocols[i].name; i++){
		p[i].name = protocols[i].name;
		p[i].callback = protocols[i].callback;
		p[i].per_session_data_size = protocols[i].per_session_data_size;
		p[i].rx_buffer_size = protocols[i].rx_buffer_size;
		p[i].user = listener;
	}

	memset(&info, 0, sizeof(info));
	info.iface = listener->host;
	info.port = listener->port;
	info.protocols = p;
	info.gid = -1;
	info.uid = -1;
#ifdef WITH_TLS
	if(listener->cafile){
		info.ssl_ca_filepath = listener->cafile;
	}else if(listener->capath){
		log__printf(NULL, MOSQ_LOG_WARNING, "Warning: CA path option is not supported for websockets");
	}
	info.ssl_cert_filepath = listener->certfile;
	info.ssl_private_key_filepath = listener->keyfile;
	info.ssl_cipher_list = listener->ciphers;
	/* HTTP 1 only, due to HTTP 2 issues in Firefox:
	   https://github.com/eclipse-mosquitto/mosquitto/issues/1211
	*/
	info.alpn = "h1";
#if defined(WITH_WEBSOCKETS) && LWS_LIBRARY_VERSION_NUMBER>=3001000
	info.tls1_3_plus_cipher_list = listener->ciphers_tls13;
#endif
	if(listener->require_certificate){
		info.options |= LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;
	}
#endif

	info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	if(listener->socket_domain == AF_INET){
		info.options |= LWS_SERVER_OPTION_DISABLE_IPV6;
	}
	info.max_http_header_data = conf->packet_buffer_size;

	user = mosquitto_calloc(1, sizeof(struct libws_mqtt_hack));
	if(!user){
		mosquitto_FREE(p);
		log__printf(NULL, MOSQ_LOG_ERR, "Out of memory.");
		return;
	}

	if(listener->http_dir){
#ifdef WIN32
		user->http_dir = _fullpath(NULL, listener->http_dir, 0);
#else
		user->http_dir = realpath(listener->http_dir, NULL);
#endif
		if(!user->http_dir){
			mosquitto_FREE(user);
			mosquitto_FREE(p);
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open http dir \"%s\".", listener->http_dir);
			return;
		}
	}
	user->listener = listener;

	info.user = user;
	info.pt_serv_buf_size = WS_SERV_BUF_SIZE;
	listener->ws_protocol = p;

	lws_set_log_level(conf->websockets_log_level, log_wrap);

	log__printf(NULL, MOSQ_LOG_INFO, "Opening websockets listen socket on port %d.", listener->port);
	listener->ws_in_init = true;
	listener->ws_context = lws_create_context(&info);
	listener->ws_in_init = false;
}

#endif
#endif
