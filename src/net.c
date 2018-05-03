/*
Copyright (c) 2009-2018 Roger Light <roger@atchoo.org>

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

#include "config.h"

#ifndef WIN32
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#ifdef WITH_WRAP
#include <tcpd.h>
#endif

#ifdef __FreeBSD__
#  include <netinet/in.h>
#  include <sys/socket.h>
#endif

#ifdef __QNX__
#include <netinet/in.h>
#include <net/netbyte.h>
#include <sys/socket.h>
#endif

#include "mosquitto_broker_internal.h"
#include "mqtt3_protocol.h"
#include "memory_mosq.h"
#include "net_mosq.h"
#include "util_mosq.h"

#ifdef WITH_TLS
#include "tls_mosq.h"
#include <openssl/err.h>
static int tls_ex_index_context = -1;
static int tls_ex_index_listener = -1;
#endif

#include "sys_tree.h"


static void net__print_error(int log, const char *format_str)
{
#ifdef WIN32
	char *buf;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			NULL, WSAGetLastError(), LANG_NEUTRAL, &buf, 0, NULL);

	log__printf(NULL, log, format_str, buf);
	LocalFree(buf);
#else
	char buf[256];

	strerror_r(errno, buf, 256);
	log__printf(NULL, log, format_str, buf);
#endif
}


int net__socket_accept(struct mosquitto_db *db, mosq_sock_t listensock)
{
	int i;
	int j;
	mosq_sock_t new_sock = INVALID_SOCKET;
	struct mosquitto *new_context;
#ifdef WITH_TLS
	BIO *bio;
	int rc;
	char ebuf[256];
	unsigned long e;
#endif
#ifdef WITH_WRAP
	struct request_info wrap_req;
	char address[1024];
#endif

	new_sock = accept(listensock, NULL, 0);
	if(new_sock == INVALID_SOCKET) return -1;

	G_SOCKET_CONNECTIONS_INC();

	if(net__socket_nonblock(new_sock)){
		return INVALID_SOCKET;
	}

#ifdef WITH_WRAP
	/* Use tcpd / libwrap to determine whether a connection is allowed. */
	request_init(&wrap_req, RQ_FILE, new_sock, RQ_DAEMON, "mosquitto", 0);
	fromhost(&wrap_req);
	if(!hosts_access(&wrap_req)){
		/* Access is denied */
		if(!net__socket_get_address(new_sock, address, 1024)){
			log__printf(NULL, MOSQ_LOG_NOTICE, "Client connection from %s denied access by tcpd.", address);
		}
		COMPAT_CLOSE(new_sock);
		return -1;
	}
#endif

	if(db->config->set_tcp_nodelay){
		int flag = 1;
		if(setsockopt(new_sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int) != 0)){
			log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Unable to set TCP_NODELAY.");
		}
	}

	new_context = context__init(db, new_sock);
	if(!new_context){
		COMPAT_CLOSE(new_sock);
		return -1;
	}
	for(i=0; i<db->config->listener_count; i++){
		for(j=0; j<db->config->listeners[i].sock_count; j++){
			if(db->config->listeners[i].socks[j] == listensock){
				new_context->listener = &db->config->listeners[i];
				new_context->listener->client_count++;
				break;
			}
		}
	}
	if(!new_context->listener){
		context__cleanup(db, new_context, true);
		return -1;
	}

	if(new_context->listener->max_connections > 0 && new_context->listener->client_count > new_context->listener->max_connections){
		log__printf(NULL, MOSQ_LOG_NOTICE, "Client connection from %s denied: max_connections exceeded.", new_context->address);
		context__cleanup(db, new_context, true);
		return -1;
	}

#ifdef WITH_TLS
	/* TLS init */
	for(i=0; i<db->config->listener_count; i++){
		for(j=0; j<db->config->listeners[i].sock_count; j++){
			if(db->config->listeners[i].socks[j] == listensock){
				if(db->config->listeners[i].ssl_ctx){
					new_context->ssl = SSL_new(db->config->listeners[i].ssl_ctx);
					if(!new_context->ssl){
						context__cleanup(db, new_context, true);
						return -1;
					}
					SSL_set_ex_data(new_context->ssl, tls_ex_index_context, new_context);
					SSL_set_ex_data(new_context->ssl, tls_ex_index_listener, &db->config->listeners[i]);
					new_context->want_write = true;
					bio = BIO_new_socket(new_sock, BIO_NOCLOSE);
					SSL_set_bio(new_context->ssl, bio, bio);
					ERR_clear_error();
					rc = SSL_accept(new_context->ssl);
					if(rc != 1){
						rc = SSL_get_error(new_context->ssl, rc);
						if(rc == SSL_ERROR_WANT_READ){
							/* We always want to read. */
						}else if(rc == SSL_ERROR_WANT_WRITE){
							new_context->want_write = true;
						}else{
							e = ERR_get_error();
							while(e){
								log__printf(NULL, MOSQ_LOG_NOTICE,
										"Client connection from %s failed: %s.",
										new_context->address, ERR_error_string(e, ebuf));
								e = ERR_get_error();
							}
							context__cleanup(db, new_context, true);
							return -1;
						}
					}
				}
			}
		}
	}
#endif

	log__printf(NULL, MOSQ_LOG_NOTICE, "New connection from %s on port %d.", new_context->address, new_context->listener->port);

	return new_sock;
}

#ifdef WITH_TLS
static int client_certificate_verify(int preverify_ok, X509_STORE_CTX *ctx)
{
	/* Preverify should check expiry, revocation. */
	return preverify_ok;
}
#endif

#ifdef WITH_TLS_PSK
static unsigned int psk_server_callback(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len)
{
	struct mosquitto_db *db;
	struct mosquitto *context;
	struct mosquitto__listener *listener;
	char *psk_key = NULL;
	int len;
	const char *psk_hint;

	if(!identity) return 0;

	db = mosquitto__get_db();

	context = SSL_get_ex_data(ssl, tls_ex_index_context);
	if(!context) return 0;

	listener = SSL_get_ex_data(ssl, tls_ex_index_listener);
	if(!listener) return 0;

	psk_hint = listener->psk_hint;

	/* The hex to BN conversion results in the length halving, so we can pass
	 * max_psk_len*2 as the max hex key here. */
	psk_key = mosquitto__calloc(1, max_psk_len*2 + 1);
	if(!psk_key) return 0;

	if(mosquitto_psk_key_get(db, context, psk_hint, identity, psk_key, max_psk_len*2) != MOSQ_ERR_SUCCESS){
		mosquitto__free(psk_key);
		return 0;
	}

	len = mosquitto__hex2bin(psk_key, psk, max_psk_len);
	if (len < 0){
		mosquitto__free(psk_key);
		return 0;
	}

	if(listener->use_identity_as_username){
		context->username = mosquitto__strdup(identity);
		if(!context->username){
			mosquitto__free(psk_key);
			return 0;
		}
	}

	mosquitto__free(psk_key);
	return len;
}
#endif

#ifdef WITH_TLS
static int mosquitto__tls_server_ctx(struct mosquitto__listener *listener)
{
	char buf[256];
	int rc;


#if OPENSSL_VERSION_NUMBER < 0x10100000L
	listener->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
#else
	listener->ssl_ctx = SSL_CTX_new(TLS_server_method());
#endif

	if(!listener->ssl_ctx){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to create TLS context.");
		return 1;
	}

	if(listener->tls_version == NULL){
		SSL_CTX_set_options(listener->ssl_ctx, SSL_OP_NO_SSLv3);
	}else if(!strcmp(listener->tls_version, "tlsv1.2")){
		SSL_CTX_set_options(listener->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1);
	}else if(!strcmp(listener->tls_version, "tlsv1.1")){
		SSL_CTX_set_options(listener->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1);
	}else if(!strcmp(listener->tls_version, "tlsv1")){
		SSL_CTX_set_options(listener->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_1);
	}

#ifdef SSL_OP_NO_COMPRESSION
	/* Disable compression */
	SSL_CTX_set_options(listener->ssl_ctx, SSL_OP_NO_COMPRESSION);
#endif
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
	/* Server chooses cipher */
	SSL_CTX_set_options(listener->ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
#endif

#ifdef SSL_MODE_RELEASE_BUFFERS
	/* Use even less memory per SSL connection. */
	SSL_CTX_set_mode(listener->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

#ifdef WITH_EC
#if OPENSSL_VERSION_NUMBER >= 0x10002000L && OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_CTX_set_ecdh_auto(listener->ssl_ctx, 1);
#endif
#endif

	snprintf(buf, 256, "mosquitto-%d", listener->port);
	SSL_CTX_set_session_id_context(listener->ssl_ctx, (unsigned char *)buf, strlen(buf));

	if(listener->ciphers){
		rc = SSL_CTX_set_cipher_list(listener->ssl_ctx, listener->ciphers);
		if(rc == 0){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to set TLS ciphers. Check cipher list \"%s\".", listener->ciphers);
			return 1;
		}
	}else{
		rc = SSL_CTX_set_cipher_list(listener->ssl_ctx, "DEFAULT:!aNULL:!eNULL:!LOW:!EXPORT:!SSLv2:@STRENGTH");
		if(rc == 0){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to set TLS ciphers. Check cipher list \"%s\".", listener->ciphers);
			return 1;
		}
	}
	return MOSQ_ERR_SUCCESS;
}
#endif

/* Creates a socket and listens on port 'port'.
 * Returns 1 on failure
 * Returns 0 on success.
 */
int net__socket_listen(struct mosquitto__listener *listener)
{
	mosq_sock_t sock = INVALID_SOCKET;
	struct addrinfo hints;
	struct addrinfo *ainfo, *rp;
	char service[10];
#ifndef WIN32
	int ss_opt = 1;
#else
	char ss_opt = 1;
#endif
#ifdef WITH_TLS
	int rc;
	X509_STORE *store;
	X509_LOOKUP *lookup;
#endif

	if(!listener) return MOSQ_ERR_INVAL;

	snprintf(service, 10, "%d", listener->port);
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;

	if(getaddrinfo(listener->host, service, &hints, &ainfo)) return INVALID_SOCKET;

	listener->sock_count = 0;
	listener->socks = NULL;

	for(rp = ainfo; rp; rp = rp->ai_next){
		if(rp->ai_family == AF_INET){
			log__printf(NULL, MOSQ_LOG_INFO, "Opening ipv4 listen socket on port %d.", ntohs(((struct sockaddr_in *)rp->ai_addr)->sin_port));
		}else if(rp->ai_family == AF_INET6){
			log__printf(NULL, MOSQ_LOG_INFO, "Opening ipv6 listen socket on port %d.", ntohs(((struct sockaddr_in6 *)rp->ai_addr)->sin6_port));
		}else{
			continue;
		}

		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(sock == INVALID_SOCKET){
			net__print_error(MOSQ_LOG_WARNING, "Warning: %s");
			continue;
		}
		listener->sock_count++;
		listener->socks = mosquitto__realloc(listener->socks, sizeof(mosq_sock_t)*listener->sock_count);
		if(!listener->socks){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
		listener->socks[listener->sock_count-1] = sock;

#ifndef WIN32
		ss_opt = 1;
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &ss_opt, sizeof(ss_opt));
#endif
		ss_opt = 1;
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &ss_opt, sizeof(ss_opt));

		if(net__socket_nonblock(sock)){
			return 1;
		}

		if(bind(sock, rp->ai_addr, rp->ai_addrlen) == -1){
			net__print_error(MOSQ_LOG_ERR, "Error: %s");
			COMPAT_CLOSE(sock);
			return 1;
		}

		if(listen(sock, 100) == -1){
			net__print_error(MOSQ_LOG_ERR, "Error: %s");
			COMPAT_CLOSE(sock);
			return 1;
		}
	}
	freeaddrinfo(ainfo);

	/* We need to have at least one working socket. */
	if(listener->sock_count > 0){
#ifdef WITH_TLS
		if((listener->cafile || listener->capath) && listener->certfile && listener->keyfile){
			if(mosquitto__tls_server_ctx(listener)){
				COMPAT_CLOSE(sock);
				return 1;
			}

			rc = SSL_CTX_load_verify_locations(listener->ssl_ctx, listener->cafile, listener->capath);
			if(rc == 0){
				if(listener->cafile && listener->capath){
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load CA certificates. Check cafile \"%s\" and capath \"%s\".", listener->cafile, listener->capath);
				}else if(listener->cafile){
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load CA certificates. Check cafile \"%s\".", listener->cafile);
				}else{
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load CA certificates. Check capath \"%s\".", listener->capath);
				}
				COMPAT_CLOSE(sock);
				return 1;
			}
			/* FIXME user data? */
			if(listener->require_certificate){
				SSL_CTX_set_verify(listener->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, client_certificate_verify);
			}else{
				SSL_CTX_set_verify(listener->ssl_ctx, SSL_VERIFY_NONE, client_certificate_verify);
			}
			rc = SSL_CTX_use_certificate_chain_file(listener->ssl_ctx, listener->certfile);
			if(rc != 1){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load server certificate \"%s\". Check certfile.", listener->certfile);
				COMPAT_CLOSE(sock);
				return 1;
			}
			rc = SSL_CTX_use_PrivateKey_file(listener->ssl_ctx, listener->keyfile, SSL_FILETYPE_PEM);
			if(rc != 1){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load server key file \"%s\". Check keyfile.", listener->keyfile);
				COMPAT_CLOSE(sock);
				return 1;
			}
			rc = SSL_CTX_check_private_key(listener->ssl_ctx);
			if(rc != 1){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Server certificate/key are inconsistent.");
				COMPAT_CLOSE(sock);
				return 1;
			}
			/* Load CRLs if they exist. */
			if(listener->crlfile){
				store = SSL_CTX_get_cert_store(listener->ssl_ctx);
				if(!store){
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to obtain TLS store.");
					COMPAT_CLOSE(sock);
					return 1;
				}
				lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
				rc = X509_load_crl_file(lookup, listener->crlfile, X509_FILETYPE_PEM);
				if(rc != 1){
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load certificate revocation file \"%s\". Check crlfile.", listener->crlfile);
					COMPAT_CLOSE(sock);
					return 1;
				}
				X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
			}

#  ifdef WITH_TLS_PSK
		}else if(listener->psk_hint){
			if(tls_ex_index_context == -1){
				tls_ex_index_context = SSL_get_ex_new_index(0, "client context", NULL, NULL, NULL);
			}
			if(tls_ex_index_listener == -1){
				tls_ex_index_listener = SSL_get_ex_new_index(0, "listener", NULL, NULL, NULL);
			}

			if(mosquitto__tls_server_ctx(listener)){
				COMPAT_CLOSE(sock);
				return 1;
			}
			SSL_CTX_set_psk_server_callback(listener->ssl_ctx, psk_server_callback);
			if(listener->psk_hint){
				rc = SSL_CTX_use_psk_identity_hint(listener->ssl_ctx, listener->psk_hint);
				if(rc == 0){
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to set TLS PSK hint.");
					COMPAT_CLOSE(sock);
					return 1;
				}
			}
#  endif /* WITH_TLS_PSK */
		}
#endif /* WITH_TLS */
		return 0;
	}else{
		return 1;
	}
}

int net__socket_get_address(mosq_sock_t sock, char *buf, int len)
{
	struct sockaddr_storage addr;
	socklen_t addrlen;

	addrlen = sizeof(addr);
	if(!getpeername(sock, (struct sockaddr *)&addr, &addrlen)){
		if(addr.ss_family == AF_INET){
			if(inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr.s_addr, buf, len)){
				return 0;
			}
		}else if(addr.ss_family == AF_INET6){
			if(inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr.s6_addr, buf, len)){
				return 0;
			}
		}
	}
	return 1;
}
