/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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

#ifndef WIN32
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <net/if.h>
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

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#ifdef WITH_UNIX_SOCKETS
#  include "sys/stat.h"
#  include "sys/un.h"
#endif

#ifdef __QNX__
#include <net/netbyte.h>
#endif

#include "mosquitto_broker_internal.h"
#include "mqtt_protocol.h"
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

/* For EMFILE handling */
static mosq_sock_t spare_sock = INVALID_SOCKET;

void net__broker_init(void)
{
	spare_sock = socket(AF_INET, SOCK_STREAM, 0);
	net__init();
#ifdef WITH_TLS
	net__init_tls();
#endif
}


void net__broker_cleanup(void)
{
	if(spare_sock != INVALID_SOCKET){
		COMPAT_CLOSE(spare_sock);
		spare_sock = INVALID_SOCKET;
	}
	net__cleanup();
}


static void net__print_error(unsigned int log, const char *format_str)
{
	char *buf;

#ifdef WIN32
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			NULL, WSAGetLastError(), LANG_NEUTRAL, (LPTSTR)&buf, 0, NULL);

	log__printf(NULL, log, format_str, buf);
	LocalFree(buf);
#else
	buf = strerror(errno);
	log__printf(NULL, log, format_str, buf);
#endif
}


struct mosquitto *net__socket_accept(struct mosquitto__listener_sock *listensock)
{
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

	new_sock = accept(listensock->sock, NULL, 0);
	if(new_sock == INVALID_SOCKET){
#ifdef WIN32
		errno = WSAGetLastError();
		if(errno == WSAEMFILE){
#else
		if(errno == EMFILE || errno == ENFILE){
#endif
			/* Close the spare socket, which means we should be able to accept
			 * this connection. Accept it, then close it immediately and create
			 * a new spare_sock. This prevents the situation of ever properly
			 * running out of sockets.
			 * It would be nice to send a "server not available" connack here,
			 * but there are lots of reasons why this would be tricky (TLS
			 * being the big one). */
			COMPAT_CLOSE(spare_sock);
			new_sock = accept(listensock->sock, NULL, 0);
			if(new_sock != INVALID_SOCKET){
				COMPAT_CLOSE(new_sock);
			}
			spare_sock = socket(AF_INET, SOCK_STREAM, 0);
			log__printf(NULL, MOSQ_LOG_WARNING,
					"Unable to accept new connection, system socket count has been exceeded. Try increasing \"ulimit -n\" or equivalent.");
		}
		return NULL;
	}

	G_SOCKET_CONNECTIONS_INC();

	if(net__socket_nonblock(&new_sock)){
		return NULL;
	}

#ifdef WITH_WRAP
	/* Use tcpd / libwrap to determine whether a connection is allowed. */
	request_init(&wrap_req, RQ_FILE, new_sock, RQ_DAEMON, "mosquitto", 0);
	fromhost(&wrap_req);
	if(!hosts_access(&wrap_req)){
		/* Access is denied */
		if(db.config->connection_messages == true){
			if(!net__socket_get_address(new_sock, address, 1024, NULL)){
				log__printf(NULL, MOSQ_LOG_NOTICE, "Client connection from %s denied access by tcpd.", address);
			}
		}
		COMPAT_CLOSE(new_sock);
		return NULL;
	}
#endif

	if(db.config->set_tcp_nodelay){
		int flag = 1;
#ifdef WIN32
			if (setsockopt(new_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int)) != 0) {
#else
		if(setsockopt(new_sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int)) != 0){
#endif
			log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Unable to set TCP_NODELAY.");
		}
	}

	new_context = context__init(new_sock);
	if(!new_context){
		COMPAT_CLOSE(new_sock);
		return NULL;
	}
	new_context->listener = listensock->listener;
	if(!new_context->listener){
		context__cleanup(new_context, true);
		return NULL;
	}
	new_context->listener->client_count++;

	if(new_context->listener->max_connections > 0 && new_context->listener->client_count > new_context->listener->max_connections){
		if(db.config->connection_messages == true){
			log__printf(NULL, MOSQ_LOG_NOTICE, "Client connection from %s denied: max_connections exceeded.", new_context->address);
		}
		context__cleanup(new_context, true);
		return NULL;
	}

#ifdef WITH_TLS
	/* TLS init */
	if(new_context->listener->ssl_ctx){
		new_context->ssl = SSL_new(new_context->listener->ssl_ctx);
		if(!new_context->ssl){
			context__cleanup(new_context, true);
			return NULL;
		}
		SSL_set_ex_data(new_context->ssl, tls_ex_index_context, new_context);
		SSL_set_ex_data(new_context->ssl, tls_ex_index_listener, new_context->listener);
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
				if(db.config->connection_messages == true){
					e = ERR_get_error();
					while(e){
						log__printf(NULL, MOSQ_LOG_NOTICE,
								"Client connection from %s failed: %s.",
								new_context->address, ERR_error_string(e, ebuf));
						e = ERR_get_error();
					}
				}
				context__cleanup(new_context, true);
				return NULL;
			}
		}
	}
#endif

	if(db.config->connection_messages == true){
		log__printf(NULL, MOSQ_LOG_NOTICE, "New connection from %s:%d on port %d.",
				new_context->address, new_context->remote_port, new_context->listener->port);
	}

	return new_context;
}

#ifdef WITH_TLS
static int client_certificate_verify(int preverify_ok, X509_STORE_CTX *ctx)
{
	UNUSED(ctx);

	/* Preverify should check expiry, revocation. */
	return preverify_ok;
}
#endif

#ifdef FINAL_WITH_TLS_PSK
static unsigned int psk_server_callback(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len)
{
	struct mosquitto *context;
	struct mosquitto__listener *listener;
	char *psk_key = NULL;
	int len;
	const char *psk_hint;

	if(!identity) return 0;

	context = SSL_get_ex_data(ssl, tls_ex_index_context);
	if(!context) return 0;

	listener = SSL_get_ex_data(ssl, tls_ex_index_listener);
	if(!listener) return 0;

	psk_hint = listener->psk_hint;

	/* The hex to BN conversion results in the length halving, so we can pass
	 * max_psk_len*2 as the max hex key here. */
	psk_key = mosquitto__calloc(1, (size_t)max_psk_len*2 + 1);
	if(!psk_key) return 0;

	if(mosquitto_psk_key_get(context, psk_hint, identity, psk_key, (int)max_psk_len*2) != MOSQ_ERR_SUCCESS){
		mosquitto__free(psk_key);
		return 0;
	}

	len = mosquitto__hex2bin(psk_key, psk, (int)max_psk_len);
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
	return (unsigned int)len;
}
#endif

#ifdef WITH_TLS
int net__tls_server_ctx(struct mosquitto__listener *listener)
{
	char buf[256];
	int rc;
	FILE *dhparamfile;
	DH *dhparam = NULL;

	if(listener->ssl_ctx){
		SSL_CTX_free(listener->ssl_ctx);
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	listener->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
#else
	listener->ssl_ctx = SSL_CTX_new(TLS_server_method());
#endif

	if(!listener->ssl_ctx){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to create TLS context.");
		return MOSQ_ERR_TLS;
	}

	if(listener->tls_version == NULL){
		SSL_CTX_set_options(listener->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
#ifdef SSL_OP_NO_TLSv1_3
	}else if(!strcmp(listener->tls_version, "tlsv1.3")){
		SSL_CTX_set_options(listener->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2);
	}else if(!strcmp(listener->tls_version, "tlsv1.2")){
		SSL_CTX_set_options(listener->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_3);
	}else if(!strcmp(listener->tls_version, "tlsv1.1")){
		SSL_CTX_set_options(listener->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_3);
#else
	}else if(!strcmp(listener->tls_version, "tlsv1.2")){
		SSL_CTX_set_options(listener->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
	}else if(!strcmp(listener->tls_version, "tlsv1.1")){
		SSL_CTX_set_options(listener->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_2);
#endif
	}else{
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unsupported tls_version \"%s\".", listener->tls_version);
		return MOSQ_ERR_TLS;
	}
	/* Use a new key when using temporary/ephemeral DH parameters.
	 * This shouldn't be necessary, but we can't guarantee that `dhparam` has
	 * been generated using strong primes.
	 */
	SSL_CTX_set_options(listener->ssl_ctx, SSL_OP_SINGLE_DH_USE);

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
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	SSL_CTX_set_dh_auto(listener->ssl_ctx, 1);
#endif

#ifdef SSL_OP_NO_RENEGOTIATION
	SSL_CTX_set_options(listener->ssl_ctx, SSL_OP_NO_RENEGOTIATION);
#endif

	snprintf(buf, 256, "mosquitto-%d", listener->port);
	SSL_CTX_set_session_id_context(listener->ssl_ctx, (unsigned char *)buf, (unsigned int)strlen(buf));

	if(listener->ciphers){
		rc = SSL_CTX_set_cipher_list(listener->ssl_ctx, listener->ciphers);
		if(rc == 0){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to set TLS ciphers. Check cipher list \"%s\".", listener->ciphers);
			return MOSQ_ERR_TLS;
		}
	}else{
		rc = SSL_CTX_set_cipher_list(listener->ssl_ctx, "DEFAULT:!aNULL:!eNULL:!LOW:!EXPORT:!SSLv2:@STRENGTH");
		if(rc == 0){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to set TLS ciphers. Check cipher list \"%s\".", listener->ciphers);
			return MOSQ_ERR_TLS;
		}
	}
#if OPENSSL_VERSION_NUMBER >= 0x10101000 && !defined(LIBRESSL_VERSION_NUMBER)
	if(listener->ciphers_tls13){
		rc = SSL_CTX_set_ciphersuites(listener->ssl_ctx, listener->ciphers_tls13);
		if(rc == 0){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to set TLS 1.3 ciphersuites. Check cipher_tls13 list \"%s\".", listener->ciphers_tls13);
			return MOSQ_ERR_TLS;
		}
	}
#endif

	if(listener->dhparamfile){
		dhparamfile = fopen(listener->dhparamfile, "r");
		if(!dhparamfile){
			log__printf(NULL, MOSQ_LOG_ERR, "Error loading dhparamfile \"%s\".", listener->dhparamfile);
			return MOSQ_ERR_TLS;
		}
		dhparam = PEM_read_DHparams(dhparamfile, NULL, NULL, NULL);
		fclose(dhparamfile);

		if(dhparam == NULL || SSL_CTX_set_tmp_dh(listener->ssl_ctx, dhparam) != 1){
			log__printf(NULL, MOSQ_LOG_ERR, "Error loading dhparamfile \"%s\".", listener->dhparamfile);
			net__print_ssl_error(NULL);
			return MOSQ_ERR_TLS;
		}
	}
	return MOSQ_ERR_SUCCESS;
}
#endif


int net__load_crl_file(struct mosquitto__listener *listener)
{
#ifdef WITH_TLS
	X509_STORE *store;
	X509_LOOKUP *lookup;
	int rc;

	store = SSL_CTX_get_cert_store(listener->ssl_ctx);
	if(!store){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to obtain TLS store.");
		net__print_error(MOSQ_LOG_ERR, "Error: %s");
		return MOSQ_ERR_TLS;
	}
	lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
	rc = X509_load_crl_file(lookup, listener->crlfile, X509_FILETYPE_PEM);
	if(rc < 1){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load certificate revocation file \"%s\". Check crlfile.", listener->crlfile);
		net__print_error(MOSQ_LOG_ERR, "Error: %s");
		net__print_ssl_error(NULL);
		return MOSQ_ERR_TLS;
	}
	X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
#endif

	return MOSQ_ERR_SUCCESS;
}


int net__load_certificates(struct mosquitto__listener *listener)
{
#ifdef WITH_TLS
	ENGINE *engine = NULL;
#  if !defined(OPENSSL_NO_ENGINE)
	UI_METHOD *ui_method;
	EVP_PKEY *pkey;
#  endif
	int rc;

	if(listener->require_certificate){
		SSL_CTX_set_verify(listener->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, client_certificate_verify);
	}else{
		SSL_CTX_set_verify(listener->ssl_ctx, SSL_VERIFY_NONE, client_certificate_verify);
	}
	rc = SSL_CTX_use_certificate_chain_file(listener->ssl_ctx, listener->certfile);
	if(rc != 1){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load server certificate \"%s\". Check certfile.", listener->certfile);
		net__print_ssl_error(NULL);
#if !defined(OPENSSL_NO_ENGINE)
		ENGINE_FINISH(engine);
#endif
		return MOSQ_ERR_TLS;
	}
	if(listener->tls_engine && listener->tls_keyform == mosq_k_engine){
#if !defined(OPENSSL_NO_ENGINE)
		ui_method = net__get_ui_method();
		if(listener->tls_engine_kpass_sha1){
			if(!ENGINE_ctrl_cmd(engine, ENGINE_SECRET_MODE, ENGINE_SECRET_MODE_SHA, NULL, NULL, 0)){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to set engine secret mode sha");
				net__print_ssl_error(NULL);
				ENGINE_FINISH(engine);
				return MOSQ_ERR_TLS;
			}
			if(!ENGINE_ctrl_cmd(engine, ENGINE_PIN, 0, listener->tls_engine_kpass_sha1, NULL, 0)){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to set engine pin");
				net__print_ssl_error(NULL);
				ENGINE_FINISH(engine);
				return MOSQ_ERR_TLS;
			}
			ui_method = NULL;
		}
		pkey = ENGINE_load_private_key(engine, listener->keyfile, ui_method, NULL);
		if(!pkey){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load engine private key file \"%s\".", listener->keyfile);
			net__print_ssl_error(NULL);
			ENGINE_FINISH(engine);
			return MOSQ_ERR_TLS;
		}
		if(SSL_CTX_use_PrivateKey(listener->ssl_ctx, pkey) <= 0){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to use engine private key file \"%s\".", listener->keyfile);
			net__print_ssl_error(NULL);
			ENGINE_FINISH(engine);
			return MOSQ_ERR_TLS;
		}
#endif
	}else{
		rc = SSL_CTX_use_PrivateKey_file(listener->ssl_ctx, listener->keyfile, SSL_FILETYPE_PEM);
		if(rc != 1){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load server key file \"%s\". Check keyfile.", listener->keyfile);
			net__print_ssl_error(NULL);
#if !defined(OPENSSL_NO_ENGINE)
			ENGINE_FINISH(engine);
#endif
			return MOSQ_ERR_TLS;
		}
	}
	rc = SSL_CTX_check_private_key(listener->ssl_ctx);
	if(rc != 1){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Server certificate/key are inconsistent.");
		net__print_ssl_error(NULL);
#if !defined(OPENSSL_NO_ENGINE)
		ENGINE_FINISH(engine);
#endif
		return MOSQ_ERR_TLS;
	}
	/* Load CRLs if they exist. */
	if(listener->crlfile){
		rc = net__load_crl_file(listener);
		if(rc){
#if !defined(OPENSSL_NO_ENGINE)
			ENGINE_FINISH(engine);
#endif
			return rc;
		}
	}
#endif
	return MOSQ_ERR_SUCCESS;
}


int net__tls_load_verify(struct mosquitto__listener *listener)
{
#ifdef WITH_TLS
	ENGINE *engine = NULL;
	int rc;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if(listener->cafile || listener->capath){
		rc = SSL_CTX_load_verify_locations(listener->ssl_ctx, listener->cafile, listener->capath);
		if(rc == 0){
			if(listener->cafile && listener->capath){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load CA certificates. Check cafile \"%s\" and capath \"%s\".", listener->cafile, listener->capath);
			}else if(listener->cafile){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load CA certificates. Check cafile \"%s\".", listener->cafile);
			}else{
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load CA certificates. Check capath \"%s\".", listener->capath);
			}
		}
	}
#else
	if(listener->cafile){
		rc = SSL_CTX_load_verify_file(listener->ssl_ctx, listener->cafile);
		if(rc == 0){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load CA certificates. Check cafile \"%s\".", listener->cafile);
			net__print_ssl_error(NULL);
			return MOSQ_ERR_TLS;
		}
	}
	if(listener->capath){
		rc = SSL_CTX_load_verify_dir(listener->ssl_ctx, listener->capath);
		if(rc == 0){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load CA certificates. Check capath \"%s\".", listener->capath);
			net__print_ssl_error(NULL);
			return MOSQ_ERR_TLS;
		}
	}
#endif

	if(listener->tls_engine){
#if !defined(OPENSSL_NO_ENGINE)
		engine = ENGINE_by_id(listener->tls_engine);
		if(!engine){
			log__printf(NULL, MOSQ_LOG_ERR, "Error loading %s engine\n", listener->tls_engine);
			net__print_ssl_error(NULL);
			return MOSQ_ERR_TLS;
		}
		if(!ENGINE_init(engine)){
			log__printf(NULL, MOSQ_LOG_ERR, "Failed engine initialisation\n");
			net__print_ssl_error(NULL);
			ENGINE_free(engine);
			return MOSQ_ERR_TLS;
		}
		ENGINE_set_default(engine, ENGINE_METHOD_ALL);
		ENGINE_free(engine); /* release the structural reference from ENGINE_by_id() */
#endif
	}
#endif
	return net__load_certificates(listener);
}


static int net__socket_listen_tcp(struct mosquitto__listener *listener)
{
	mosq_sock_t sock = INVALID_SOCKET;
	struct addrinfo hints;
	struct addrinfo *ainfo, *rp;
	char service[10];
	int rc;
	int ss_opt = 1;
#ifdef SO_BINDTODEVICE
	struct ifreq ifr;
#endif

	if(!listener) return MOSQ_ERR_INVAL;

	snprintf(service, 10, "%d", listener->port);
	memset(&hints, 0, sizeof(struct addrinfo));
	if(listener->socket_domain){
		hints.ai_family = listener->socket_domain;
	}else{
		hints.ai_family = AF_UNSPEC;
	}
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;

	rc = getaddrinfo(listener->host, service, &hints, &ainfo);
	if (rc){
		log__printf(NULL, MOSQ_LOG_ERR, "Error creating listener: %s.", gai_strerror(rc));
		return INVALID_SOCKET;
	}

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
		listener->socks = mosquitto__realloc(listener->socks, sizeof(mosq_sock_t)*(size_t)listener->sock_count);
		if(!listener->socks){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			freeaddrinfo(ainfo);
			COMPAT_CLOSE(sock);
			return MOSQ_ERR_NOMEM;
		}
		listener->socks[listener->sock_count-1] = sock;

#ifndef WIN32
		ss_opt = 1;
		/* Unimportant if this fails */
		(void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &ss_opt, sizeof(ss_opt));
#endif
#ifdef IPV6_V6ONLY
		ss_opt = 1;
		(void)setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &ss_opt, sizeof(ss_opt));
#endif

		if(net__socket_nonblock(&sock)){
			freeaddrinfo(ainfo);
			mosquitto__free(listener->socks);
			return 1;
		}

#ifdef SO_BINDTODEVICE
		if(listener->bind_interface){
			memset(&ifr, 0, sizeof(ifr));
			strncpy(ifr.ifr_name, listener->bind_interface, sizeof(ifr.ifr_name)-1);
			ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';
			log__printf(NULL, MOSQ_LOG_INFO, "Binding listener to interface \"%s\".", ifr.ifr_name);
			if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
				net__print_error(MOSQ_LOG_ERR, "Error: %s");
				COMPAT_CLOSE(sock);
				freeaddrinfo(ainfo);
				mosquitto__free(listener->socks);
				return 1;
			}
		}
#endif

		if(bind(sock, rp->ai_addr, rp->ai_addrlen) == -1){
			net__print_error(MOSQ_LOG_ERR, "Error: %s");
			COMPAT_CLOSE(sock);
			freeaddrinfo(ainfo);
			mosquitto__free(listener->socks);
			return 1;
		}

		if(listen(sock, 100) == -1){
			net__print_error(MOSQ_LOG_ERR, "Error: %s");
			freeaddrinfo(ainfo);
			COMPAT_CLOSE(sock);
			mosquitto__free(listener->socks);
			return 1;
		}
	}
	freeaddrinfo(ainfo);

	return 0;
}


#ifdef WITH_UNIX_SOCKETS
static int net__socket_listen_unix(struct mosquitto__listener *listener)
{
	struct sockaddr_un addr;
	int sock;
	int rc;
	mode_t old_mask;

	if(listener->unix_socket_path == NULL){
		return MOSQ_ERR_INVAL;
	}
	if(strlen(listener->unix_socket_path) > sizeof(addr.sun_path)-1){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Path to unix socket is too long \"%s\".", listener->unix_socket_path);
		return MOSQ_ERR_INVAL;
	}

	unlink(listener->unix_socket_path);
	log__printf(NULL, MOSQ_LOG_INFO, "Opening unix listen socket on path %s.", listener->unix_socket_path);
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, listener->unix_socket_path, sizeof(addr.sun_path)-1);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if(sock == INVALID_SOCKET){
		net__print_error(MOSQ_LOG_ERR, "Error creating unix socket: %s");
		return 1;
	}
	listener->sock_count++;
	listener->socks = mosquitto__realloc(listener->socks, sizeof(mosq_sock_t)*(size_t)listener->sock_count);
	if(!listener->socks){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		COMPAT_CLOSE(sock);
		return MOSQ_ERR_NOMEM;
	}
	listener->socks[listener->sock_count-1] = sock;


	old_mask = umask(0007);
	rc = bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
	umask(old_mask);

	if(rc == -1){
		net__print_error(MOSQ_LOG_ERR, "Error binding unix socket: %s");
		return 1;
	}

	if(listen(sock, 10) == -1){
		net__print_error(MOSQ_LOG_ERR, "Error listening to unix socket: %s");
		return 1;
	}

	if(net__socket_nonblock(&sock)){
		return 1;
	}

	return 0;
}
#endif


/* Creates a socket and listens on port 'port'.
 * Returns 1 on failure
 * Returns 0 on success.
 */
int net__socket_listen(struct mosquitto__listener *listener)
{
	int rc;

	if(!listener) return MOSQ_ERR_INVAL;

#ifdef WITH_UNIX_SOCKETS
	if(listener->port == 0 && listener->unix_socket_path != NULL){
		rc = net__socket_listen_unix(listener);
	}else
#endif
	{
		rc = net__socket_listen_tcp(listener);
	}
	if(rc) return rc;

	/* We need to have at least one working socket. */
	if(listener->sock_count > 0){
#ifdef WITH_TLS
		if(listener->certfile && listener->keyfile){
			if(net__tls_server_ctx(listener)){
				return 1;
			}

			if(net__tls_load_verify(listener)){
				return 1;
			}
#  ifdef FINAL_WITH_TLS_PSK
		}else if(listener->psk_hint){
			if(tls_ex_index_context == -1){
				tls_ex_index_context = SSL_get_ex_new_index(0, "client context", NULL, NULL, NULL);
			}
			if(tls_ex_index_listener == -1){
				tls_ex_index_listener = SSL_get_ex_new_index(0, "listener", NULL, NULL, NULL);
			}

			if(net__tls_server_ctx(listener)){
				return 1;
			}
			SSL_CTX_set_psk_server_callback(listener->ssl_ctx, psk_server_callback);
			if(listener->psk_hint){
				rc = SSL_CTX_use_psk_identity_hint(listener->ssl_ctx, listener->psk_hint);
				if(rc == 0){
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to set TLS PSK hint.");
					net__print_ssl_error(NULL);
					return 1;
				}
			}
#  endif /* FINAL_WITH_TLS_PSK */
		}
#endif /* WITH_TLS */
		return 0;
	}else{
		return 1;
	}
}

int net__socket_get_address(mosq_sock_t sock, char *buf, size_t len, uint16_t *remote_port)
{
	struct sockaddr_storage addr;
	socklen_t addrlen;

	memset(&addr, 0, sizeof(struct sockaddr_storage));
	addrlen = sizeof(addr);
	if(!getpeername(sock, (struct sockaddr *)&addr, &addrlen)){
		if(addr.ss_family == AF_INET){
			if(remote_port){
				*remote_port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
			}
			if(inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr.s_addr, buf, (socklen_t)len)){
				return 0;
			}
		}else if(addr.ss_family == AF_INET6){
			if(remote_port){
				*remote_port = ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
			}
			if(inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr.s6_addr, buf, (socklen_t)len)){
				return 0;
			}
#ifdef WITH_UNIX_SOCKETS
		}else if(addr.ss_family == AF_UNIX){
			struct sockaddr_un un;
			addrlen = sizeof(struct sockaddr_un);
			if(!getsockname(sock, (struct sockaddr *)&un, &addrlen)){
				snprintf(buf, len, "%s", un.sun_path);
			}else{
				snprintf(buf, len, "unix-socket");
			}
			return 0;
#endif
		}
	}
	return 1;
}
