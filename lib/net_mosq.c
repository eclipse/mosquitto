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

#define _GNU_SOURCE
#include "config.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#define _GNU_SOURCE
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifdef __ANDROID__
#include <linux/in.h>
#include <linux/in6.h>
#include <sys/endian.h>
#endif

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#ifdef WITH_UNIX_SOCKETS
#  include <sys/un.h>
#endif

#ifdef __QNX__
#include <net/netbyte.h>
#endif

#ifdef WITH_TLS
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ui.h>
#include <tls_mosq.h>
#endif

#ifdef WITH_BROKER
#  include "mosquitto_broker_internal.h"
#  ifdef WITH_WEBSOCKETS
#    include <libwebsockets.h>
#  endif
#else
#  include "read_handle.h"
#endif

#include "logging_mosq.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "net_mosq.h"
#include "time_mosq.h"
#include "util_mosq.h"

#ifdef WITH_TLS
int tls_ex_index_mosq = -1;
UI_METHOD *_ui_method = NULL;

static bool is_tls_initialized = false;

/* Functions taken from OpenSSL s_server/s_client */
static int ui_open(UI *ui)
{
	return UI_method_get_opener(UI_OpenSSL())(ui);
}

static int ui_read(UI *ui, UI_STRING *uis)
{
	return UI_method_get_reader(UI_OpenSSL())(ui, uis);
}

static int ui_write(UI *ui, UI_STRING *uis)
{
	return UI_method_get_writer(UI_OpenSSL())(ui, uis);
}

static int ui_close(UI *ui)
{
	return UI_method_get_closer(UI_OpenSSL())(ui);
}

static void setup_ui_method(void)
{
	_ui_method = UI_create_method("OpenSSL application user interface");
	UI_method_set_opener(_ui_method, ui_open);
	UI_method_set_reader(_ui_method, ui_read);
	UI_method_set_writer(_ui_method, ui_write);
	UI_method_set_closer(_ui_method, ui_close);
}

static void cleanup_ui_method(void)
{
	if(_ui_method){
		UI_destroy_method(_ui_method);
		_ui_method = NULL;
	}
}

UI_METHOD *net__get_ui_method(void)
{
	return _ui_method;
}

#endif

int net__init(void)
{
#ifdef WIN32
	WSADATA wsaData;
	if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0){
		return MOSQ_ERR_UNKNOWN;
	}
#endif

#ifdef WITH_SRV
	ares_library_init(ARES_LIB_INIT_ALL);
#endif

	return MOSQ_ERR_SUCCESS;
}

void net__cleanup(void)
{
#ifdef WITH_TLS
#  if OPENSSL_VERSION_NUMBER < 0x10100000L
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	ERR_remove_thread_state(NULL);
	EVP_cleanup();

#    if !defined(OPENSSL_NO_ENGINE)
	ENGINE_cleanup();
#    endif
	is_tls_initialized = false;
#  endif

	CONF_modules_unload(1);
	cleanup_ui_method();
#endif

#ifdef WITH_SRV
	ares_library_cleanup();
#endif

#ifdef WIN32
	WSACleanup();
#endif
}

#ifdef WITH_TLS
void net__init_tls(void)
{
	if(is_tls_initialized) return;

#  if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
#  else
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
			| OPENSSL_INIT_ADD_ALL_DIGESTS \
			| OPENSSL_INIT_LOAD_CONFIG, NULL);
#  endif
#if !defined(OPENSSL_NO_ENGINE)
	ENGINE_load_builtin_engines();
#endif
	setup_ui_method();
	if(tls_ex_index_mosq == -1){
		tls_ex_index_mosq = SSL_get_ex_new_index(0, "client context", NULL, NULL, NULL);
	}

	is_tls_initialized = true;
}
#endif

/* Close a socket associated with a context and set it to -1.
 * Returns 1 on failure (context is NULL)
 * Returns 0 on success.
 */
int net__socket_close(struct mosquitto *mosq)
{
	int rc = 0;
#ifdef WITH_BROKER
	struct mosquitto *mosq_found;
#endif

	assert(mosq);
#ifdef WITH_TLS
#ifdef WITH_WEBSOCKETS
	if(!mosq->wsi)
#endif
	{
		if(mosq->ssl){
			if(!SSL_in_init(mosq->ssl)){
				SSL_shutdown(mosq->ssl);
			}
			SSL_free(mosq->ssl);
			mosq->ssl = NULL;
		}
	}
#endif

#ifdef WITH_WEBSOCKETS
	if(mosq->wsi)
	{
		if(mosq->state != mosq_cs_disconnecting){
			mosquitto__set_state(mosq, mosq_cs_disconnect_ws);
		}
		lws_callback_on_writable(mosq->wsi);
	}else
#endif
	{
		if(mosq->sock != INVALID_SOCKET){
#ifdef WITH_BROKER
			HASH_FIND(hh_sock, db.contexts_by_sock, &mosq->sock, sizeof(mosq->sock), mosq_found);
			if(mosq_found){
				HASH_DELETE(hh_sock, db.contexts_by_sock, mosq_found);
			}
#endif
			rc = COMPAT_CLOSE(mosq->sock);
			mosq->sock = INVALID_SOCKET;
		}
	}

#ifdef WITH_BROKER
	if(mosq->listener){
		mosq->listener->client_count--;
	}
#endif

	return rc;
}


#ifdef FINAL_WITH_TLS_PSK
static unsigned int psk_client_callback(SSL *ssl, const char *hint,
		char *identity, unsigned int max_identity_len,
		unsigned char *psk, unsigned int max_psk_len)
{
	struct mosquitto *mosq;
	int len;

	UNUSED(hint);

	mosq = SSL_get_ex_data(ssl, tls_ex_index_mosq);
	if(!mosq) return 0;

	snprintf(identity, max_identity_len, "%s", mosq->tls_psk_identity);

	len = mosquitto__hex2bin(mosq->tls_psk, psk, (int)max_psk_len);
	if (len < 0) return 0;
	return (unsigned int)len;
}
#endif

#if defined(WITH_BROKER) && defined(__GLIBC__) && defined(WITH_ADNS)
/* Async connect, part 1 (dns lookup) */
int net__try_connect_step1(struct mosquitto *mosq, const char *host)
{
	int s;
	void *sevp = NULL;
	struct addrinfo *hints;

	if(mosq->adns){
		gai_cancel(mosq->adns);
		mosquitto__free((struct addrinfo *)mosq->adns->ar_request);
		mosquitto__free(mosq->adns);
	}
	mosq->adns = mosquitto__calloc(1, sizeof(struct gaicb));
	if(!mosq->adns){
		return MOSQ_ERR_NOMEM;
	}

	hints = mosquitto__calloc(1, sizeof(struct addrinfo));
	if(!hints){
		mosquitto__free(mosq->adns);
		mosq->adns = NULL;
		return MOSQ_ERR_NOMEM;
	}

	hints->ai_family = AF_UNSPEC;
	hints->ai_socktype = SOCK_STREAM;

	mosq->adns->ar_name = host;
	mosq->adns->ar_request = hints;

	s = getaddrinfo_a(GAI_NOWAIT, &mosq->adns, 1, sevp);
	if(s){
		errno = s;
		if(mosq->adns){
			mosquitto__free((struct addrinfo *)mosq->adns->ar_request);
			mosquitto__free(mosq->adns);
			mosq->adns = NULL;
		}
		return MOSQ_ERR_EAI;
	}

	return MOSQ_ERR_SUCCESS;
}

/* Async connect part 2, the connection. */
int net__try_connect_step2(struct mosquitto *mosq, uint16_t port, mosq_sock_t *sock)
{
	struct addrinfo *ainfo, *rp;
	int rc;

	ainfo = mosq->adns->ar_result;

	for(rp = ainfo; rp != NULL; rp = rp->ai_next){
		*sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(*sock == INVALID_SOCKET) continue;

		if(rp->ai_family == AF_INET){
			((struct sockaddr_in *)rp->ai_addr)->sin_port = htons(port);
		}else if(rp->ai_family == AF_INET6){
			((struct sockaddr_in6 *)rp->ai_addr)->sin6_port = htons(port);
		}else{
			COMPAT_CLOSE(*sock);
			*sock = INVALID_SOCKET;
			continue;
		}

		/* Set non-blocking */
		if(net__socket_nonblock(sock)){
			continue;
		}

		rc = connect(*sock, rp->ai_addr, rp->ai_addrlen);
#ifdef WIN32
		errno = WSAGetLastError();
#endif
		if(rc == 0 || errno == EINPROGRESS || errno == COMPAT_EWOULDBLOCK){
			if(rc < 0 && (errno == EINPROGRESS || errno == COMPAT_EWOULDBLOCK)){
				rc = MOSQ_ERR_CONN_PENDING;
			}

			/* Set non-blocking */
			if(net__socket_nonblock(sock)){
				continue;
			}
			break;
		}

		COMPAT_CLOSE(*sock);
		*sock = INVALID_SOCKET;
	}
	freeaddrinfo(mosq->adns->ar_result);
	mosq->adns->ar_result = NULL;

	mosquitto__free((struct addrinfo *)mosq->adns->ar_request);
	mosquitto__free(mosq->adns);
	mosq->adns = NULL;

	if(!rp){
		return MOSQ_ERR_ERRNO;
	}

	return rc;
}

#endif


static int net__try_connect_tcp(const char *host, uint16_t port, mosq_sock_t *sock, const char *bind_address, bool blocking)
{
	struct addrinfo hints;
	struct addrinfo *ainfo, *rp;
	struct addrinfo *ainfo_bind, *rp_bind;
	int s;
	int rc = MOSQ_ERR_SUCCESS;
#ifdef WIN32
	uint32_t val = 1;
#endif

	ainfo_bind = NULL;

	*sock = INVALID_SOCKET;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	s = getaddrinfo(host, NULL, &hints, &ainfo);
	if(s){
		errno = s;
		return MOSQ_ERR_EAI;
	}

	if(bind_address){
		s = getaddrinfo(bind_address, NULL, &hints, &ainfo_bind);
		if(s){
			freeaddrinfo(ainfo);
			errno = s;
			return MOSQ_ERR_EAI;
		}
	}

	for(rp = ainfo; rp != NULL; rp = rp->ai_next){
		*sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(*sock == INVALID_SOCKET) continue;

		if(rp->ai_family == AF_INET){
			((struct sockaddr_in *)rp->ai_addr)->sin_port = htons(port);
		}else if(rp->ai_family == AF_INET6){
			((struct sockaddr_in6 *)rp->ai_addr)->sin6_port = htons(port);
		}else{
			COMPAT_CLOSE(*sock);
			*sock = INVALID_SOCKET;
			continue;
		}

		if(bind_address){
			for(rp_bind = ainfo_bind; rp_bind != NULL; rp_bind = rp_bind->ai_next){
				if(bind(*sock, rp_bind->ai_addr, rp_bind->ai_addrlen) == 0){
					break;
				}
			}
			if(!rp_bind){
				COMPAT_CLOSE(*sock);
				*sock = INVALID_SOCKET;
				continue;
			}
		}

		if(!blocking){
			/* Set non-blocking */
			if(net__socket_nonblock(sock)){
				continue;
			}
		}

		rc = connect(*sock, rp->ai_addr, rp->ai_addrlen);
#ifdef WIN32
		errno = WSAGetLastError();
#endif
		if(rc == 0 || errno == EINPROGRESS || errno == COMPAT_EWOULDBLOCK){
			if(rc < 0 && (errno == EINPROGRESS || errno == COMPAT_EWOULDBLOCK)){
				rc = MOSQ_ERR_CONN_PENDING;
			}

			if(blocking){
				/* Set non-blocking */
				if(net__socket_nonblock(sock)){
					continue;
				}
			}
			break;
		}

		COMPAT_CLOSE(*sock);
		*sock = INVALID_SOCKET;
	}
	freeaddrinfo(ainfo);
	if(bind_address){
		freeaddrinfo(ainfo_bind);
	}
	if(!rp){
		return MOSQ_ERR_ERRNO;
	}
	return rc;
}


#ifdef WITH_UNIX_SOCKETS
static int net__try_connect_unix(const char *host, mosq_sock_t *sock)
{
	struct sockaddr_un addr;
	int s;
	int rc;

	if(host == NULL || strlen(host) == 0 || strlen(host) > sizeof(addr.sun_path)-1){
		return MOSQ_ERR_INVAL;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, host, sizeof(addr.sun_path)-1);

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if(s < 0){
		return MOSQ_ERR_ERRNO;
	}
	rc = net__socket_nonblock(&s);
	if(rc) return rc;

	rc = connect(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
	if(rc < 0){
		close(s);
		return MOSQ_ERR_ERRNO;
	}

	*sock = s;

	return 0;
}
#endif


int net__try_connect(const char *host, uint16_t port, mosq_sock_t *sock, const char *bind_address, bool blocking)
{
	if(port == 0){
#ifdef WITH_UNIX_SOCKETS
		return net__try_connect_unix(host, sock);
#else
		return MOSQ_ERR_NOT_SUPPORTED;
#endif
	}else{
		return net__try_connect_tcp(host, port, sock, bind_address, blocking);
	}
}


#ifdef WITH_TLS
void net__print_ssl_error(struct mosquitto *mosq)
{
	char ebuf[256];
	unsigned long e;
	int num = 0;

	e = ERR_get_error();
	while(e){
		log__printf(mosq, MOSQ_LOG_ERR, "OpenSSL Error[%d]: %s", num, ERR_error_string(e, ebuf));
		e = ERR_get_error();
		num++;
	}
}


int net__socket_connect_tls(struct mosquitto *mosq)
{
	int ret, err;
	long res;

	ERR_clear_error();
	if (mosq->tls_ocsp_required) {
		/* Note: OCSP is available in all currently supported OpenSSL versions. */
		if ((res=SSL_set_tlsext_status_type(mosq->ssl, TLSEXT_STATUSTYPE_ocsp)) != 1) {
			log__printf(mosq, MOSQ_LOG_ERR, "Could not activate OCSP (error: %ld)", res);
			return MOSQ_ERR_OCSP;
		}
		if ((res=SSL_CTX_set_tlsext_status_cb(mosq->ssl_ctx, mosquitto__verify_ocsp_status_cb)) != 1) {
			log__printf(mosq, MOSQ_LOG_ERR, "Could not activate OCSP (error: %ld)", res);
			return MOSQ_ERR_OCSP;
		}
		if ((res=SSL_CTX_set_tlsext_status_arg(mosq->ssl_ctx, mosq)) != 1) {
			log__printf(mosq, MOSQ_LOG_ERR, "Could not activate OCSP (error: %ld)", res);
			return MOSQ_ERR_OCSP;
		}
	}

	ret = SSL_connect(mosq->ssl);
	if(ret != 1) {
		err = SSL_get_error(mosq->ssl, ret);
		if (err == SSL_ERROR_SYSCALL) {
			mosq->want_connect = true;
			return MOSQ_ERR_SUCCESS;
		}
		if(err == SSL_ERROR_WANT_READ){
			mosq->want_connect = true;
			/* We always try to read anyway */
		}else if(err == SSL_ERROR_WANT_WRITE){
			mosq->want_write = true;
			mosq->want_connect = true;
		}else{
			net__print_ssl_error(mosq);

			COMPAT_CLOSE(mosq->sock);
			mosq->sock = INVALID_SOCKET;
			net__print_ssl_error(mosq);
			return MOSQ_ERR_TLS;
		}
	}else{
		mosq->want_connect = false;
	}
	return MOSQ_ERR_SUCCESS;
}
#endif


#ifdef WITH_TLS
static int net__tls_load_ca(struct mosquitto *mosq)
{
	int ret;

	if(mosq->tls_use_os_certs){
		SSL_CTX_set_default_verify_paths(mosq->ssl_ctx);
	}
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if(mosq->tls_cafile || mosq->tls_capath){
		ret = SSL_CTX_load_verify_locations(mosq->ssl_ctx, mosq->tls_cafile, mosq->tls_capath);
		if(ret == 0){
#  ifdef WITH_BROKER
			if(mosq->tls_cafile && mosq->tls_capath){
				log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check bridge_cafile \"%s\" and bridge_capath \"%s\".", mosq->tls_cafile, mosq->tls_capath);
			}else if(mosq->tls_cafile){
				log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check bridge_cafile \"%s\".", mosq->tls_cafile);
			}else{
				log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check bridge_capath \"%s\".", mosq->tls_capath);
			}
#  else
			if(mosq->tls_cafile && mosq->tls_capath){
				log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check cafile \"%s\" and capath \"%s\".", mosq->tls_cafile, mosq->tls_capath);
			}else if(mosq->tls_cafile){
				log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check cafile \"%s\".", mosq->tls_cafile);
			}else{
				log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check capath \"%s\".", mosq->tls_capath);
			}
#  endif
			return MOSQ_ERR_TLS;
		}
	}
#else
	if(mosq->tls_cafile){
		ret = SSL_CTX_load_verify_file(mosq->ssl_ctx, mosq->tls_cafile);
		if(ret == 0){
#  ifdef WITH_BROKER
			log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check bridge_cafile \"%s\".", mosq->tls_cafile);
#  else
			log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check cafile \"%s\".", mosq->tls_cafile);
#  endif
			return MOSQ_ERR_TLS;
		}
	}
	if(mosq->tls_capath){
		ret = SSL_CTX_load_verify_dir(mosq->ssl_ctx, mosq->tls_capath);
		if(ret == 0){
#  ifdef WITH_BROKER
			log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check bridge_capath \"%s\".", mosq->tls_capath);
#  else
			log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check capath \"%s\".", mosq->tls_capath);
#  endif
			return MOSQ_ERR_TLS;
		}
	}
#endif
	return MOSQ_ERR_SUCCESS;
}


static int net__init_ssl_ctx(struct mosquitto *mosq)
{
	int ret;
	ENGINE *engine = NULL;
	uint8_t tls_alpn_wire[256];
	uint8_t tls_alpn_len;
#if !defined(OPENSSL_NO_ENGINE)
	EVP_PKEY *pkey;
#endif

	if(mosq->ssl_ctx){
		if(!mosq->ssl_ctx_defaults){
			return MOSQ_ERR_SUCCESS;
		}else if(!mosq->tls_cafile && !mosq->tls_capath && !mosq->tls_psk){
			log__printf(mosq, MOSQ_LOG_ERR, "Error: MOSQ_OPT_SSL_CTX_WITH_DEFAULTS used without specifying cafile, capath or psk.");
			return MOSQ_ERR_INVAL;
		}
	}

	/* Apply default SSL_CTX settings. This is only used if MOSQ_OPT_SSL_CTX
	 * has not been set, or if both of MOSQ_OPT_SSL_CTX and
	 * MOSQ_OPT_SSL_CTX_WITH_DEFAULTS are set. */
	if(mosq->tls_cafile || mosq->tls_capath || mosq->tls_psk || mosq->tls_use_os_certs){
		if(!mosq->ssl_ctx){
			net__init_tls();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
			mosq->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#else
			mosq->ssl_ctx = SSL_CTX_new(TLS_client_method());
#endif

			if(!mosq->ssl_ctx){
				log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to create TLS context.");
				net__print_ssl_error(mosq);
				return MOSQ_ERR_TLS;
			}
		}

		if(!mosq->tls_version){
			SSL_CTX_set_options(mosq->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
#ifdef SSL_OP_NO_TLSv1_3
		}else if(!strcmp(mosq->tls_version, "tlsv1.3")){
			SSL_CTX_set_options(mosq->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2);
#endif
		}else if(!strcmp(mosq->tls_version, "tlsv1.2")){
			SSL_CTX_set_options(mosq->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
		}else if(!strcmp(mosq->tls_version, "tlsv1.1")){
			SSL_CTX_set_options(mosq->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
		}else{
			log__printf(mosq, MOSQ_LOG_ERR, "Error: Protocol %s not supported.", mosq->tls_version);
			return MOSQ_ERR_INVAL;
		}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		/* Allow use of DHE ciphers */
		SSL_CTX_set_dh_auto(mosq->ssl_ctx, 1);
#endif
		/* Disable compression */
		SSL_CTX_set_options(mosq->ssl_ctx, SSL_OP_NO_COMPRESSION);

		/* Set ALPN */
		if(mosq->tls_alpn) {
			tls_alpn_len = (uint8_t) strnlen(mosq->tls_alpn, 254);
			tls_alpn_wire[0] = tls_alpn_len;  /* first byte is length of string */
			memcpy(tls_alpn_wire + 1, mosq->tls_alpn, tls_alpn_len);
			SSL_CTX_set_alpn_protos(mosq->ssl_ctx, tls_alpn_wire, tls_alpn_len + 1U);
		}

#ifdef SSL_MODE_RELEASE_BUFFERS
			/* Use even less memory per SSL connection. */
			SSL_CTX_set_mode(mosq->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

#if !defined(OPENSSL_NO_ENGINE)
		if(mosq->tls_engine){
			engine = ENGINE_by_id(mosq->tls_engine);
			if(!engine){
				log__printf(mosq, MOSQ_LOG_ERR, "Error loading %s engine\n", mosq->tls_engine);
				return MOSQ_ERR_TLS;
			}
			if(!ENGINE_init(engine)){
				log__printf(mosq, MOSQ_LOG_ERR, "Failed engine initialisation\n");
				ENGINE_free(engine);
				return MOSQ_ERR_TLS;
			}
			ENGINE_set_default(engine, ENGINE_METHOD_ALL);
			ENGINE_free(engine); /* release the structural reference from ENGINE_by_id() */
		}
#endif

		if(mosq->tls_ciphers){
			ret = SSL_CTX_set_cipher_list(mosq->ssl_ctx, mosq->tls_ciphers);
			if(ret == 0){
				log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to set TLS ciphers. Check cipher list \"%s\".", mosq->tls_ciphers);
#if !defined(OPENSSL_NO_ENGINE)
				ENGINE_FINISH(engine);
#endif
				net__print_ssl_error(mosq);
				return MOSQ_ERR_TLS;
			}
		}
		if(mosq->tls_cafile || mosq->tls_capath || mosq->tls_use_os_certs){
			ret = net__tls_load_ca(mosq);
			if(ret != MOSQ_ERR_SUCCESS){
#  if !defined(OPENSSL_NO_ENGINE)
				ENGINE_FINISH(engine);
#  endif
				net__print_ssl_error(mosq);
				return MOSQ_ERR_TLS;
			}
			if(mosq->tls_cert_reqs == 0){
				SSL_CTX_set_verify(mosq->ssl_ctx, SSL_VERIFY_NONE, NULL);
			}else{
				SSL_CTX_set_verify(mosq->ssl_ctx, SSL_VERIFY_PEER, mosquitto__server_certificate_verify);
			}

			if(mosq->tls_pw_callback){
				SSL_CTX_set_default_passwd_cb(mosq->ssl_ctx, mosq->tls_pw_callback);
				SSL_CTX_set_default_passwd_cb_userdata(mosq->ssl_ctx, mosq);
			}

			if(mosq->tls_certfile){
				ret = SSL_CTX_use_certificate_chain_file(mosq->ssl_ctx, mosq->tls_certfile);
				if(ret != 1){
#ifdef WITH_BROKER
					log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load client certificate, check bridge_certfile \"%s\".", mosq->tls_certfile);
#else
					log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load client certificate \"%s\".", mosq->tls_certfile);
#endif
#if !defined(OPENSSL_NO_ENGINE)
					ENGINE_FINISH(engine);
#endif
					net__print_ssl_error(mosq);
					return MOSQ_ERR_TLS;
				}
			}
			if(mosq->tls_keyfile){
				if(mosq->tls_keyform == mosq_k_engine){
#if !defined(OPENSSL_NO_ENGINE)
					UI_METHOD *ui_method = net__get_ui_method();
					if(mosq->tls_engine_kpass_sha1){
						if(!ENGINE_ctrl_cmd(engine, ENGINE_SECRET_MODE, ENGINE_SECRET_MODE_SHA, NULL, NULL, 0)){
							log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to set engine secret mode sha1");
							ENGINE_FINISH(engine);
							net__print_ssl_error(mosq);
							return MOSQ_ERR_TLS;
						}
						if(!ENGINE_ctrl_cmd(engine, ENGINE_PIN, 0, mosq->tls_engine_kpass_sha1, NULL, 0)){
							log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to set engine pin");
							ENGINE_FINISH(engine);
							net__print_ssl_error(mosq);
							return MOSQ_ERR_TLS;
						}
						ui_method = NULL;
					}
					pkey = ENGINE_load_private_key(engine, mosq->tls_keyfile, ui_method, NULL);
					if(!pkey){
						log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load engine private key file \"%s\".", mosq->tls_keyfile);
						ENGINE_FINISH(engine);
						net__print_ssl_error(mosq);
						return MOSQ_ERR_TLS;
					}
					if(SSL_CTX_use_PrivateKey(mosq->ssl_ctx, pkey) <= 0){
						log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to use engine private key file \"%s\".", mosq->tls_keyfile);
						ENGINE_FINISH(engine);
						net__print_ssl_error(mosq);
						return MOSQ_ERR_TLS;
					}
#endif
				}else{
					ret = SSL_CTX_use_PrivateKey_file(mosq->ssl_ctx, mosq->tls_keyfile, SSL_FILETYPE_PEM);
					if(ret != 1){
#ifdef WITH_BROKER
						log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load client key file, check bridge_keyfile \"%s\".", mosq->tls_keyfile);
#else
						log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load client key file \"%s\".", mosq->tls_keyfile);
#endif
#if !defined(OPENSSL_NO_ENGINE)
						ENGINE_FINISH(engine);
#endif
						net__print_ssl_error(mosq);
						return MOSQ_ERR_TLS;
					}
				}
				ret = SSL_CTX_check_private_key(mosq->ssl_ctx);
				if(ret != 1){
					log__printf(mosq, MOSQ_LOG_ERR, "Error: Client certificate/key are inconsistent.");
#if !defined(OPENSSL_NO_ENGINE)
					ENGINE_FINISH(engine);
#endif
					net__print_ssl_error(mosq);
					return MOSQ_ERR_TLS;
				}
			}
#ifdef FINAL_WITH_TLS_PSK
		}else if(mosq->tls_psk){
			SSL_CTX_set_psk_client_callback(mosq->ssl_ctx, psk_client_callback);
#endif
		}
	}

	return MOSQ_ERR_SUCCESS;
}
#endif


int net__socket_connect_step3(struct mosquitto *mosq, const char *host)
{
#ifdef WITH_TLS
	BIO *bio;

	int rc = net__init_ssl_ctx(mosq);
	if(rc){
		net__socket_close(mosq);
		return rc;
	}

	if(mosq->ssl_ctx){
		if(mosq->ssl){
			SSL_free(mosq->ssl);
		}
		mosq->ssl = SSL_new(mosq->ssl_ctx);
		if(!mosq->ssl){
			net__socket_close(mosq);
			net__print_ssl_error(mosq);
			return MOSQ_ERR_TLS;
		}

		SSL_set_ex_data(mosq->ssl, tls_ex_index_mosq, mosq);
		bio = BIO_new_socket(mosq->sock, BIO_NOCLOSE);
		if(!bio){
			net__socket_close(mosq);
			net__print_ssl_error(mosq);
			return MOSQ_ERR_TLS;
		}
		SSL_set_bio(mosq->ssl, bio, bio);

		/*
		 * required for the SNI resolving
		 */
		if(SSL_set_tlsext_host_name(mosq->ssl, host) != 1) {
			net__socket_close(mosq);
			return MOSQ_ERR_TLS;
		}

		if(net__socket_connect_tls(mosq)){
			net__socket_close(mosq);
			return MOSQ_ERR_TLS;
		}

	}
#endif
	return MOSQ_ERR_SUCCESS;
}

/* Create a socket and connect it to 'ip' on port 'port'.  */
int net__socket_connect(struct mosquitto *mosq, const char *host, uint16_t port, const char *bind_address, bool blocking)
{
	mosq_sock_t sock = INVALID_SOCKET;
	int rc, rc2;

	if(!mosq || !host) return MOSQ_ERR_INVAL;

	rc = net__try_connect(host, port, &sock, bind_address, blocking);
	if(rc > 0) return rc;

	mosq->sock = sock;

	if(mosq->tcp_nodelay){
		int flag = 1;
		if(setsockopt(mosq->sock, IPPROTO_TCP, TCP_NODELAY, (const void*)&flag, sizeof(int)) != 0){
			log__printf(mosq, MOSQ_LOG_WARNING, "Warning: Unable to set TCP_NODELAY.");
		}
	}

#if defined(WITH_SOCKS) && !defined(WITH_BROKER)
	if(!mosq->socks5_host)
#endif
	{
		rc2 = net__socket_connect_step3(mosq, host);
		if(rc2) return rc2;
	}

	return MOSQ_ERR_SUCCESS;
}


ssize_t net__read(struct mosquitto *mosq, void *buf, size_t count)
{
#ifdef WITH_TLS
	int ret;
	int err;
#endif
	assert(mosq);
	errno = 0;
#ifdef WITH_TLS
	if(mosq->ssl){
		ret = SSL_read(mosq->ssl, buf, (int)count);
		if(ret <= 0){
			err = SSL_get_error(mosq->ssl, ret);
			if(err == SSL_ERROR_WANT_READ){
				ret = -1;
				errno = EAGAIN;
			}else if(err == SSL_ERROR_WANT_WRITE){
				ret = -1;
				mosq->want_write = true;
				errno = EAGAIN;
			}else{
				net__print_ssl_error(mosq);
				errno = EPROTO;
			}
			ERR_clear_error();
#ifdef WIN32
			WSASetLastError(errno);
#endif
		}
		return (ssize_t )ret;
	}else{
		/* Call normal read/recv */

#endif

#ifndef WIN32
	return read(mosq->sock, buf, count);
#else
	return recv(mosq->sock, buf, count, 0);
#endif

#ifdef WITH_TLS
	}
#endif
}

ssize_t net__write(struct mosquitto *mosq, void *buf, size_t count)
{
#ifdef WITH_TLS
	int ret;
	int err;
#endif
	assert(mosq);

	errno = 0;
#ifdef WITH_TLS
	if(mosq->ssl){
		mosq->want_write = false;
		ret = SSL_write(mosq->ssl, buf, (int)count);
		if(ret < 0){
			err = SSL_get_error(mosq->ssl, ret);
			if(err == SSL_ERROR_WANT_READ){
				ret = -1;
				errno = EAGAIN;
			}else if(err == SSL_ERROR_WANT_WRITE){
				ret = -1;
				mosq->want_write = true;
				errno = EAGAIN;
			}else{
				net__print_ssl_error(mosq);
				errno = EPROTO;
			}
			ERR_clear_error();
#ifdef WIN32
			WSASetLastError(errno);
#endif
		}
		return (ssize_t )ret;
	}else{
		/* Call normal write/send */
#endif

#ifndef WIN32
	return write(mosq->sock, buf, count);
#else
	return send(mosq->sock, buf, count, 0);
#endif

#ifdef WITH_TLS
	}
#endif
}


int net__socket_nonblock(mosq_sock_t *sock)
{
#ifndef WIN32
	int opt;
	/* Set non-blocking */
	opt = fcntl(*sock, F_GETFL, 0);
	if(opt == -1){
		COMPAT_CLOSE(*sock);
		*sock = INVALID_SOCKET;
		return MOSQ_ERR_ERRNO;
	}
	if(fcntl(*sock, F_SETFL, opt | O_NONBLOCK) == -1){
		/* If either fcntl fails, don't want to allow this client to connect. */
		COMPAT_CLOSE(*sock);
		*sock = INVALID_SOCKET;
		return MOSQ_ERR_ERRNO;
	}
#else
	unsigned long opt = 1;
	if(ioctlsocket(*sock, FIONBIO, &opt)){
		COMPAT_CLOSE(*sock);
		*sock = INVALID_SOCKET;
		return MOSQ_ERR_ERRNO;
	}
#endif
	return MOSQ_ERR_SUCCESS;
}


#ifndef WITH_BROKER
int net__socketpair(mosq_sock_t *pairR, mosq_sock_t *pairW)
{
#ifdef WIN32
	int family[2] = {AF_INET, AF_INET6};
	int i;
	struct sockaddr_storage ss;
	struct sockaddr_in *sa = (struct sockaddr_in *)&ss;
	struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&ss;
	socklen_t ss_len;
	mosq_sock_t spR, spW;

	mosq_sock_t listensock;

	*pairR = INVALID_SOCKET;
	*pairW = INVALID_SOCKET;

	for(i=0; i<2; i++){
		memset(&ss, 0, sizeof(ss));
		if(family[i] == AF_INET){
			sa->sin_family = family[i];
			sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			sa->sin_port = 0;
			ss_len = sizeof(struct sockaddr_in);
		}else if(family[i] == AF_INET6){
			sa6->sin6_family = family[i];
			sa6->sin6_addr = in6addr_loopback;
			sa6->sin6_port = 0;
			ss_len = sizeof(struct sockaddr_in6);
		}else{
			return MOSQ_ERR_INVAL;
		}

		listensock = socket(family[i], SOCK_STREAM, IPPROTO_TCP);
		if(listensock == -1){
			continue;
		}

		if(bind(listensock, (struct sockaddr *)&ss, ss_len) == -1){
			COMPAT_CLOSE(listensock);
			continue;
		}

		if(listen(listensock, 1) == -1){
			COMPAT_CLOSE(listensock);
			continue;
		}
		memset(&ss, 0, sizeof(ss));
		ss_len = sizeof(ss);
		if(getsockname(listensock, (struct sockaddr *)&ss, &ss_len) < 0){
			COMPAT_CLOSE(listensock);
			continue;
		}

		if(family[i] == AF_INET){
			sa->sin_family = family[i];
			sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			ss_len = sizeof(struct sockaddr_in);
		}else if(family[i] == AF_INET6){
			sa6->sin6_family = family[i];
			sa6->sin6_addr = in6addr_loopback;
			ss_len = sizeof(struct sockaddr_in6);
		}

		spR = socket(family[i], SOCK_STREAM, IPPROTO_TCP);
		if(spR == -1){
			COMPAT_CLOSE(listensock);
			continue;
		}
		if(net__socket_nonblock(&spR)){
			COMPAT_CLOSE(listensock);
			continue;
		}
		if(connect(spR, (struct sockaddr *)&ss, ss_len) < 0){
#ifdef WIN32
			errno = WSAGetLastError();
#endif
			if(errno != EINPROGRESS && errno != COMPAT_EWOULDBLOCK){
				COMPAT_CLOSE(spR);
				COMPAT_CLOSE(listensock);
				continue;
			}
		}
		spW = accept(listensock, NULL, 0);
		if(spW == -1){
#ifdef WIN32
			errno = WSAGetLastError();
#endif
			if(errno != EINPROGRESS && errno != COMPAT_EWOULDBLOCK){
				COMPAT_CLOSE(spR);
				COMPAT_CLOSE(listensock);
				continue;
			}
		}

		if(net__socket_nonblock(&spW)){
			COMPAT_CLOSE(spR);
			COMPAT_CLOSE(listensock);
			continue;
		}
		COMPAT_CLOSE(listensock);

		*pairR = spR;
		*pairW = spW;
		return MOSQ_ERR_SUCCESS;
	}
	return MOSQ_ERR_UNKNOWN;
#else
	int sv[2];

	*pairR = INVALID_SOCKET;
	*pairW = INVALID_SOCKET;

	if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1){
		return MOSQ_ERR_ERRNO;
	}
	if(net__socket_nonblock(&sv[0])){
		COMPAT_CLOSE(sv[1]);
		return MOSQ_ERR_ERRNO;
	}
	if(net__socket_nonblock(&sv[1])){
		COMPAT_CLOSE(sv[0]);
		return MOSQ_ERR_ERRNO;
	}
	*pairR = sv[0];
	*pairW = sv[1];
	return MOSQ_ERR_SUCCESS;
#endif
}
#endif

#ifndef WITH_BROKER
void *mosquitto_ssl_get(struct mosquitto *mosq)
{
#ifdef WITH_TLS
	return mosq->ssl;
#else
	return NULL;
#endif
}
#endif
