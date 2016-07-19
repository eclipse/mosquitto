/*
Copyright (c) 2009-2015 Roger Light <roger@atchoo.org>

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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#include <netdb.h>
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

#ifdef __FreeBSD__
#  include <netinet/in.h>
#endif

#ifdef __SYMBIAN32__
#include <netinet/in.h>
#endif

#ifdef __QNX__
#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG 0
#endif
#include <net/netbyte.h>
#include <netinet/in.h>
#endif

#ifdef WITH_TLS
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <tls_mosq.h>
#endif

#ifdef WITH_BROKER
#  include "mosquitto_broker.h"
#  ifdef WITH_WEBSOCKETS
#    include <libwebsockets.h>
#  endif
#else
#  include "read_handle.h"
#endif

#include "logging_mosq.h"
#include "memory_mosq.h"
#include "mqtt3_protocol.h"
#include "net_mosq.h"
#include "time_mosq.h"
#include "util_mosq.h"

#include "config.h"

#ifdef WITH_TLS
int tls_ex_index_mosq = -1;
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

#ifdef WITH_TLS
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	if(tls_ex_index_mosq == -1){
		tls_ex_index_mosq = SSL_get_ex_new_index(0, "client context", NULL, NULL, NULL);
	}
#endif
	return MOSQ_ERR_SUCCESS;
}

void net__cleanup(void)
{
#ifdef WITH_TLS
	ERR_remove_state(0);
	ENGINE_cleanup();
	CONF_modules_unload(1);
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
#endif

#ifdef WITH_SRV
	ares_library_cleanup();
#endif

#ifdef WIN32
	WSACleanup();
#endif
}


/* Close a socket associated with a context and set it to -1.
 * Returns 1 on failure (context is NULL)
 * Returns 0 on success.
 */
#ifdef WITH_BROKER
int net__socket_close(struct mosquitto_db *db, struct mosquitto *mosq)
#else
int net__socket_close(struct mosquitto *mosq)
#endif
{
	int rc = 0;

	assert(mosq);
#ifdef WITH_TLS
	if(mosq->ssl){
		SSL_shutdown(mosq->ssl);
		SSL_free(mosq->ssl);
		mosq->ssl = NULL;
	}
	if(mosq->ssl_ctx){
		SSL_CTX_free(mosq->ssl_ctx);
		mosq->ssl_ctx = NULL;
	}
#endif

	if((int)mosq->sock >= 0){
#ifdef WITH_BROKER
		HASH_DELETE(hh_sock, db->contexts_by_sock, mosq);
#endif
		rc = COMPAT_CLOSE(mosq->sock);
		mosq->sock = INVALID_SOCKET;
#ifdef WITH_WEBSOCKETS
	}else if(mosq->sock == WEBSOCKET_CLIENT){
		if(mosq->state != mosq_cs_disconnecting){
			mosq->state = mosq_cs_disconnect_ws;
		}
		if(mosq->wsi){
			libwebsocket_callback_on_writable(mosq->ws_context, mosq->wsi);
		}
		mosq->sock = INVALID_SOCKET;
#endif
	}

#ifdef WITH_BROKER
	if(mosq->listener){
		mosq->listener->client_count--;
		assert(mosq->listener->client_count >= 0);
		mosq->listener = NULL;
	}
#endif

	return rc;
}


#ifdef REAL_WITH_TLS_PSK
static unsigned int psk_client_callback(SSL *ssl, const char *hint,
		char *identity, unsigned int max_identity_len,
		unsigned char *psk, unsigned int max_psk_len)
{
	struct mosquitto *mosq;
	int len;

	mosq = SSL_get_ex_data(ssl, tls_ex_index_mosq);
	if(!mosq) return 0;

	snprintf(identity, max_identity_len, "%s", mosq->tls_psk_identity);

	len = mosquitto__hex2bin(mosq->tls_psk, psk, max_psk_len);
	if (len < 0) return 0;
	return len;
}
#endif


int net__try_connect(struct mosquitto *mosq, const char *host, uint16_t port, mosq_sock_t *sock, const char *bind_address, bool blocking)
{
	struct addrinfo hints;
	struct addrinfo *ainfo, *rp;
	struct addrinfo *ainfo_bind, *rp_bind;
	int s;
	int rc = MOSQ_ERR_SUCCESS;
#ifdef WIN32
	uint32_t val = 1;
#endif

	*sock = INVALID_SOCKET;
	memset(&hints, 0, sizeof(struct addrinfo));
#ifdef WITH_TLS
	if(mosq->tls_cafile || mosq->tls_capath || mosq->tls_psk){
		hints.ai_family = PF_INET;
	}else
#endif
	{
		hints.ai_family = PF_UNSPEC;
	}
	hints.ai_flags = AI_ADDRCONFIG;
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
		
		if(rp->ai_family == PF_INET){
			((struct sockaddr_in *)rp->ai_addr)->sin_port = htons(port);
		}else if(rp->ai_family == PF_INET6){
			((struct sockaddr_in6 *)rp->ai_addr)->sin6_port = htons(port);
		}else{
			COMPAT_CLOSE(*sock);
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
				continue;
			}
		}

		if(!blocking){
			/* Set non-blocking */
			if(net__socket_nonblock(*sock)){
				COMPAT_CLOSE(*sock);
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
				if(net__socket_nonblock(*sock)){
					COMPAT_CLOSE(*sock);
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


#ifdef WITH_TLS
void net__print_ssl_error(struct mosquitto *mosq)
{
	char ebuf[256];
	unsigned long e;

	e = ERR_get_error();
	while(e){
		log__printf(mosq, MOSQ_LOG_ERR, "OpenSSL Error: %s", ERR_error_string(e, ebuf));
		e = ERR_get_error();
	}
}


int net__socket_connect_tls(struct mosquitto *mosq)
{
	int ret, err;
	ret = SSL_connect(mosq->ssl);
	if(ret != 1) {
		err = SSL_get_error(mosq->ssl, ret);
#ifdef WIN32
		if (err == SSL_ERROR_SYSCALL) {
			mosq->want_connect = true;
			return MOSQ_ERR_SUCCESS;
		}
#endif
		if(err == SSL_ERROR_WANT_READ){
			mosq->want_connect = true;
			/* We always try to read anyway */
		}else if(err == SSL_ERROR_WANT_WRITE){
			mosq->want_write = true;
			mosq->want_connect = true;
		}else{
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


/* Create a socket and connect it to 'ip' on port 'port'.
 * Returns -1 on failure (ip is NULL, socket creation/connection error)
 * Returns sock number on success.
 */
int net__socket_connect(struct mosquitto *mosq, const char *host, uint16_t port, const char *bind_address, bool blocking)
{
	mosq_sock_t sock = INVALID_SOCKET;
	int rc;
#ifdef WITH_TLS
	int ret;
	BIO *bio;
#endif

	if(!mosq || !host || !port) return MOSQ_ERR_INVAL;

	rc = net__try_connect(mosq, host, port, &sock, bind_address, blocking);
	if(rc > 0) return rc;

#ifdef WITH_TLS
	if(mosq->tls_cafile || mosq->tls_capath || mosq->tls_psk){
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
		if(!mosq->tls_version){
			mosq->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
		}else if(!strcmp(mosq->tls_version, "tlsv1.2")){
			mosq->ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
		}else if(!strcmp(mosq->tls_version, "tlsv1.1")){
			mosq->ssl_ctx = SSL_CTX_new(TLSv1_1_client_method());
		}else if(!strcmp(mosq->tls_version, "tlsv1")){
			mosq->ssl_ctx = SSL_CTX_new(TLSv1_client_method());
		}else{
			log__printf(mosq, MOSQ_LOG_ERR, "Error: Protocol %s not supported.", mosq->tls_version);
			COMPAT_CLOSE(sock);
			return MOSQ_ERR_INVAL;
		}
#else
		if(!mosq->tls_version || !strcmp(mosq->tls_version, "tlsv1")){
			mosq->ssl_ctx = SSL_CTX_new(TLSv1_client_method());
		}else{
			log__printf(mosq, MOSQ_LOG_ERR, "Error: Protocol %s not supported.", mosq->tls_version);
			COMPAT_CLOSE(sock);
			return MOSQ_ERR_INVAL;
		}
#endif
		if(!mosq->ssl_ctx){
			log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to create TLS context.");
			COMPAT_CLOSE(sock);
			net__print_ssl_error(mosq);
			return MOSQ_ERR_TLS;
		}

#if OPENSSL_VERSION_NUMBER >= 0x10000000
		/* Disable compression */
		SSL_CTX_set_options(mosq->ssl_ctx, SSL_OP_NO_COMPRESSION);
#endif
#ifdef SSL_MODE_RELEASE_BUFFERS
			/* Use even less memory per SSL connection. */
			SSL_CTX_set_mode(mosq->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

		if(mosq->tls_ciphers){
			ret = SSL_CTX_set_cipher_list(mosq->ssl_ctx, mosq->tls_ciphers);
			if(ret == 0){
				log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to set TLS ciphers. Check cipher list \"%s\".", mosq->tls_ciphers);
				COMPAT_CLOSE(sock);
				net__print_ssl_error(mosq);
				return MOSQ_ERR_TLS;
			}
		}
		if(mosq->tls_cafile || mosq->tls_capath){
			ret = SSL_CTX_load_verify_locations(mosq->ssl_ctx, mosq->tls_cafile, mosq->tls_capath);
			if(ret == 0){
#ifdef WITH_BROKER
				if(mosq->tls_cafile && mosq->tls_capath){
					log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check bridge_cafile \"%s\" and bridge_capath \"%s\".", mosq->tls_cafile, mosq->tls_capath);
				}else if(mosq->tls_cafile){
					log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check bridge_cafile \"%s\".", mosq->tls_cafile);
				}else{
					log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check bridge_capath \"%s\".", mosq->tls_capath);
				}
#else
				if(mosq->tls_cafile && mosq->tls_capath){
					log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check cafile \"%s\" and capath \"%s\".", mosq->tls_cafile, mosq->tls_capath);
				}else if(mosq->tls_cafile){
					log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check cafile \"%s\".", mosq->tls_cafile);
				}else{
					log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check capath \"%s\".", mosq->tls_capath);
				}
#endif
				COMPAT_CLOSE(sock);
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
					COMPAT_CLOSE(sock);
					net__print_ssl_error(mosq);
					return MOSQ_ERR_TLS;
				}
			}
			if(mosq->tls_keyfile){
				ret = SSL_CTX_use_PrivateKey_file(mosq->ssl_ctx, mosq->tls_keyfile, SSL_FILETYPE_PEM);
				if(ret != 1){
#ifdef WITH_BROKER
					log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load client key file, check bridge_keyfile \"%s\".", mosq->tls_keyfile);
#else
					log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load client key file \"%s\".", mosq->tls_keyfile);
#endif
					COMPAT_CLOSE(sock);
					net__print_ssl_error(mosq);
					return MOSQ_ERR_TLS;
				}
				ret = SSL_CTX_check_private_key(mosq->ssl_ctx);
				if(ret != 1){
					log__printf(mosq, MOSQ_LOG_ERR, "Error: Client certificate/key are inconsistent.");
					COMPAT_CLOSE(sock);
					net__print_ssl_error(mosq);
					return MOSQ_ERR_TLS;
				}
			}
#ifdef REAL_WITH_TLS_PSK
		}else if(mosq->tls_psk){
			SSL_CTX_set_psk_client_callback(mosq->ssl_ctx, psk_client_callback);
#endif
		}

		mosq->ssl = SSL_new(mosq->ssl_ctx);
		if(!mosq->ssl){
			COMPAT_CLOSE(sock);
			net__print_ssl_error(mosq);
			return MOSQ_ERR_TLS;
		}
		if(mosq->tls_server_name){
			ret = SSL_set_tlsext_host_name(mosq->ssl, mosq->tls_server_name);
			if(ret != 1){
#ifdef WITH_BROKER
				log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to set server name, check bridge_server_name \"%s\".", mosq->tls_server_name);
#else
				log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to set server name \"%s\".", mosq->tls_server_name);
#endif
				COMPAT_CLOSE(sock);
				return MOSQ_ERR_TLS;
			}
		}
		SSL_set_ex_data(mosq->ssl, tls_ex_index_mosq, mosq);
		bio = BIO_new_socket(sock, BIO_NOCLOSE);
		if(!bio){
			COMPAT_CLOSE(sock);
			net__print_ssl_error(mosq);
			return MOSQ_ERR_TLS;
		}
		SSL_set_bio(mosq->ssl, bio, bio);

		mosq->sock = sock;
		if(net__socket_connect_tls(mosq)){
			return MOSQ_ERR_TLS;
		}

	}
#endif

	mosq->sock = sock;

	return rc;
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
		ret = SSL_read(mosq->ssl, buf, count);
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
		ret = SSL_write(mosq->ssl, buf, count);
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


int net__socket_nonblock(int sock)
{
#ifndef WIN32
	int opt;
	/* Set non-blocking */
	opt = fcntl(sock, F_GETFL, 0);
	if(opt == -1){
		COMPAT_CLOSE(sock);
		return 1;
	}
	if(fcntl(sock, F_SETFL, opt | O_NONBLOCK) == -1){
		/* If either fcntl fails, don't want to allow this client to connect. */
		COMPAT_CLOSE(sock);
		return 1;
	}
#else
	unsigned long opt = 1;
	if(ioctlsocket(sock, FIONBIO, &opt)){
		COMPAT_CLOSE(sock);
		return 1;
	}
#endif
	return 0;
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
		if(net__socket_nonblock(spR)){
			COMPAT_CLOSE(spR);
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

		if(net__socket_nonblock(spW)){
			COMPAT_CLOSE(spR);
			COMPAT_CLOSE(spW);
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

	if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1){
		return MOSQ_ERR_ERRNO;
	}
	if(net__socket_nonblock(sv[0])){
		COMPAT_CLOSE(sv[0]);
		COMPAT_CLOSE(sv[1]);
		return MOSQ_ERR_ERRNO;
	}
	if(net__socket_nonblock(sv[1])){
		COMPAT_CLOSE(sv[0]);
		COMPAT_CLOSE(sv[1]);
		return MOSQ_ERR_ERRNO;
	}
	*pairR = sv[0];
	*pairW = sv[1];
	return MOSQ_ERR_SUCCESS;
#endif
}
#endif
