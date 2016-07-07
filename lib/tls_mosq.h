/*
Copyright (c) 2013-2015 Roger Light <roger@atchoo.org>

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

#ifndef TLS_MOSQ_H
#define TLS_MOSQ_H

#ifdef WITH_TLS
#  define SSL_DATA_PENDING(A) ((A)->ssl && SSL_pending((A)->ssl))
#else
#  define SSL_DATA_PENDING(A) 0
#endif

#ifdef WITH_TLS

#include <openssl/ssl.h>
#include <openssl/engine.h>
#ifdef WITH_TLS_PSK
#  if OPENSSL_VERSION_NUMBER >= 0x10000000
#    define REAL_WITH_TLS_PSK
#  else
#    warning "TLS-PSK not supported, openssl too old."
#  endif
#endif

int mosquitto__server_certificate_verify(int preverify_ok, X509_STORE_CTX *ctx);
int mosquitto__verify_certificate_hostname(X509 *cert, const char *hostname);

#endif /* WITH_TLS */

#endif
