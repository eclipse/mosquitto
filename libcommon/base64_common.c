/*
Copyright (c) 2012-2021 Roger Light <roger@atchoo.org>

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

#include "config.h"

#ifdef WITH_TLS
#  include <openssl/opensslv.h>
#  include <openssl/evp.h>
#  include <openssl/rand.h>
#  include <openssl/buffer.h>
#endif
#include <string.h>

#include "mosquitto.h"

#ifdef WITH_TLS
int mosquitto_base64_encode(const unsigned char *in, size_t in_len, char **encoded)
{
	BIO *bmem, *b64;
	BUF_MEM *bptr = NULL;
	int rc = 1;

	b64 = BIO_new(BIO_f_base64());
	if(b64 == NULL) return 1;

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new(BIO_s_mem());
	if(bmem){
		b64 = BIO_push(b64, bmem);
		BIO_write(b64, in, (int)in_len);

		if(BIO_flush(b64) == 1){
			BIO_get_mem_ptr(b64, &bptr);
			*encoded = mosquitto_malloc(bptr->length+1);
			if(*encoded){
				memcpy(*encoded, bptr->data, bptr->length);
				(*encoded)[bptr->length] = '\0';
				rc = 0;
			}
		}
	}
	BIO_free_all(b64);

	return rc;
}


int mosquitto_base64_decode(const char *in, unsigned char **decoded, unsigned int *decoded_len)
{
	BIO *bmem, *b64;
	size_t slen;
	int len;
	int rc = 1;

	slen = strlen(in);

	b64 = BIO_new(BIO_f_base64());
	if(!b64) return 1;

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new(BIO_s_mem());
	if(bmem){
		b64 = BIO_push(b64, bmem);
		BIO_write(bmem, in, (int)slen);

		if(BIO_flush(bmem) == 1){
			*decoded = mosquitto_calloc(slen, 1);

			if(*decoded){
				len = BIO_read(b64, *decoded, (int)slen);
				if(len > 0){
					*decoded_len = (unsigned int)len;
					rc = 0;
				}else{
					mosquitto_free(*decoded);
					*decoded = NULL;
				}
			}
		}
	}
	BIO_free_all(b64);

	return rc;
}
#endif
