/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>
Copyright (c) 2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG), Dr. Lars Voelker <lars.voelker@bmw.de>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR EDL-1.0

Contributors:
   Dr. Lars Voelker, BMW AG
*/

/*
COPYRIGHT AND PERMISSION NOTICE of curl on which the ocsp code is based:

Copyright (c) 1996 - 2016, Daniel Stenberg, <daniel@haxx.se>, and many
contributors, see the THANKS file.

All rights reserved.

Permission to use, copy, modify, and distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of a copyright holder shall not
be used in advertising or otherwise to promote the sale, use or other dealings
in this Software without prior written authorization of the copyright holder.
*/

#include "config.h"

#ifdef WITH_TLS
#include <logging_mosq.h>
#include <mosquitto_internal.h>
#include <net_mosq.h>

#include <openssl/safestack.h>
#include <openssl/tls1.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>

int mosquitto__verify_ocsp_status_cb(SSL * ssl, void *arg)
{
	struct mosquitto *mosq = (struct mosquitto *)arg;
	int ocsp_status, result2, i;
	unsigned char *p;
	const unsigned char *cp;
	OCSP_RESPONSE *rsp = NULL;
	OCSP_BASICRESP *br = NULL;
	X509_STORE     *st = NULL;
	STACK_OF(X509) *ch = NULL;

	long len = SSL_get_tlsext_status_ocsp_resp(mosq->ssl, &p);
	log__printf(mosq, MOSQ_LOG_DEBUG, "OCSP: SSL_get_tlsext_status_ocsp_resp returned %ld bytes", len);

	/* the following functions expect a const pointer */
	cp = (const unsigned char *)p;

	if (!cp || len <= 0) {
		log__printf(mosq, MOSQ_LOG_DEBUG, "OCSP: no response");
		goto end;
	}


	rsp = d2i_OCSP_RESPONSE(NULL, &cp, len);
	if (rsp==NULL) {
		log__printf(mosq, MOSQ_LOG_DEBUG, "OCSP: invalid response");
		goto end;
	}

	ocsp_status = OCSP_response_status(rsp);
	if(ocsp_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		log__printf(mosq, MOSQ_LOG_DEBUG, "OCSP: invalid status: %s (%d)",
			       OCSP_response_status_str(ocsp_status), ocsp_status);
		goto end;
	}

	br = OCSP_response_get1_basic(rsp);
	if (!br) {
		log__printf(mosq, MOSQ_LOG_DEBUG, "OCSP: invalid response");
		goto end;
	}

	ch = SSL_get_peer_cert_chain(mosq->ssl);
	if (sk_X509_num(ch) <= 0) {
		log__printf(mosq, MOSQ_LOG_ERR, "OCSP: we did not receive certificates of the server (num: %d)", sk_X509_num(ch));
		goto end;
	}

	st = SSL_CTX_get_cert_store(mosq->ssl_ctx);

	/* Note:
	 * Other checkers often fix problems in OpenSSL before 1.0.2a (e.g. libcurl).
	 * For all currently supported versions of the OpenSSL project, this is not needed anymore.
	 */

	if ((result2=OCSP_basic_verify(br, ch, st, 0)) <= 0) {
		log__printf(mosq, MOSQ_LOG_DEBUG, "OCSP: response verification failed (error: %d)", result2);
		goto end;
	}

	for(i = 0; i < OCSP_resp_count(br); i++) {
		int cert_status, crl_reason;
		OCSP_SINGLERESP *single = NULL;

		ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;

		single = OCSP_resp_get0(br, i);
		if(!single)
			continue;

		cert_status = OCSP_single_get0_status(single, &crl_reason, &rev, &thisupd, &nextupd);

		log__printf(mosq, MOSQ_LOG_DEBUG, "OCSP: SSL certificate status: %s (%d)",
				OCSP_cert_status_str(cert_status), cert_status);

		switch(cert_status) {
			case V_OCSP_CERTSTATUS_GOOD:
				/* Note: A OCSP stapling result will be accepted up to 5 minutes after it expired! */
				if(!OCSP_check_validity(thisupd, nextupd, 300L, -1L)) {
					log__printf(mosq, MOSQ_LOG_DEBUG, "OCSP: OCSP response has expired");
					goto end;
				}
				break;

			case V_OCSP_CERTSTATUS_REVOKED:
				log__printf(mosq, MOSQ_LOG_DEBUG, "OCSP: SSL certificate revocation reason: %s (%d)",
					OCSP_crl_reason_str(crl_reason), crl_reason);
				goto end;

			case V_OCSP_CERTSTATUS_UNKNOWN:
				goto end;

			default:
				log__printf(mosq, MOSQ_LOG_DEBUG, "OCSP: SSL certificate revocation status unknown");
				goto end;
		}
	}

	if (br!=NULL)  OCSP_BASICRESP_free(br);
	if (rsp!=NULL) OCSP_RESPONSE_free(rsp);
	return 1; /* OK */

end:
	if (br!=NULL)  OCSP_BASICRESP_free(br);
	if (rsp!=NULL) OCSP_RESPONSE_free(rsp);
	return 0; /* Not OK */
}
#endif
