/*
Copyright (c) 2009-2021 Roger Light <roger@atchoo.org>

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
#include <stdlib.h> /* Keep this here to allow glibc detection */

#ifdef WIN32
#  include <winsock2.h>
#  include <aclapi.h>
#  include <io.h>
#  include <lmcons.h>
#endif

#ifdef WITH_TLS
#  include <openssl/bn.h>
#  include <openssl/rand.h>
#elif defined(HAVE_GETRANDOM)  /* From CMakeLists.txt */
# include <sys/random.h>
#elif defined(__linux__) && defined(__GLIBC__) /* For legacy Makefiles */
#  if __GLIBC_PREREQ(2, 25)
#    include <sys/random.h>
#    define HAVE_GETRANDOM 1
#  endif
#endif

#include "mosquitto.h"


int mosquitto_getrandom(void *bytes, int count)
{
	int rc = MOSQ_ERR_UNKNOWN;

#ifdef WITH_TLS
	if(RAND_bytes(bytes, count) == 1){
		rc = MOSQ_ERR_SUCCESS;
	}
#elif defined(HAVE_GETRANDOM)
	if(getrandom(bytes, (size_t)count, 0) == count){
		rc = MOSQ_ERR_SUCCESS;
	}
#elif defined(WIN32)
	HCRYPTPROV provider;

	if(!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)){
		return MOSQ_ERR_UNKNOWN;
	}

	if(CryptGenRandom(provider, count, bytes)){
		rc = MOSQ_ERR_SUCCESS;
	}

	CryptReleaseContext(provider, 0);
#else /* For legacy Makefiles */
#  error "No suitable random function found."
#endif
	return rc;
}
