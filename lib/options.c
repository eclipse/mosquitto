/*
Copyright (c) 2010-2020 Roger Light <roger@atchoo.org>

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
#  include <strings.h>
#endif

#include <string.h>

#ifdef WITH_TLS
#  ifdef WIN32
#    include <winsock2.h>
#  endif
#  include <openssl/engine.h>
#endif

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "memory_mosq.h"
#include "misc_mosq.h"
#include "mqtt_protocol.h"
#include "util_mosq.h"
#include "will_mosq.h"


int mosquitto_will_set(struct mosquitto *mosq, const char *topic, int payloadlen, const void *payload, int qos, bool retain)
{
	return mosquitto_will_set_v5(mosq, topic, payloadlen, payload, qos, retain, NULL);
}


int mosquitto_will_set_v5(struct mosquitto *mosq, const char *topic, int payloadlen, const void *payload, int qos, bool retain, mosquitto_property *properties)
{
	int rc;

	if(!mosq) return MOSQ_ERR_INVAL;

	if(properties){
		rc = mosquitto_property_check_all(CMD_WILL, properties);
		if(rc) return rc;
	}

	return will__set(mosq, topic, payloadlen, payload, qos, retain, properties);
}


int mosquitto_will_clear(struct mosquitto *mosq)
{
	if(!mosq) return MOSQ_ERR_INVAL;
	return will__clear(mosq);
}


int mosquitto_username_pw_set(struct mosquitto *mosq, const char *username, const char *password)
{
	size_t slen;

	if(!mosq) return MOSQ_ERR_INVAL;

	if(mosq->protocol == mosq_p_mqtt311 || mosq->protocol == mosq_p_mqtt31){
		if(password != NULL && username == NULL){
			return MOSQ_ERR_INVAL;
		}
	}

	mosquitto__free(mosq->username);
	mosq->username = NULL;

	mosquitto__free(mosq->password);
	mosq->password = NULL;

	if(username){
		slen = strlen(username);
		if(slen > UINT16_MAX){
			return MOSQ_ERR_INVAL;
		}
		if(mosquitto_validate_utf8(username, (int)slen)){
			return MOSQ_ERR_MALFORMED_UTF8;
		}
		mosq->username = mosquitto__strdup(username);
		if(!mosq->username) return MOSQ_ERR_NOMEM;
	}

	if(password){
		mosq->password = mosquitto__strdup(password);
		if(!mosq->password){
			mosquitto__free(mosq->username);
			mosq->username = NULL;
			return MOSQ_ERR_NOMEM;
		}
	}
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_reconnect_delay_set(struct mosquitto *mosq, unsigned int reconnect_delay, unsigned int reconnect_delay_max, bool reconnect_exponential_backoff)
{
	if(!mosq) return MOSQ_ERR_INVAL;
	
	if(reconnect_delay == 0) reconnect_delay = 1;

	mosq->reconnect_delay = reconnect_delay;
	mosq->reconnect_delay_max = reconnect_delay_max;
	mosq->reconnect_exponential_backoff = reconnect_exponential_backoff;
	
	return MOSQ_ERR_SUCCESS;
	
}


int mosquitto_tls_set(struct mosquitto *mosq, const char *cafile, const char *capath, const char *certfile, const char *keyfile, int (*pw_callback)(char *buf, int size, int rwflag, void *userdata))
{
#ifdef WITH_TLS
	FILE *fptr;

	if(!mosq || (!cafile && !capath) || (certfile && !keyfile) || (!certfile && keyfile)) return MOSQ_ERR_INVAL;

	mosquitto__free(mosq->tls_cafile);
	mosq->tls_cafile = NULL;
	if(cafile){
		fptr = mosquitto__fopen(cafile, "rt", false);
		if(fptr){
			fclose(fptr);
		}else{
			return MOSQ_ERR_INVAL;
		}
		mosq->tls_cafile = mosquitto__strdup(cafile);

		if(!mosq->tls_cafile){
			return MOSQ_ERR_NOMEM;
		}
	}

	mosquitto__free(mosq->tls_capath);
	mosq->tls_capath = NULL;
	if(capath){
		mosq->tls_capath = mosquitto__strdup(capath);
		if(!mosq->tls_capath){
			return MOSQ_ERR_NOMEM;
		}
	}

	mosquitto__free(mosq->tls_certfile);
	mosq->tls_certfile = NULL;
	if(certfile){
		fptr = mosquitto__fopen(certfile, "rt", false);
		if(fptr){
			fclose(fptr);
		}else{
			mosquitto__free(mosq->tls_cafile);
			mosq->tls_cafile = NULL;

			mosquitto__free(mosq->tls_capath);
			mosq->tls_capath = NULL;
			return MOSQ_ERR_INVAL;
		}
		mosq->tls_certfile = mosquitto__strdup(certfile);
		if(!mosq->tls_certfile){
			return MOSQ_ERR_NOMEM;
		}
	}

	mosquitto__free(mosq->tls_keyfile);
	mosq->tls_keyfile = NULL;
	if(keyfile){
		fptr = mosquitto__fopen(keyfile, "rt", false);
		if(fptr){
			fclose(fptr);
		}else{
			mosquitto__free(mosq->tls_cafile);
			mosq->tls_cafile = NULL;

			mosquitto__free(mosq->tls_capath);
			mosq->tls_capath = NULL;

			mosquitto__free(mosq->tls_certfile);
			mosq->tls_certfile = NULL;
			return MOSQ_ERR_INVAL;
		}
		mosq->tls_keyfile = mosquitto__strdup(keyfile);
		if(!mosq->tls_keyfile){
			return MOSQ_ERR_NOMEM;
		}
	}

	mosq->tls_pw_callback = pw_callback;


	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;

#endif
}


int mosquitto_tls_opts_set(struct mosquitto *mosq, int cert_reqs, const char *tls_version, const char *ciphers)
{
#ifdef WITH_TLS
	if(!mosq) return MOSQ_ERR_INVAL;

	mosq->tls_cert_reqs = cert_reqs;
	if(tls_version){
		if(!strcasecmp(tls_version, "tlsv1.3")
				|| !strcasecmp(tls_version, "tlsv1.2")
				|| !strcasecmp(tls_version, "tlsv1.1")){

			mosq->tls_version = mosquitto__strdup(tls_version);
			if(!mosq->tls_version) return MOSQ_ERR_NOMEM;
		}else{
			return MOSQ_ERR_INVAL;
		}
	}else{
		mosq->tls_version = mosquitto__strdup("tlsv1.2");
		if(!mosq->tls_version) return MOSQ_ERR_NOMEM;
	}
	if(ciphers){
		mosq->tls_ciphers = mosquitto__strdup(ciphers);
		if(!mosq->tls_ciphers) return MOSQ_ERR_NOMEM;
	}else{
		mosq->tls_ciphers = NULL;
	}


	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;

#endif
}


int mosquitto_tls_insecure_set(struct mosquitto *mosq, bool value)
{
#ifdef WITH_TLS
	if(!mosq) return MOSQ_ERR_INVAL;
	mosq->tls_insecure = value;
	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}


int mosquitto_string_option(struct mosquitto *mosq, enum mosq_opt_t option, const char *value)
{
#ifdef WITH_TLS
	ENGINE *eng;
	char *str;
#endif

	if(!mosq) return MOSQ_ERR_INVAL;

	switch(option){
		case MOSQ_OPT_TLS_ENGINE:
#ifdef WITH_TLS
#    if !defined(OPENSSL_NO_ENGINE)
			eng = ENGINE_by_id(value);
			if(!eng){
				return MOSQ_ERR_INVAL;
			}
			ENGINE_free(eng); /* release the structural reference from ENGINE_by_id() */
			mosq->tls_engine = mosquitto__strdup(value);
			if(!mosq->tls_engine){
				return MOSQ_ERR_NOMEM;
			}
			return MOSQ_ERR_SUCCESS;
#endif
#else
			return MOSQ_ERR_NOT_SUPPORTED;
#endif
			break;

		case MOSQ_OPT_TLS_KEYFORM:
#ifdef WITH_TLS
			if(!value) return MOSQ_ERR_INVAL;
			if(!strcasecmp(value, "pem")){
				mosq->tls_keyform = mosq_k_pem;
			}else if (!strcasecmp(value, "engine")){
				mosq->tls_keyform = mosq_k_engine;
			}else{
				return MOSQ_ERR_INVAL;
			}
			return MOSQ_ERR_SUCCESS;
#else
			return MOSQ_ERR_NOT_SUPPORTED;
#endif
			break;


		case MOSQ_OPT_TLS_ENGINE_KPASS_SHA1:
#ifdef WITH_TLS
			if(mosquitto__hex2bin_sha1(value, (unsigned char**)&str) != MOSQ_ERR_SUCCESS){
				return MOSQ_ERR_INVAL;
			}
			mosq->tls_engine_kpass_sha1 = str;
			return MOSQ_ERR_SUCCESS;
#else
			return MOSQ_ERR_NOT_SUPPORTED;
#endif
			break;

		case MOSQ_OPT_TLS_ALPN:
#ifdef WITH_TLS
			mosq->tls_alpn = mosquitto__strdup(value);
			if(!mosq->tls_alpn){
				return MOSQ_ERR_NOMEM;
			}
			return MOSQ_ERR_SUCCESS;
#else
			return MOSQ_ERR_NOT_SUPPORTED;
#endif
			break;

		case MOSQ_OPT_BIND_ADDRESS:
			mosquitto__free(mosq->bind_address);
			if(value){
				mosq->bind_address = mosquitto__strdup(value);
				if(mosq->bind_address){
					return MOSQ_ERR_SUCCESS;
				}else{
					return MOSQ_ERR_NOMEM;
				}
			}else{
				return MOSQ_ERR_SUCCESS;
			}


		default:
			return MOSQ_ERR_INVAL;
	}
}


int mosquitto_tls_psk_set(struct mosquitto *mosq, const char *psk, const char *identity, const char *ciphers)
{
#ifdef FINAL_WITH_TLS_PSK
	if(!mosq || !psk || !identity) return MOSQ_ERR_INVAL;

	/* Check for hex only digits */
	if(strspn(psk, "0123456789abcdefABCDEF") < strlen(psk)){
		return MOSQ_ERR_INVAL;
	}
	mosq->tls_psk = mosquitto__strdup(psk);
	if(!mosq->tls_psk) return MOSQ_ERR_NOMEM;

	mosq->tls_psk_identity = mosquitto__strdup(identity);
	if(!mosq->tls_psk_identity){
		mosquitto__free(mosq->tls_psk);
		return MOSQ_ERR_NOMEM;
	}
	if(ciphers){
		mosq->tls_ciphers = mosquitto__strdup(ciphers);
		if(!mosq->tls_ciphers) return MOSQ_ERR_NOMEM;
	}else{
		mosq->tls_ciphers = NULL;
	}

	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}


int mosquitto_opts_set(struct mosquitto *mosq, enum mosq_opt_t option, void *value)
{
	int ival;

	if(!mosq || !value) return MOSQ_ERR_INVAL;

	switch(option){
		case MOSQ_OPT_PROTOCOL_VERSION:
			ival = *((int *)value);
			return mosquitto_int_option(mosq, option, ival);
		case MOSQ_OPT_SSL_CTX:
#ifdef WITH_TLS
			mosq->ssl_ctx = (SSL_CTX *)value;
			if(mosq->ssl_ctx){
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
				SSL_CTX_up_ref(mosq->ssl_ctx);
#else
				CRYPTO_add(&(mosq->ssl_ctx)->references, 1, CRYPTO_LOCK_SSL_CTX);
#endif
			}
			break;
#else
			return MOSQ_ERR_NOT_SUPPORTED;
#endif
		default:
			return MOSQ_ERR_INVAL;
	}
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_int_option(struct mosquitto *mosq, enum mosq_opt_t option, int value)
{
	if(!mosq) return MOSQ_ERR_INVAL;

	switch(option){
		case MOSQ_OPT_PROTOCOL_VERSION:
			if(value == MQTT_PROTOCOL_V31){
				mosq->protocol = mosq_p_mqtt31;
			}else if(value == MQTT_PROTOCOL_V311){
				mosq->protocol = mosq_p_mqtt311;
			}else if(value == MQTT_PROTOCOL_V5){
				mosq->protocol = mosq_p_mqtt5;
			}else{
				return MOSQ_ERR_INVAL;
			}
			break;

		case MOSQ_OPT_RECEIVE_MAXIMUM:
			if(value < 0 || value > UINT16_MAX){
				return MOSQ_ERR_INVAL;
			}
			if(value == 0){
				mosq->msgs_in.inflight_maximum = UINT16_MAX;
			}else{
				mosq->msgs_in.inflight_maximum = (uint16_t)value;
			}
			break;

		case MOSQ_OPT_SEND_MAXIMUM:
			if(value < 0 || value > UINT16_MAX){
				return MOSQ_ERR_INVAL;
			}
			if(value == 0){
				mosq->msgs_out.inflight_maximum = UINT16_MAX;
			}else{
				mosq->msgs_out.inflight_maximum = (uint16_t)value;
			}
			break;

		case MOSQ_OPT_SSL_CTX_WITH_DEFAULTS:
#if defined(WITH_TLS) && OPENSSL_VERSION_NUMBER >= 0x10100000L
			if(value){
				mosq->ssl_ctx_defaults = true;
			}else{
				mosq->ssl_ctx_defaults = false;
			}
			break;
#else
			return MOSQ_ERR_NOT_SUPPORTED;
#endif

		case MOSQ_OPT_TLS_USE_OS_CERTS:
#ifdef WITH_TLS
			if(value){
				mosq->tls_use_os_certs = true;
			}else{
				mosq->tls_use_os_certs = false;
			}
			break;
#else
			return MOSQ_ERR_NOT_SUPPORTED;
#endif

		case MOSQ_OPT_TLS_OCSP_REQUIRED:
#ifdef WITH_TLS
			mosq->tls_ocsp_required = (bool)value;
#else
			return MOSQ_ERR_NOT_SUPPORTED;
#endif
			break;

		case MOSQ_OPT_TCP_NODELAY:
			mosq->tcp_nodelay = (bool)value;
			break;

		default:
			return MOSQ_ERR_INVAL;
	}
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_void_option(struct mosquitto *mosq, enum mosq_opt_t option, void *value)
{
	if(!mosq || !value) return MOSQ_ERR_INVAL;

	switch(option){
		case MOSQ_OPT_SSL_CTX:
#ifdef WITH_TLS
			mosq->ssl_ctx = (SSL_CTX *)value;
			if(mosq->ssl_ctx){
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
				SSL_CTX_up_ref(mosq->ssl_ctx);
#else
				CRYPTO_add(&(mosq->ssl_ctx)->references, 1, CRYPTO_LOCK_SSL_CTX);
#endif
			}
			break;
#else
			return MOSQ_ERR_NOT_SUPPORTED;
#endif
		default:
			return MOSQ_ERR_INVAL;
	}
	return MOSQ_ERR_SUCCESS;
}


void mosquitto_user_data_set(struct mosquitto *mosq, void *userdata)
{
	if(mosq){
		mosq->userdata = userdata;
	}
}

void *mosquitto_userdata(struct mosquitto *mosq)
{
	return mosq->userdata;
}
