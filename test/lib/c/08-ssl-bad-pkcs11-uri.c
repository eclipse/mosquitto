#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <mosquitto.h>

int main(int argc, char *argv[])
{
	int rc = 0;
	struct mosquitto *mosq;

	mosquitto_lib_init();

	mosq = mosquitto_new("08-ssl-bad-cacert", true, NULL);
	mosquitto_tls_opts_set(mosq, 1, "tlsv1", NULL);

	/* Bad pkcs11 URI */
	if(mosquitto_tls_set_uri(mosq, 
				 "file://../ssl/test-root-ca.crt", 
				 "../ssl/certs",
				 "file://../ssl/client.crt",
				 "pk:test-uri",
				 NULL,
				 "../ssl/libpkcs11.so",
				 "../ssl/libsofthsm2.so") != MOSQ_ERR_INVAL){
		rc = 1;
		goto cleanup;
	}
	
	/*  Bad key file */
	if(mosquitto_tls_set_uri(mosq,
				 "file://../ssl/test-root-ca.crt",
				 "../ssl/certs",
				 "file://../ssl/client.crt",
				 "file://../ssl/key.crt",
				 NULL,
				 NULL,
				 NULL) != MOSQ_ERR_INVAL){
		rc = 1;
		goto cleanup;
	}
	
	/* Bad client cert */
	if(mosquitto_tls_set_uri(mosq,
				 "file://../ssl/test-root-ca.crt",
				 "../ssl/certs",
				 "file://../ssl/client.cr",
				 "pkcs11:test-uri",
				 NULL,
				 "../ssl/libpkcs11.so",
				 "../ssl/libsofthsm2.so") != MOSQ_ERR_INVAL){
		rc = 1;
		goto cleanup;
	}
	
	/* Bad client cert uri */
	if(mosquitto_tls_set_uri(mosq,
				 "file://../ssl/test-root-ca.crt",
				 "../ssl/certs",
				 "file//../ssl/client.crt",
				 "pkcs11:test-uri",
				 NULL,
				 "../ssl/libpkcs11.so",
				 "../ssl/libsofthsm2.so") != MOSQ_ERR_INVAL){
		rc = 1;
		goto cleanup;
	}
	
	/* Bad root ca */
	if(mosquitto_tls_set_uri(mosq,
				 "file://../ssl/test-root-ca.cr",
				 "../ssl/certs",
				 "file://../ssl/client.crt",
				 "pkcs11:test-uri",
				 NULL,
				 "../ssl/libpkcs11.so",
				 "../ssl/libsofthsm2.so") != MOSQ_ERR_INVAL){
		rc = 1;
		goto cleanup;
	}

	/* Bad root ca uri */
	if(mosquitto_tls_set_uri(mosq,
				 "file//../ssl/test-root-ca.crt",
				 "../ssl/certs",
				 "file://../ssl/client.crt",
				 "pkcs11:test-uri",
				 NULL,
				 "../ssl/libpkcs11.so",
				 "../ssl/libsofthsm2.so") != MOSQ_ERR_INVAL){
		rc = 1;
		goto cleanup;
	}
	
	/*  Bad key file */
	if(mosquitto_tls_set_uri(mosq,
				 "file://../ssl/test-root-ca.crt",
				 "../ssl/certs",
				 "file://../ssl/client.crt",
				 "file://../ssl/key.crt",
				 NULL,
				 NULL,
				 NULL) != MOSQ_ERR_INVAL){
		rc = 1;
		goto cleanup;
	}
	
	/*  Bad key file uri */
	if(mosquitto_tls_set_uri(mosq,
				 "file://../ssl/test-root-ca.crt",
				 "../ssl/certs",
				 "file://../ssl/client.crt",
				 "file//../ssl/key.crt",
				 NULL,
				 NULL,
				 NULL) != MOSQ_ERR_INVAL){
		rc = 1;
		goto cleanup;
	}
	
	/* Bad libp11 library */
	if(mosquitto_tls_set_uri(mosq,
				 "file://../ssl/test-root-ca.crt",
				 "../ssl/certs",
				 "file://../ssl/client.crt",
				 "pkcs11:test-uri",
				 NULL,
				 "../ssl/libpkcs11.s",
				 "../ssl/libsofthsm2.so") != MOSQ_ERR_INVAL){
		rc = 1;
		goto cleanup;
	}
	
	/* No libp11 library */
	if(mosquitto_tls_set_uri(mosq,
				 "file://../ssl/test-root-ca.crt",
				 "../ssl/certs",
				 "file://../ssl/client.crt",
				 "pkcs11:test-uri",
				 NULL,
				 NULL,
				 "../ssl/libsofthsm2.so") != MOSQ_ERR_INVAL){
		rc = 1;
		goto cleanup;
	}
	
	/* No pkcs11 provider */
	if(mosquitto_tls_set_uri(mosq,
				 "file://../ssl/test-root-ca.crt",
				 "../ssl/certs",
				 "file://../ssl/client.crt",
				 "pkcs11:test-uri",
				 NULL,
				 "../ssl/libpkcs11.so",
				 NULL) != MOSQ_ERR_INVAL){
		rc = 1;
		goto cleanup;
	}
	
	/* Bad pkcs11 provider */
	if(mosquitto_tls_set_uri(mosq,
				 "file://../ssl/test-root-ca.crt",
				 "../ssl/certs",
				 "file://../ssl/client.crt",
				 "pkcs11:test-uri",
				 NULL,
				 "../ssl/libpkcs11.so",
				 "../ssl/libsofthsm2.s") != MOSQ_ERR_INVAL){
		rc = 1;
		goto cleanup;
	}
	
	/* NULL cert file */
	if(mosquitto_tls_set_uri(mosq,
				 "file://../ssl/test-root-ca.crt",
				 "../ssl/certs",
				 NULL,
				 "pkcs11:test-uri",
				 NULL,
				 "../ssl/libpkcs11.so",
				 "../ssl/libsofthsm2.so") != MOSQ_ERR_INVAL){
		rc = 1;
		goto cleanup;
	}
cleanup:
	mosquitto_lib_cleanup();
	return rc;
}
