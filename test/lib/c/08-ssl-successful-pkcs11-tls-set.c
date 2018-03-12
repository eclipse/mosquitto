#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <mosquitto.h>

int main(int argc, char *argv[])
{
	int rc = 1;
	struct mosquitto *mosq;

	mosquitto_lib_init();

	mosq = mosquitto_new("08-ssl-bad-cacert", true, NULL);
	mosquitto_tls_opts_set(mosq, 1, "tlsv1", NULL);

	if(mosquitto_tls_set_uri(mosq, "file://../ssl/test-root-ca.crt", "file://../ssl/certs",
				 "file://../ssl/client.crt", "pkcs11:something", 
				 NULL, "../ssl/libpkcs11.so", "../ssl/libsofthsm2.so") == 0){
		rc = 0;
	}
	mosquitto_lib_cleanup();
	return rc;
}
