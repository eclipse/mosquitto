#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <mosquitto.h>
#include <openssl/ssl.h>

static int run = -1;

void handle_sigint(int signal)
{
	run = 0;
}

void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	if(rc){
		exit(1);
	}else{
		mosquitto_disconnect(mosq);
	}
}

void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
	run = rc;
}

int main(int argc, char *argv[])
{
	int rc;
	struct mosquitto *mosq;
	SSL_CTX *ssl_ctx;
	int port = atoi(argv[1]);

	mosquitto_lib_init();

	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
			| OPENSSL_INIT_ADD_ALL_DIGESTS \
			| OPENSSL_INIT_LOAD_CONFIG, NULL);
	ssl_ctx = SSL_CTX_new(TLS_client_method());

	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_use_certificate_chain_file(ssl_ctx, "../ssl/client.crt");
	SSL_CTX_use_PrivateKey_file(ssl_ctx, "../ssl/client.key", SSL_FILETYPE_PEM);
	SSL_CTX_load_verify_locations(ssl_ctx, "../ssl/test-root-ca.crt", "../ssl/certs");

	mosq = mosquitto_new("08-ssl-connect-crt-auth", true, NULL);
	if(mosq == NULL){
		return 1;
	}
	mosquitto_tls_set(mosq, "../ssl/test-root-ca.crt", "../ssl/certs", "../ssl/client.crt", "../ssl/client.key", NULL);
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_disconnect_callback_set(mosq, on_disconnect);

	mosquitto_int_option(mosq, MOSQ_OPT_SSL_CTX_WITH_DEFAULTS, 0);
	mosquitto_void_option(mosq, MOSQ_OPT_SSL_CTX, ssl_ctx);

	rc = mosquitto_connect(mosq, "localhost", port, 60);

	signal(SIGINT, handle_sigint);
	while(run == -1){
		mosquitto_loop(mosq, -1, 1);
	}
	SSL_CTX_free(ssl_ctx);
	mosquitto_destroy(mosq);

	mosquitto_lib_cleanup();
	return run;
}
