/*
Copyright (c) 2014-2016 Roger Light <roger@atchoo.org>

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

#ifndef CLIENT_CONFIG_H
#define CLIENT_CONFIG_H

#include <stdio.h>

/* pub_client.c modes */
#define MSGMODE_NONE 0
#define MSGMODE_CMD 1
#define MSGMODE_STDIN_LINE 2
#define MSGMODE_STDIN_FILE 3
#define MSGMODE_FILE 4
#define MSGMODE_NULL 5

#define CLIENT_PUB 1
#define CLIENT_SUB 2

struct mosq_config {
	char *id;
	char *id_prefix;
	int protocol_version;
	int keepalive;
	char *host;
	int port;
	int qos;
	bool retain;
	int pub_mode; /* pub */
	char *file_input; /* pub */
	char *message; /* pub */
	long msglen; /* pub */
	char *topic; /* pub */
	char *bind_address;
#ifdef WITH_SRV
	bool use_srv;
#endif
	bool debug;
	bool quiet;
	unsigned int max_inflight;
	char *username;
	char *password;
	char *will_topic;
	char *will_payload;
	long will_payloadlen;
	int will_qos;
	bool will_retain;
#ifdef WITH_TLS
	char *cafile;
	char *capath;
	char *certfile;
	char *keyfile;
	char *ciphers;
	bool insecure;
	char *tls_version;
#  ifdef WITH_TLS_PSK
	char *psk;
	char *psk_identity;
#  endif
#  ifdef WITH_TLS_TICKET
	char *sessionfile;
#  endif
#endif
	bool clean_session;
	char **topics; /* sub */
	int topic_count; /* sub */
	bool no_retain; /* sub */
	bool retained_only; /* sub */
	char **filter_outs; /* sub */
	int filter_out_count; /* sub */
	char **unsub_topics; /* sub */
	int unsub_topic_count; /* sub */
	bool verbose; /* sub */
	bool eol; /* sub */
	int msg_count; /* sub */
	char *format; /* sub */
#ifdef WITH_SOCKS
	char *socks5_host;
	int socks5_port;
	char *socks5_username;
	char *socks5_password;
#endif
};

int client_config_load(struct mosq_config *config, int pub_or_sub, int argc, char *argv[]);
void client_config_cleanup(struct mosq_config *cfg);
int client_opts_set(struct mosquitto *mosq, struct mosq_config *cfg);
int client_id_generate(struct mosq_config *cfg, const char *id_base);
int client_connect(struct mosquitto *mosq, struct mosq_config *cfg);

#if defined(WITH_TLS) && defined(WITH_TLS_TICKET)
int client_read_file(const char* fname, char** buf);
int client_write_file(const char* fname, const char* buf);
#endif

#endif
