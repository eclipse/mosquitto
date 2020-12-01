/*
Copyright (c) 2014-2020 Roger Light <roger@atchoo.org>

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

#ifndef CLIENT_CONFIG_H
#define CLIENT_CONFIG_H

#include <stdio.h>

#ifdef WIN32
#  include <winsock2.h>
#else
#  include <sys/time.h>
#endif

/* pub_client.c modes */
#define MSGMODE_NONE 0
#define MSGMODE_CMD 1
#define MSGMODE_STDIN_LINE 2
#define MSGMODE_STDIN_FILE 3
#define MSGMODE_FILE 4
#define MSGMODE_NULL 5

#define CLIENT_PUB 1
#define CLIENT_SUB 2
#define CLIENT_RR 3
#define CLIENT_RESPONSE_TOPIC 4

#define PORT_UNDEFINED -1
#define PORT_UNIX 0

struct mosq_config {
	char *id;
	char *id_prefix;
	int protocol_version;
	int keepalive;
	char *host;
	int port;
	int qos;
	bool retain;
	int pub_mode; /* pub, rr */
	char *file_input; /* pub, rr */
	char *message; /* pub, rr */
	int msglen; /* pub, rr */
	char *topic; /* pub, rr */
	char *bind_address;
	int repeat_count; /* pub */
	struct timeval repeat_delay; /* pub */
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
	int will_payloadlen;
	int will_qos;
	bool will_retain;
#ifdef WITH_TLS
	char *cafile;
	char *capath;
	char *certfile;
	char *keyfile;
	char *ciphers;
	bool insecure;
	char *tls_alpn;
	char *tls_version;
	char *tls_engine;
	char *tls_engine_kpass_sha1;
	char *keyform;
	bool tls_use_os_certs;
#  ifdef FINAL_WITH_TLS_PSK
	char *psk;
	char *psk_identity;
#  endif
#endif
	bool clean_session;
	char **topics; /* sub, rr */
	int topic_count; /* sub, rr */
	bool exit_after_sub; /* sub */
	bool no_retain; /* sub */
	bool retained_only; /* sub */
	bool remove_retained; /* sub */
	char **filter_outs; /* sub */
	int filter_out_count; /* sub */
	char **unsub_topics; /* sub */
	int unsub_topic_count; /* sub */
	bool verbose; /* sub */
	bool eol; /* sub */
	int msg_count; /* sub */
	char *format; /* sub, rr */
	bool pretty; /* sub, rr */
	unsigned int timeout; /* sub */
	int sub_opts; /* sub */
	long session_expiry_interval;
	int random_filter; /* sub */
#ifdef WITH_SOCKS
	char *socks5_host;
	int socks5_port;
	char *socks5_username;
	char *socks5_password;
#endif
	mosquitto_property *connect_props;
	mosquitto_property *publish_props;
	mosquitto_property *subscribe_props;
	mosquitto_property *unsubscribe_props;
	mosquitto_property *disconnect_props;
	mosquitto_property *will_props;
	bool have_topic_alias; /* pub */
	char *response_topic; /* rr */
	bool tcp_nodelay;
};

int client_config_load(struct mosq_config *config, int pub_or_sub, int argc, char *argv[]);
void client_config_cleanup(struct mosq_config *cfg);
int client_opts_set(struct mosquitto *mosq, struct mosq_config *cfg);
int client_id_generate(struct mosq_config *cfg);
int client_connect(struct mosquitto *mosq, struct mosq_config *cfg);

int cfg_parse_property(struct mosq_config *cfg, int argc, char *argv[], int *idx);

void err_printf(const struct mosq_config *cfg, const char *fmt, ...);

#endif
