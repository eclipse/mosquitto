/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>

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
#ifndef MOSQUITTO_CTRL_H
#define MOSQUITTO_CTRL_H

#include <cjson/cJSON.h>
#include <stdbool.h>

#include "mosquitto.h"

#define PORT_UNDEFINED -1
#define PORT_UNIX 0

struct mosq_config {
	char *id;
	int protocol_version;
	int keepalive;
	char *host;
	int port;
	int qos;
	char *bind_address;
	bool debug;
	bool quiet;
	char *username;
	char *password;
	char *options_file;
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
#  ifdef FINAL_WITH_TLS_PSK
	char *psk;
	char *psk_identity;
#  endif
#endif
	bool verbose; /* sub */
	unsigned int timeout; /* sub */
#ifdef WITH_SOCKS
	char *socks5_host;
	int socks5_port;
	char *socks5_username;
	char *socks5_password;
#endif
};

struct mosq_ctrl {
	struct mosq_config cfg;
	char *request_topic;
	char *response_topic;
	char *payload;
	void (*payload_callback)(struct mosq_ctrl *, long , const void *);
	void *userdata;
};

typedef int (*FUNC_ctrl_main)(int argc, char *argv[], struct mosq_ctrl *ctrl);

void init_config(struct mosq_config *cfg);
int ctrl_config_parse(struct mosq_config *cfg, int *argc, char **argv[]);
int client_config_load(struct mosq_config *cfg);
void client_config_cleanup(struct mosq_config *cfg);

int client_request_response(struct mosq_ctrl *ctrl);
int client_opts_set(struct mosquitto *mosq, struct mosq_config *cfg);
int client_connect(struct mosquitto *mosq, struct mosq_config *cfg);

cJSON *cJSON_AddIntToObject(cJSON * const object, const char * const name, int number);

void dynsec__print_usage(void);
int dynsec__main(int argc, char *argv[], struct mosq_ctrl *ctrl);

int dynsec_client__add_remove_role(int argc, char *argv[], cJSON *j_command, const char *command);
int dynsec_client__create(int argc, char *argv[], cJSON *j_command);
int dynsec_client__delete(int argc, char *argv[], cJSON *j_command);
int dynsec_client__enable_disable(int argc, char *argv[], cJSON *j_command, const char *command);
int dynsec_client__get(int argc, char *argv[], cJSON *j_command);
int dynsec_client__list_all(int argc, char *argv[], cJSON *j_command);
int dynsec_client__set_id(int argc, char *argv[], cJSON *j_command);
int dynsec_client__set_password(int argc, char *argv[], cJSON *j_command);

int dynsec_group__add_remove_client(int argc, char *argv[], cJSON *j_command, const char *command);
int dynsec_group__add_remove_role(int argc, char *argv[], cJSON *j_command, const char *command);
int dynsec_group__create(int argc, char *argv[], cJSON *j_command);
int dynsec_group__delete(int argc, char *argv[], cJSON *j_command);
int dynsec_group__get(int argc, char *argv[], cJSON *j_command);
int dynsec_group__list_all(int argc, char *argv[], cJSON *j_command);
int dynsec_group__set_anonymous(int argc, char *argv[], cJSON *j_command);
int dynsec_group__get_anonymous(int argc, char *argv[], cJSON *j_command);

int dynsec_role__create(int argc, char *argv[], cJSON *j_command);
int dynsec_role__delete(int argc, char *argv[], cJSON *j_command);
int dynsec_role__get(int argc, char *argv[], cJSON *j_command);
int dynsec_role__list_all(int argc, char *argv[], cJSON *j_command);
int dynsec_role__add_acl(int argc, char *argv[], cJSON *j_command);
int dynsec_role__remove_acl(int argc, char *argv[], cJSON *j_command);

/* Functions to implement as an external module: */
void ctrl_help(void);
int ctrl_main(int argc, char *argv[], struct mosq_ctrl *ctrl);

#endif
