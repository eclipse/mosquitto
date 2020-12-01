/*
Copyright (c) 2015-2020 Roger Light <roger@atchoo.org>

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

/* This is a skeleton authentication and access control plugin that print a
 * message when each check occurs. It allows everything. */

#include <stdio.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"

#define ANSI_GREEN "\e[0;32m"
#define ANSI_BLUE "\e[0;34m"
#define ANSI_MAGENTA "\e[0;35m"
#define ANSI_RESET "\e[0m"

void print_col(struct mosquitto *client)
{
	switch(mosquitto_client_protocol(client)){
		case mp_mqtt:
			printf("%s", ANSI_GREEN);
			break;
		case mp_websockets:
			printf("%s", ANSI_MAGENTA);
			break;
		default:
			break;
	}
}

int mosquitto_auth_plugin_version(void)
{
	printf(ANSI_BLUE "PLUGIN ::: mosquitto_auth_plugin_version()" ANSI_RESET "\n");
	return 4;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	printf(ANSI_BLUE "PLUGIN ::: mosquitto_auth_plugin_init(,,%d)" ANSI_RESET "\n", auth_opt_count);
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	printf(ANSI_BLUE "PLUGIN ::: mosquitto_auth_plugin_cleanup(,,%d)" ANSI_RESET "\n", auth_opt_count);
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count, bool reload)
{
	printf(ANSI_BLUE "PLUGIN ::: mosquitto_auth_security_init(,,%d, %d)" ANSI_RESET "\n", auth_opt_count, reload);
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count, bool reload)
{
	printf(ANSI_BLUE "PLUGIN ::: mosquitto_auth_security_cleanup(,,%d, %d)" ANSI_RESET "\n", auth_opt_count, reload);
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void *user_data, int access, struct mosquitto *client, const struct mosquitto_acl_msg *msg)
{
	print_col(client);
	printf("PLUGIN ::: mosquitto_auth_acl_check(%p, %d, %s, %s)" ANSI_RESET "\n",
			user_data, access, mosquitto_client_username(client), msg->topic);
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_unpwd_check(void *user_data, struct mosquitto *client, const char *username, const char *password)
{
	print_col(client);
	printf("PLUGIN ::: mosquitto_auth_unpwd_check(%p, %s, %s)" ANSI_RESET "\n",
			user_data, mosquitto_client_username(client), username);
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_psk_key_get(void *user_data, struct mosquitto *client, const char *hint, const char *identity, char *key, int max_key_len)
{
	print_col(client);
	printf("PLUGIN ::: mosquitto_auth_psk_key_get(%p, %s, %s)" ANSI_RESET "\n",
			user_data, mosquitto_client_username(client), hint);
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_start(void *user_data, struct mosquitto *client, const char *method, bool reauth, const void *data_in, uint16_t data_in_len, void **data_out, uint16_t *data_out_len)
{
	print_col(client);
	printf("PLUGIN ::: mosquitto_auth_start(%p, %s, %s, %d, %d, %hn)" ANSI_RESET "\n",
			user_data, mosquitto_client_username(client), method, reauth, data_in_len, data_out_len);
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_continue(void *user_data, struct mosquitto *client, const char *method, const void *data_in, uint16_t data_in_len, void **data_out, uint16_t *data_out_len)
{
	print_col(client);
	printf("PLUGIN ::: mosquitto_auth_continue(%p, %s, %s, %d, %hn)" ANSI_RESET "\n",
			user_data, mosquitto_client_username(client), method, data_in_len, data_out_len);
	return MOSQ_ERR_SUCCESS;
}
