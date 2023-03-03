/*
Copyright (c) 2022 Roger Light <roger@atchoo.org>

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

/*
 * This is an example plugin that inspects payloads before they are published.
 * On matching payload, the publish is denied, the IP address of the client
 * added to a log file that can be used with fail2ban or similar to ban the
 * client connection, and the client kicked.
 *
 * This was developed in response to an obnoxious campaign by an MQTT client
 * that was republishing spam advertising messages to every retained message on
 * test.mosquitto.org
 *
 * Compile with:
 *   gcc -I<path to mosquitto-repo/include> -fPIC -shared mosquitto_payload_ban.c -o mosquitto_payload_ban.so
 *
 * Use in config with:
 *
 *   plugin /path/to/mosquitto_payload_ban.so
 *
 * Note that this only works on Mosquitto 2.0 or later.
 */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <uthash.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

#define PLUGIN_NAME "payload-ban"
#define PLUGIN_VERSION "1.0"

struct banlist{
	UT_hash_handle hh_by_address;
	UT_hash_handle hh_by_id;
	char ip_address[50];
	char clientid[];
};

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

static mosquitto_plugin_id_t *mosq_pid = NULL;
static struct banlist *banlist_by_address = NULL;
static struct banlist *banlist_by_id = NULL;

static int basic_auth_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_basic_auth *ed = event_data;
	struct banlist *entry;
	const char *ip_address;
	const char *clientid;

	UNUSED(event);
	UNUSED(userdata);

	ip_address = mosquitto_client_address(ed->client);
	if(ip_address){
		HASH_FIND(hh_by_address, banlist_by_address, ip_address, strlen(ip_address), entry);
		if(entry){
			return MOSQ_ERR_AUTH;
		}
	}
	clientid = mosquitto_client_id(ed->client);
	if(clientid){
		HASH_FIND(hh_by_id, banlist_by_id, clientid, strlen(clientid), entry);
		if(entry){
			return MOSQ_ERR_AUTH;
		}
	}

	return MOSQ_ERR_SUCCESS;
}


static int acl_check_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_acl_check *ed = event_data;
	struct banlist *new_entry = NULL, *entry;
	const char *clientid, *ip_address;
	FILE *fptr;

	UNUSED(event);
	UNUSED(userdata);

	if(ed->payload && ed->payloadlen > sizeof("Tired of using an old outdated MQTT client")){
		if(!strncmp(ed->payload, "Tired of using an old outdated MQTT client", strlen("Tired of using an old outdated MQTT client"))){
			ip_address = mosquitto_client_address(ed->client);
			clientid = mosquitto_client_id(ed->client);

			HASH_FIND(hh_by_address, banlist_by_address, ip_address, strlen(ip_address), entry);
			if(entry){
				mosquitto_kick_client_by_clientid(clientid, false);
				return MOSQ_ERR_ACL_DENIED;
			}
			new_entry = calloc(1, sizeof(struct banlist)+strlen(clientid) + 1);
			if(!new_entry){
				return MOSQ_ERR_ACL_DENIED;
			}
			strcpy(new_entry->clientid, clientid);
			strncpy(new_entry->ip_address, ip_address, sizeof(new_entry->ip_address)-1);
			HASH_ADD(hh_by_id, banlist_by_id, clientid, strlen(clientid), new_entry);
			HASH_ADD(hh_by_address, banlist_by_address, ip_address, strlen(ip_address), new_entry);
			mosquitto_kick_client_by_clientid(clientid, false);
			fptr = fopen("/tmp/payload-banlist", "at");
			if(fptr){
				fprintf(fptr, "%s || %s\n", ip_address, clientid);
				fclose(fptr);
			}
			return MOSQ_ERR_ACL_DENIED;
		}
	}

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	mosq_pid = identifier;
	mosquitto_plugin_set_info(identifier, PLUGIN_NAME, PLUGIN_VERSION);
	mosquitto_callback_register(mosq_pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL, NULL);
	mosquitto_callback_register(mosq_pid, MOSQ_EVT_ACL_CHECK, acl_check_callback, NULL, NULL);

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
	struct banlist *entry, *entry_tmp;

	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	HASH_ITER(hh_by_address, banlist_by_address, entry, entry_tmp){
		HASH_DELETE(hh_by_address, banlist_by_address, entry);
		HASH_DELETE(hh_by_id, banlist_by_id, entry);
		free(entry);
	}

	return MOSQ_ERR_SUCCESS;
}
