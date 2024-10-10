/*
Copyright (c) 2023 Akos Vandra-Meyer <akos@vandra.hu>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR EDL-1.0

Contributors:
   Akos Vandra-Meyer - initial implementation and documentation.
*/

/*
 * This is an example plugin showing how to use the basic authentication
 * callback to allow/disallow client connections based on a HMAC-derived secret.
 *
 * This is useful for new clients to be able to connect to the broker without having
 * to change the configuration of the broker (the broker does not have to be aware or
 * keep a list of all users, and the users are able to be provided with a psk that they
 * can use to connect to the broker under their assigned username only).
 *
 * This is similar to a certificate, but without having to toss around large blobs of data,
 * which can be problematic in an embedded environment.
 *
 * (!) ClientIDs MUST be prefixed with the username.
 * Passwords for clients are derived by base64(HMAC_SHA256(supersecret, cilentid))
 * This can be done in the command line using: `echo -n "<clientid>" | openssl dgst -sha256 -hmac "<supersecret>" -binary | base64`
 *
 * Configuration:
 *   plugin_opt_hmac_secret_XXX - default supersecret for all clients connecting with username XXX, with clientIds starting with XXX
 *   plugin_opt_hmac_secret_YYY - default supersecret for all clients connecting with username YYY, with clientIds starting with YYY
 *
 *   usernames SHOULD NOT contain the separator character'-' to make them mutually exclusive and
 *   avoid a bunch of issues with ordering and precedence.
 *
 * Caveats:
 *  - clientids MUST be prefixed by the username and a hyphen.
 *  - Hyphens SHOULD not be used in username (or take extreme caution to keep them prefix-free)
 *  - if usernames are not prefix-free, the client given the password for clientid foo-bar-baz-quox-123 can connect as any the user foo, foo-bar, foo-bar-baz or foo-bar-baz-quox if they exist.
 *  - passwords cannot be changed (could add a salt in the password to generate new hashes, but old ones would still be valid)
 *  - once a user/pass is delivered, it cannot be revoked, even if the password is leaked (could implement a blacklist)
 *  - passwords currently never expire (although one could encode expiry it in the username / password as a salt, and check that when connecting)
 *  - probably good only for users with very limited/segregated access.

 * Note that this only works on Mosquitto 2.0 or later.
 */
#include "config.h"

#include <stdio.h>
#include <string.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "base64_mosq.h"


struct keyval {
	char *key;
	char *value;
};

struct plugin_config {
	//A hash would probably be a good choice as well,
	//but it is not expected to have more than a few items in this list,
	//so it would be more of an overhead than a benefit.
	struct keyval* users;
};

static void free_plugin_cfg(struct plugin_config* cfg) {
	if (cfg == NULL) {
		return;
	}

	int i = 0;

	while(cfg->users && cfg->users[i].key && cfg->users[i].value) {
		mosquitto_free(cfg->users[i].key);
		mosquitto_free(cfg->users[i].value);
		i++;
	}

	mosquitto_free(cfg->users);
	mosquitto_free(cfg);
}

static mosquitto_plugin_id_t *mosq_pid = NULL;

static int basic_auth_callback(int event, void *event_data, void *userdata)
{
	UNUSED(event);

	struct mosquitto_evt_basic_auth *ed = event_data;
	struct plugin_config *cfg = userdata;

	char* client_id = mosquitto_client_id(ed->client);

	if (ed->password == NULL) {
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "auth_by_hmac: no password received, deferring authentication");
		return MOSQ_ERR_PLUGIN_DEFER;
	}

	//If ClientID does not start with the username and a hyphen
	if ((strlen(client_id) <= strlen(ed->username) + 1) || strstr(client_id, ed->username) != client_id || client_id[strlen(ed->username)] != '-') {
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "auth_by_hmac: clientId does not start with a known username and hyphen, deferring authentication");
		return MOSQ_ERR_PLUGIN_DEFER;
	}

	int i = 0;

	while(cfg->users && cfg->users[i].key && cfg->users[i].value) {
		if (strstr(ed->username, cfg->users[i].key) == ed->username) {
			break;
		}

		i++;
	}

	char* supersecret = NULL;

	if (cfg->users && cfg->users[i].value) {
		 supersecret = cfg->users[i].value;
   }

   if (supersecret == NULL) {
	    mosquitto_log_printf(MOSQ_LOG_DEBUG, "auth_by_hmac: no supersecret set up for this username, deferring authentication");
	    return MOSQ_ERR_PLUGIN_DEFER;
   }

	unsigned int hmaclen = 32;
	unsigned char* hmac = mosquitto_calloc(sizeof(unsigned char), hmaclen);

	HMAC(EVP_sha256(), supersecret, (int)strlen(supersecret), mosquitto_client_id(ed->client), strlen(mosquitto_client_id(ed->client)), hmac, &hmaclen);

    char* hmac_b64;

	base64__encode(hmac, hmaclen, &hmac_b64);

	mosquitto_free(hmac);

    mosquitto_log_printf(MOSQ_LOG_DEBUG, "Supersecret is %s, expected %s, Got %s\n", supersecret, hmac_b64, ed->password);

	int ret = (hmac_b64 != NULL && (strcmp(hmac_b64, ed->password) == 0)) ? MOSQ_ERR_SUCCESS : MOSQ_ERR_PLUGIN_DEFER;

	mosquitto_free(hmac_b64);

	return ret;
}

int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)
{
	int i;

	for(i=0; i<supported_version_count; i++){
		if(supported_versions[i] == 5){
			return 5;
		}
	}
	return -1;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{;
	UNUSED(user_data);

	struct plugin_config* cfg = mosquitto_calloc(sizeof(struct plugin_config), 1);

	if (!cfg) {
		return MOSQ_ERR_NOMEM;
	}

	unsigned int prefix_count = 0;

	for(int i=0; i<opt_count; i++) {
		if (strstr(opts[i].key, "hmac_secret_")) { prefix_count++; }

		// Disallow the '-' character in the prefixes to prevent a bunch of problems with ordering and precedence.
		if (strstr(opts[i].key, "-")) {
			mosquitto_log_printf(MOSQ_LOG_WARNING, "WARNING: auth_by_hmac: It is not allowed to have a '-' character in the prefix, ignoring %s", opts[i].key);
			prefix_count--;
		}
	}

	if (prefix_count > 0) {
		cfg->users = mosquitto_calloc(sizeof(struct keyval), prefix_count + 1);
	}

	for(int i=0; i<opt_count; i++){
		if (strstr(opts[i].key, "hmac_secret_") == opts[i].key) {

			// Disallow the '-' character in the prefixes to prevent a bunch of problems with ordering and precedence.
			if (strstr(opts[i].key, "-")) { continue; }

			// Fill from back because the order of prefixes does not count,
			// as they are mutually exclusive, because it is not allowed to have a '-' character in the prefix.

			prefix_count--;
			cfg->users[prefix_count].key = mosquitto_strdup(opts[i].key + strlen("hmac_secret_"));

			if (cfg->users[prefix_count].key == NULL) {
				free_plugin_cfg(cfg);
				return MOSQ_ERR_NOMEM;
			}

			cfg->users[prefix_count].value = mosquitto_strdup(opts[i].value);

			if (cfg->users[prefix_count].value == NULL) {
				free_plugin_cfg(cfg);
				return MOSQ_ERR_NOMEM;
			}

			mosquitto_log_printf(MOSQ_LOG_DEBUG, "auth_by_hmac: registering hmac_secret for prefix %s", cfg->users[prefix_count].key);
		}
	}

	if(cfg->users == NULL){
		mosquitto_log_printf(MOSQ_LOG_WARNING, "WARNING: Auth by HMAC has no global or prefixed hmac secrets defined. The plugin will not be activated.");
		free_plugin_cfg(cfg);
		return MOSQ_ERR_SUCCESS;
	}

	*user_data = cfg;

	mosq_pid = identifier;
	return mosquitto_callback_register(mosq_pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL, cfg);
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
	free_plugin_cfg(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	return mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL);
}
