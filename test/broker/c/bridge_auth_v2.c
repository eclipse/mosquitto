/*
Copyright (C) by ebblo Switzerland GmbH, CH-8212 Neuhausen, Switzerland

This project and the accompanying materials are made available under the 
terms of the Eclipse Public License 2.0 and 3-Clause BSD License which
accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0
and the 3-Clause BSD License is available at
   https://opensource.org/license/BSD-3-Clause

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
 - Thorsten Wendt <thorsten.wendt@ebblo.com> - Adding means for brigde authentication.
*/

/*
 * This plugin provides username/password for bridge authentication.
 * 
 * This test yields different results based on the specified bridge_name provided by the callback parameters
 * 
 * 1) bridge_name = "default_v2"
 *       username = "Marie"
 *       password = "Curie"
 *        returns = MOSQ_ERR_SUCCESS
 *      
 * 2) bridge_name = "defer_v2"
 *       username = <unchanged>
 *       password = <unchanged>
 *        returns = MOSQ_ERR_PLUGIN_DEFER
 *      
 * 3) bridge_name = "denied_v2"
 *       username = <unchanged>
 *       password = <unchanged>
 *        returns = MOSQ_ERR_ACL_DENIED
 *      
 * 4) bridge_name = <ALL OTHER BRIDGE NAMES>
 *       username = <unchanged>
 *       password = <unchanged>
 *        returns = MOSQ_ERR_NOT_FOUND
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mosquitto.h"

#include <config.h>

#define PLUGIN_NAME "bridge_auth_v2"
#define PLUGIN_VERSION "0.0.1"

#define AUTH_PLUGIN_USERNAME "Marie"
#define AUTH_PLUGIN_PASSWORD "Curie"

#define TEST_SETUP_DEFAULT "default_v2"
#define TEST_SETUP_DEFER "defer_v2"
#define TEST_SETUP_DENIED "denied_v2"

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

static mosquitto_plugin_id_t* mosq_pid = NULL;

static int basic_auth_v2_callback(int event, void* event_data, void* userdata)
{
  struct mosquitto_evt_load_bridge_cred* ed = event_data;

  UNUSED(event);
  UNUSED(userdata);

  if (!strcmp(ed->bridge_name, TEST_SETUP_DEFAULT)) {
    ed->username = mosquitto_strdup(AUTH_PLUGIN_USERNAME);
    ed->password = mosquitto_strdup(AUTH_PLUGIN_PASSWORD);
    return MOSQ_ERR_SUCCESS;
  }
  
  if (!strcmp(ed->bridge_name, TEST_SETUP_DEFER)) {
    return MOSQ_ERR_PLUGIN_DEFER;
  }

  if (!strcmp(ed->bridge_name, TEST_SETUP_DENIED)) {
    return MOSQ_ERR_AUTH_DENIED;
  }

  return MOSQ_ERR_NOT_FOUND;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t* identifier,
                          void** user_data,
                          struct mosquitto_opt* opts,
                          int opt_count)
{
  UNUSED(user_data);
  UNUSED(opts);
  UNUSED(opt_count);

  mosq_pid = identifier;
  mosquitto_plugin_set_info(identifier, PLUGIN_NAME, PLUGIN_VERSION);
  return mosquitto_callback_register(mosq_pid, MOSQ_EVT_LOAD_BRIDGE_CRED, basic_auth_v2_callback, NULL, NULL);
}

int mosquitto_plugin_cleanup(void* user_data, struct mosquitto_opt* opts, int opt_count)
{
  UNUSED(user_data);
  UNUSED(opts);
  UNUSED(opt_count);
  return MOSQ_ERR_SUCCESS;
}
