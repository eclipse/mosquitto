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
 * This is an example plugin showing how to use the authentication
 * callback to provide username and password for connecting a bridge to a broker.
 * 
 * This callback is called when a new bridge is going to be established.
 * 
 * The callback have to provide username/passwort. The broker (in bridge mode)
 * is going to use these credentials for authentication against the broker.
 * 
 * The following return values are supported:
 * 
 * MOSQ_ERR_SUCCESS      - This plugin provided username and password
 * MOSQ_ERR_PLUGIN_DEFER - This plugin is not able to provide username/password
 * MOSQ_ERR_AUTH_DENIED  - Authentication is denied by the plugin and                         
 * MOSQ_ERR_NOMEM        - Out of memory
 * 
 *
 * Compile with:
 *   gcc -I<path to mosquitto-repo/include> -fPIC -shared mosquitto_auth_by_bridge.c -o mosquitto_auth_by_bridge.so
 *
 * Use in config with:
 *
 *   plugin /path/to/mosquitto_auth_by_bridge.so
 *
 * Note that this only works on Mosquitto 2.1 or later.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mosquitto.h"

#include <config.h>

#define PLUGIN_NAME "auth-by-bridge"
#define PLUGIN_VERSION "0.0.1"

#define ENV_AUTH_PLUGIN_USER "AUTH_PLUGIN_USER"
#define ENV_AUTH_PLUGIN_PASS "AUTH_PLUGIN_PASS"

MOSQUITTO_PLUGIN_DECLARE_VERSION( 5 );

static mosquitto_plugin_id_t *mosq_pid = NULL;

static int basic_auth_callback(int event, void *event_data, void *userdata)
{
    struct mosquitto_evt_load_bridge_cred* ed = event_data;
    
    UNUSED( event );
    UNUSED( userdata );
    
    char* env_auth_plugin_user = getenv( ENV_AUTH_PLUGIN_USER );
    char* env_auth_plugin_pass = getenv( ENV_AUTH_PLUGIN_PASS );
    
    if ( ( env_auth_plugin_user && strlen( env_auth_plugin_user ) > 0 ) &&
         ( env_auth_plugin_pass && strlen( env_auth_plugin_pass ) > 0 ) )
    {
      char* auth_plugin_username = mosquitto_strdup( env_auth_plugin_user );
      if ( !auth_plugin_username )
      {
        mosquitto_log_printf( MOSQ_LOG_ERR, "Out of memory." );
        return MOSQ_ERR_NOMEM;
      }
    
      char* auth_plugin_password = mosquitto_strdup( env_auth_plugin_pass );
      if ( !auth_plugin_password )
      {
        mosquitto_free( auth_plugin_username );
        mosquitto_log_printf( MOSQ_LOG_ERR, "Out of memory." );
        return MOSQ_ERR_NOMEM;
      }
    
      ed->username = auth_plugin_username;
      ed->password = auth_plugin_password;
      return MOSQ_ERR_SUCCESS;
    }
    
    return MOSQ_ERR_NOT_FOUND;
}


int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
    UNUSED( user_data );
    UNUSED( opts );
    UNUSED( opt_count );

    mosq_pid = identifier;
    mosquitto_plugin_set_info( identifier, PLUGIN_NAME, PLUGIN_VERSION );
    return mosquitto_callback_register( mosq_pid, MOSQ_EVT_LOAD_BRIDGE_CRED, basic_auth_callback, NULL, NULL );
}


/* mosquitto_plugin_cleanup() is optional in 2.1 and later. Use it only if you have your own cleanup to do */
int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
    UNUSED( user_data );
    UNUSED( opts );
    UNUSED( opt_count );

    return MOSQ_ERR_SUCCESS;
}
