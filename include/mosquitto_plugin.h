/*
Copyright (c) 2012-2020 Roger Light <roger@atchoo.org>

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

#ifndef MOSQUITTO_PLUGIN_H
#define MOSQUITTO_PLUGIN_H

#ifdef __cplusplus
extern "C" {
#endif

/* The generic plugin interface starts at version 5 */
#define MOSQ_PLUGIN_VERSION 5

/* The old auth only interface stopped at version 4 */
#define MOSQ_AUTH_PLUGIN_VERSION 4

#define MOSQ_ACL_NONE 0x00
#define MOSQ_ACL_READ 0x01
#define MOSQ_ACL_WRITE 0x02
#define MOSQ_ACL_SUBSCRIBE 0x04
#define MOSQ_ACL_UNSUBSCRIBE 0x08

#include <stdbool.h>
#include <stdint.h>

struct mosquitto;

struct mosquitto_opt {
	char *key;
	char *value;
};

struct mosquitto_auth_opt {
	char *key;
	char *value;
};

struct mosquitto_acl_msg {
	const char *topic;
	const void *payload;
	long payloadlen;
	int qos;
	bool retain;
};

#ifdef WIN32
#  define mosq_plugin_EXPORT __declspec(dllexport)
#else
#  define mosq_plugin_EXPORT
#endif

/*
 * To create an authentication plugin you must include this file then implement
 * the functions listed in the "Plugin Functions" section below. The resulting
 * code should then be compiled as a shared library. Using gcc this can be
 * achieved as follows:
 *
 * gcc -I<path to mosquitto_plugin.h> -fPIC -shared plugin.c -o plugin.so
 *
 * On Mac OS X:
 *
 * gcc -I<path to mosquitto_plugin.h> -fPIC -shared plugin.c -undefined dynamic_lookup -o plugin.so
 *
 * Authentication plugins can implement one or both of authentication and
 * access control. If your plugin does not wish to handle either of
 * authentication or access control it should return MOSQ_ERR_PLUGIN_DEFER. In
 * this case, the next plugin will handle it. If all plugins return
 * MOSQ_ERR_PLUGIN_DEFER, the request will be denied.
 *
 * For each check, the following flow happens:
 *
 * * The default password file and/or acl file checks are made. If either one
 *   of these is not defined, then they are considered to be deferred. If either
 *   one accepts the check, no further checks are made. If an error occurs, the
 *   check is denied
 * * The first plugin does the check, if it returns anything other than
 *   MOSQ_ERR_PLUGIN_DEFER, then the check returns immediately. If the plugin
 *   returns MOSQ_ERR_PLUGIN_DEFER then the next plugin runs its check.
 * * If the final plugin returns MOSQ_ERR_PLUGIN_DEFER, then access will be
 *   denied.
 */

/* =========================================================================
 *
 * Helper Functions
 *
 * ========================================================================= */

/* There are functions that are available for plugin developers to use in
 * mosquitto_broker.h, including logging and accessor functions.
 */


/* =========================================================================
 *
 * Plugin Functions v5
 *
 * This is the plugin version 5 interface, which covers authentication, access
 * control, the $CONTROL topic space handling, and message inspection and
 * modification.
 *
 * This interface is available from v2.0 onwards.
 *
 * There are just three functions to implement in your plugin. You should
 * register callbacks to handle different events in your
 * mosquitto_plugin_init() function. See mosquitto_broker.h for the events and
 * callback registering functions.
 *
 * ========================================================================= */

/*
 * Function: mosquitto_plugin_version
 *
 * The broker will attempt to call this function immediately after loading the
 * plugin to check it is a supported plugin version. Your code must simply
 * return the plugin interface version you support, i.e. 5.
 *
 * The supported_versions array tells you which plugin versions the broker supports.
 *
 * If the broker does not support the version that you require, return -1 to
 * indicate failure.
 */
mosq_plugin_EXPORT int mosquitto_plugin_version(int supported_version_count, const int *supported_versions);

/*
 * Function: mosquitto_auth_plugin_init
 *
 * Called after the plugin has been loaded and <mosquitto_plugin_version>
 * has been called. This will only ever be called once and can be used to
 * initialise the plugin.
 *
 * Parameters:
 *
 *  identifier :     This is a pointer to an opaque structure which you must
 *                   save and use when registering/unregistering callbacks.
 *	user_data :      The pointer set here will be passed to the other plugin
 *	                 functions. Use to hold connection information for example.
 *	opts :           Pointer to an array of struct mosquitto_opt, which
 *	                 provides the plugin options defined in the configuration file.
 *	opt_count :      The number of elements in the opts array.
 *
 * Return value:
 *	Return 0 on success
 *	Return >0 on failure.
 */
mosq_plugin_EXPORT int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **userdata, struct mosquitto_opt *options, int option_count);


/*
 * Function: mosquitto_plugin_cleanup
 *
 * Called when the broker is shutting down. This will only ever be called once
 * per plugin.
 *
 * Parameters:
 *
 *	user_data :      The pointer provided in <mosquitto_auth_plugin_init>.
 *	opts :           Pointer to an array of struct mosquitto_opt, which
 *	                 provides the plugin options defined in the configuration file.
 *	opt_count :      The number of elements in the opts array.
 *
 * Return value:
 *	Return 0 on success
 *	Return >0 on failure.
 */
mosq_plugin_EXPORT int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count);



/* =========================================================================
 *
 * Plugin Functions v4
 *
 * This is the plugin version 4 interface, which is exclusively for
 * authentication and access control, and which is still supported for existing
 * plugins. If you are developing a new plugin, please use the v5 interface.
 *
 * You must implement these functions in your plugin.
 *
 * ========================================================================= */

/*
 * Function: mosquitto_auth_plugin_version
 *
 * The broker will call this function immediately after loading the plugin to
 * check it is a supported plugin version. Your code must simply return
 * the version of the plugin interface you support, i.e. 4.
 */
mosq_plugin_EXPORT int mosquitto_auth_plugin_version(void);


/*
 * Function: mosquitto_auth_plugin_init
 *
 * Called after the plugin has been loaded and <mosquitto_auth_plugin_version>
 * has been called. This will only ever be called once and can be used to
 * initialise the plugin.
 *
 * Parameters:
 *
 *	user_data :      The pointer set here will be passed to the other plugin
 *	                 functions. Use to hold connection information for example.
 *	opts :           Pointer to an array of struct mosquitto_opt, which
 *	                 provides the plugin options defined in the configuration file.
 *	opt_count :      The number of elements in the opts array.
 *
 * Return value:
 *	Return 0 on success
 *	Return >0 on failure.
 */
mosq_plugin_EXPORT int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_opt *opts, int opt_count);


/*
 * Function: mosquitto_auth_plugin_cleanup
 *
 * Called when the broker is shutting down. This will only ever be called once
 * per plugin.
 * Note that <mosquitto_auth_security_cleanup> will be called directly before
 * this function.
 *
 * Parameters:
 *
 *	user_data :      The pointer provided in <mosquitto_auth_plugin_init>.
 *	opts :           Pointer to an array of struct mosquitto_opt, which
 *	                 provides the plugin options defined in the configuration file.
 *	opt_count :      The number of elements in the opts array.
 *
 * Return value:
 *	Return 0 on success
 *	Return >0 on failure.
 */
mosq_plugin_EXPORT int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count);


/*
 * Function: mosquitto_auth_security_init
 *
 * This function is called in two scenarios:
 *
 * 1. When the broker starts up.
 * 2. If the broker is requested to reload its configuration whilst running. In
 *    this case, <mosquitto_auth_security_cleanup> will be called first, then
 *    this function will be called.  In this situation, the reload parameter
 *    will be true.
 *
 * Parameters:
 *
 *	user_data :      The pointer provided in <mosquitto_auth_plugin_init>.
 *	opts :           Pointer to an array of struct mosquitto_opt, which
 *	                 provides the plugin options defined in the configuration file.
 *	opt_count :      The number of elements in the opts array.
 *	reload :         If set to false, this is the first time the function has
 *	                 been called. If true, the broker has received a signal
 *	                 asking to reload its configuration.
 *
 * Return value:
 *	Return 0 on success
 *	Return >0 on failure.
 */
mosq_plugin_EXPORT int mosquitto_auth_security_init(void *user_data, struct mosquitto_opt *opts, int opt_count, bool reload);


/* 
 * Function: mosquitto_auth_security_cleanup
 *
 * This function is called in two scenarios:
 *
 * 1. When the broker is shutting down.
 * 2. If the broker is requested to reload its configuration whilst running. In
 *    this case, this function will be called, followed by
 *    <mosquitto_auth_security_init>. In this situation, the reload parameter
 *    will be true.
 *
 * Parameters:
 *
 *	user_data :      The pointer provided in <mosquitto_auth_plugin_init>.
 *	opts :           Pointer to an array of struct mosquitto_opt, which
 *	                 provides the plugin options defined in the configuration file.
 *	opt_count :      The number of elements in the opts array.
 *	reload :         If set to false, this is the first time the function has
 *	                 been called. If true, the broker has received a signal
 *	                 asking to reload its configuration.
 *
 * Return value:
 *	Return 0 on success
 *	Return >0 on failure.
 */
mosq_plugin_EXPORT int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count, bool reload);


/*
 * Function: mosquitto_auth_acl_check
 *
 * Called by the broker when topic access must be checked. access will be one
 * of:
 *  MOSQ_ACL_SUBSCRIBE when a client is asking to subscribe to a topic string.
 *                     This differs from MOSQ_ACL_READ in that it allows you to
 *                     deny access to topic strings rather than by pattern. For
 *                     example, you may use MOSQ_ACL_SUBSCRIBE to deny
 *                     subscriptions to '#', but allow all topics in
 *                     MOSQ_ACL_READ. This allows clients to subscribe to any
 *                     topic they want, but not discover what topics are in use
 *                     on the server.
 *  MOSQ_ACL_READ      when a message is about to be sent to a client (i.e. whether
 *                     it can read that topic or not).
 *  MOSQ_ACL_WRITE     when a message has been received from a client (i.e. whether
 *                     it can write to that topic or not).
 *
 * Return:
 *	MOSQ_ERR_SUCCESS if access was granted.
 *	MOSQ_ERR_ACL_DENIED if access was not granted.
 *	MOSQ_ERR_UNKNOWN for an application specific error.
 *	MOSQ_ERR_PLUGIN_DEFER if your plugin does not wish to handle this check.
 */
mosq_plugin_EXPORT int mosquitto_auth_acl_check(void *user_data, int access, struct mosquitto *client, const struct mosquitto_acl_msg *msg);


/*
 * Function: mosquitto_auth_unpwd_check
 *
 * This function is OPTIONAL. Only include this function in your plugin if you
 * are making basic username/password checks.
 *
 * Called by the broker when a username/password must be checked.
 *
 * Return:
 *	MOSQ_ERR_SUCCESS if the user is authenticated.
 *	MOSQ_ERR_AUTH if authentication failed.
 *	MOSQ_ERR_UNKNOWN for an application specific error.
 *	MOSQ_ERR_PLUGIN_DEFER if your plugin does not wish to handle this check.
 */
mosq_plugin_EXPORT int mosquitto_auth_unpwd_check(void *user_data, struct mosquitto *client, const char *username, const char *password);


/*
 * Function: mosquitto_psk_key_get
 *
 * This function is OPTIONAL. Only include this function in your plugin if you
 * are making TLS-PSK checks.
 *
 * Called by the broker when a client connects to a listener using TLS/PSK.
 * This is used to retrieve the pre-shared-key associated with a client
 * identity.
 *
 * Examine hint and identity to determine the required PSK (which must be a
 * hexadecimal string with no leading "0x") and copy this string into key.
 *
 * Parameters:
 *	user_data :   the pointer provided in <mosquitto_auth_plugin_init>.
 *	hint :        the psk_hint for the listener the client is connecting to.
 *	identity :    the identity string provided by the client
 *	key :         a string where the hex PSK should be copied
 *	max_key_len : the size of key
 *
 * Return value:
 *	Return 0 on success.
 *	Return >0 on failure.
 *	Return MOSQ_ERR_PLUGIN_DEFER if your plugin does not wish to handle this check.
 */
mosq_plugin_EXPORT int mosquitto_auth_psk_key_get(void *user_data, struct mosquitto *client, const char *hint, const char *identity, char *key, int max_key_len);

/*
 * Function: mosquitto_auth_start
 *
 * This function is OPTIONAL. Only include this function in your plugin if you
 * are making extended authentication checks.
 *
 * Parameters:
 *	user_data :   the pointer provided in <mosquitto_auth_plugin_init>.
 *	method : the authentication method
 *	reauth : this is set to false if this is the first authentication attempt
 *	         on a connection, set to true if the client is attempting to
 *	         reauthenticate.
 *	data_in : pointer to authentication data, or NULL
 *	data_in_len : length of data_in, in bytes
 *	data_out : if your plugin wishes to send authentication data back to the
 *	           client, allocate some memory using malloc or friends and set
 *	           data_out. The broker will free the memory after use.
 *	data_out_len : Set the length of data_out in bytes.
 *
 * Return value:
 *	Return MOSQ_ERR_SUCCESS if authentication was successful.
 *	Return MOSQ_ERR_AUTH_CONTINUE if the authentication is a multi step process and can continue.
 *	Return MOSQ_ERR_AUTH if authentication was valid but did not succeed.
 *	Return any other relevant positive integer MOSQ_ERR_* to produce an error.
 */
mosq_plugin_EXPORT int mosquitto_auth_start(void *user_data, struct mosquitto *client, const char *method, bool reauth, const void *data_in, uint16_t data_in_len, void **data_out, uint16_t *data_out_len);

mosq_plugin_EXPORT int mosquitto_auth_continue(void *user_data, struct mosquitto *client, const char *method, const void *data_in, uint16_t data_in_len, void **data_out, uint16_t *data_out_len);


#ifdef __cplusplus
}
#endif

#endif
