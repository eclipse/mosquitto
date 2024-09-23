/*
Copyright (c) 2021 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include <cjson/cJSON.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/rand.h>

#include "dynamic_security.h"
#include "json_help.h"

const char pw_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-=_+[]{}@#~,./<>?";

static int add_default_access(cJSON *j_tree)
{
	cJSON *j_default_access;

	j_default_access = cJSON_AddObjectToObject(j_tree, "defaultACLAccess");
	if(j_default_access == NULL){
		return MOSQ_ERR_NOMEM;
	}
	/* Set default behaviour:
	 * * Client can not publish to the broker by default.
	 * * Broker *CAN* publish to the client by default.
	 * * Client con not subscribe to topics by default.
	 * * Client *CAN* unsubscribe from topics by default.
	 */
	if(cJSON_AddBoolToObject(j_default_access, "publishClientSend", false) == NULL
			|| cJSON_AddBoolToObject(j_default_access, "publishClientReceive", true) == NULL
			|| cJSON_AddBoolToObject(j_default_access, "subscribe", false) == NULL
			|| cJSON_AddBoolToObject(j_default_access, "unsubscribe", true) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}
	return MOSQ_ERR_SUCCESS;
}


static int get_password_from_init_file(struct dynsec__data *data, char **pw)
{
	FILE *fptr;
	char buf[1024];
	int pos;

	if(data->password_init_file == NULL){
		*pw = NULL;
		return MOSQ_ERR_SUCCESS;
	}
	fptr = mosquitto_fopen(data->password_init_file, "rt", true);
	if(!fptr){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Unable to get initial password from '%s', file not accessible.", data->password_init_file);
		return MOSQ_ERR_INVAL;
	}
	if(!fgets(buf, sizeof(buf), fptr)){
		fclose(fptr);
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Unable to get initial password from '%s', file empty.", data->password_init_file);
		return MOSQ_ERR_INVAL;
	}
	fclose(fptr);

	pos = (int)strlen(buf)-1;
	while(pos >= 0 && isspace(buf[pos])){
		buf[pos] = '\0';
		pos--;
	}
	if(strlen(buf) == 0){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Unable to get initial password from '%s', password is empty.", data->password_init_file);
		return MOSQ_ERR_INVAL;
	}
	*pw = strdup(buf);
	if(!*pw){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Unable to get initial password from '%s', out of memory.", data->password_init_file);
		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}


/* Generate a password for the admin user
 *
 * Uses passwords from, in order:
 *
 * * The password defined in the plugin_opt_password_init_file file
 * * The contents of the MOSQUITTO_DYNSEC_PASSWORD environment variable
 * * Randomly generated passwords for "admin", "user", stored in plain text at '<plugin_opt_config_file>.pw'
 */
static int generate_password(struct dynsec__data *data, cJSON *j_client, char **password)
{
	struct mosquitto_pw *pw;
	int i;
	unsigned char vb;
	unsigned long v;
	size_t len;
	char *pwenv;

	if(data->init_mode == dpwim_file){
		if(get_password_from_init_file(data, password)){
			return MOSQ_ERR_INVAL;
		}
	}else if(data->init_mode == dpwim_env){
		pwenv = getenv("MOSQUITTO_DYNSEC_PASSWORD");
		if(pwenv == NULL || strlen(pwenv) < 12){
			mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Not generating dynsec config, MOSQUITTO_DYNSEC_PASSWORD must be at least 12 characters.");
			return MOSQ_ERR_INVAL;
		}
		*password = strdup(pwenv);
		if(*password == NULL){
			return MOSQ_ERR_NOMEM;
		}
	}else{
		*password = malloc(21);
		if(*password == NULL){
			return MOSQ_ERR_NOMEM;
		}
		len = sizeof(pw_chars)-1;
		for(i=0; i<20; i++){
			do{
				if(RAND_bytes(&vb, 1) != 1){
					free(*password);
					return MOSQ_ERR_UNKNOWN;
				}
				v = vb;
			}while(v >= (RAND_MAX - (RAND_MAX % len)));
			(*password)[i] = pw_chars[v%len];
		}
		(*password)[20] = '\0';
	}

	if(mosquitto_pw_new(&pw, MOSQ_PW_DEFAULT) != MOSQ_ERR_SUCCESS
			|| mosquitto_pw_hash_encoded(pw, *password) != MOSQ_ERR_SUCCESS
			|| cJSON_AddStringToObject(j_client, "encoded_password", mosquitto_pw_get_encoded(pw)) == NULL){

		mosquitto_pw_cleanup(pw);
		free(*password);
		*password = NULL;
		return MOSQ_ERR_UNKNOWN;
	}

	mosquitto_pw_cleanup(pw);

	return MOSQ_ERR_SUCCESS;
}


static int client_role_add(cJSON *j_roles, const char *rolename)
{
	cJSON *j_role;

	j_role = cJSON_CreateObject();
	if(j_role == NULL){
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToArray(j_roles, j_role);
	if(cJSON_AddStringToObject(j_role, "rolename", rolename) == NULL){
		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}


static int client_add_admin(struct dynsec__data *data, FILE *pwfile, cJSON *j_clients)
{
	cJSON *j_client, *j_roles;
	char *password = NULL;

	j_client = cJSON_CreateObject();
	if(j_client == NULL){
		return MOSQ_ERR_NOMEM;
	}
	if(generate_password(data, j_client, &password)){
		cJSON_Delete(j_client);
		return MOSQ_ERR_UNKNOWN;
	}

	cJSON_AddItemToArray(j_clients, j_client);
	if(cJSON_AddStringToObject(j_client, "username", "admin") == NULL
			|| cJSON_AddStringToObject(j_client, "textname", "Admin user") == NULL
			|| (j_roles = cJSON_AddArrayToObject(j_client, "roles")) == NULL
			){

		cJSON_Delete(j_client);
		free(password);
		return MOSQ_ERR_NOMEM;
	}

	if(client_role_add(j_roles, "super-admin")
	        || client_role_add(j_roles, "sys-observe")
	        || client_role_add(j_roles, "topic-observe")){

		free(password);
		return MOSQ_ERR_NOMEM;
	}

	if(data->init_mode == dpwim_random){
		fprintf(pwfile, "admin %s\n", password);
	}
	free(password);

	return MOSQ_ERR_SUCCESS;
}

static int client_add_user(struct dynsec__data *data, FILE *pwfile, cJSON *j_clients)
{
	cJSON *j_client, *j_roles;
	char *password = NULL;

	if(data->init_mode != dpwim_random){
		return MOSQ_ERR_SUCCESS;
	}
	j_client = cJSON_CreateObject();
	if(j_client == NULL){
		return MOSQ_ERR_NOMEM;
	}

	if(generate_password(data, j_client, &password)){
		cJSON_Delete(j_client);
		return MOSQ_ERR_UNKNOWN;
	}

	if(cJSON_AddStringToObject(j_client, "username", "democlient") == NULL
			|| cJSON_AddStringToObject(j_client, "textname", "Demonstration client with full read/write access to the '#' topic hierarchy.") == NULL
			|| (j_roles = cJSON_AddArrayToObject(j_client, "roles")) == NULL
			){

		free(password);
		cJSON_Delete(j_client);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToArray(j_clients, j_client);

	if(client_role_add(j_roles, "client")){
		free(password);
		return MOSQ_ERR_NOMEM;
	}

	fprintf(pwfile, "democlient %s\n", password);
	free(password);

	return MOSQ_ERR_SUCCESS;
}

static int add_clients(struct dynsec__data *data, cJSON *j_tree)
{
	cJSON *j_clients;
	char *pwfile;
	size_t len;
	FILE *fptr = NULL;

	if(data->init_mode == dpwim_random){
		len = strlen(data->config_file) + 5;
		pwfile = malloc(len);
		if(pwfile == NULL){
			return MOSQ_ERR_NOMEM;
		}
		snprintf(pwfile, len, "%s.pw", data->config_file);
		fptr = mosquitto_fopen(pwfile, "wb", true);
		free(pwfile);
		if(fptr == NULL){
			return MOSQ_ERR_UNKNOWN;
		}
	}

	j_clients = cJSON_AddArrayToObject(j_tree, "clients");
	if(j_clients == NULL){
		if(fptr) fclose(fptr);
		return MOSQ_ERR_NOMEM;
	}

	if(client_add_admin(data, fptr, j_clients)
			|| client_add_user(data, fptr, j_clients)
			){

		if(fptr) fclose(fptr);
		return MOSQ_ERR_NOMEM;
	}

	if(fptr) fclose(fptr);
	return MOSQ_ERR_SUCCESS;
}


static int group_add_anon(cJSON *j_groups)
{
	cJSON *j_group;

	j_group = cJSON_CreateObject();
	if(j_group == NULL){
		return MOSQ_ERR_NOMEM;
	}

	cJSON_AddItemToArray(j_groups, j_group);
	if(cJSON_AddStringToObject(j_group, "groupname", "unauthenticated") == NULL
			|| cJSON_AddStringToObject(j_group, "textname", "Unauthenticated group") == NULL
			|| cJSON_AddStringToObject(j_group, "textdescription", "If unauthenticated access is allowed, this group can be used to define roles for clients that connect without a password.") == NULL
			|| cJSON_AddArrayToObject(j_group, "roles") == NULL
			){

		return MOSQ_ERR_NOMEM;
	}

	return MOSQ_ERR_SUCCESS;
}

static int add_groups(cJSON *j_tree)
{
	cJSON *j_groups;

	j_groups = cJSON_AddArrayToObject(j_tree, "groups");
	if(j_groups == NULL){
		return MOSQ_ERR_NOMEM;
	}

	return group_add_anon(j_groups);
}


static int acl_add(cJSON *j_acls, const char *acltype, const char *topic, int priority, bool allow)
{
	cJSON *j_acl;

	j_acl = cJSON_CreateObject();
	cJSON_AddItemToArray(j_acls, j_acl);
	if(cJSON_AddStringToObject(j_acl, "acltype", acltype) == NULL
			|| cJSON_AddStringToObject(j_acl, "topic", topic) == NULL
			|| cJSON_AddNumberToObject(j_acl, "priority", priority) == NULL
			|| cJSON_AddBoolToObject(j_acl, "allow", allow) == NULL
			){
		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

static int add_role_with_full_permission(cJSON *j_roles, const char *role_name, const char *text_description, const char *topic_pattern)
{
	cJSON *j_role, *j_acls;

	j_role = cJSON_CreateObject();
	if(j_role == NULL){
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToArray(j_roles, j_role);

	if(cJSON_AddStringToObject(j_role, "rolename", role_name) == NULL
		   || cJSON_AddStringToObject(j_role, "textdescription", text_description) == NULL
		   || (j_acls = cJSON_AddArrayToObject(j_role, "acls")) == NULL){
		return MOSQ_ERR_NOMEM;
	}

	if(acl_add(j_acls, "publishClientSend", topic_pattern, 0, true)
		|| acl_add(j_acls, "publishClientReceive", topic_pattern, 0, true)
		|| acl_add(j_acls, "subscribePattern", topic_pattern, 0, true)
		|| acl_add(j_acls, "unsubscribePattern", topic_pattern, 0, true)){
		return MOSQ_ERR_NOMEM;
	}
	return MOSQ_ERR_SUCCESS;
}

static int role_add_sys_notify(cJSON *j_roles)
{
	cJSON *j_role, *j_acls;

	j_role = cJSON_CreateObject();
	if(j_role == NULL){
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToArray(j_roles, j_role);

	if(cJSON_AddStringToObject(j_role, "rolename", "sys-notify") == NULL
			|| cJSON_AddStringToObject(j_role, "textdescription",
				"Allow bridges to publish connection state messages.") == NULL
			|| (j_acls = cJSON_AddArrayToObject(j_role, "acls")) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}

	if(acl_add(j_acls, "publishClientSend", "$SYS/broker/connection/%c/state", 0, true)
			){

		return MOSQ_ERR_NOMEM;
	}
	return MOSQ_ERR_SUCCESS;
}

static int role_add_sys_observe(cJSON *j_roles)
{
	cJSON *j_role, *j_acls;

	j_role = cJSON_CreateObject();
	if(j_role == NULL){
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToArray(j_roles, j_role);

	if(cJSON_AddStringToObject(j_role, "rolename", "sys-observe") == NULL
			|| cJSON_AddStringToObject(j_role, "textdescription",
				"Observe the $SYS topic hierarchy.") == NULL
			|| (j_acls = cJSON_AddArrayToObject(j_role, "acls")) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}

	if(acl_add(j_acls, "publishClientReceive", "$SYS/#", 0, true)
			|| acl_add(j_acls, "subscribePattern", "$SYS/#", 0, true)
			){

		return MOSQ_ERR_NOMEM;
	}
	return MOSQ_ERR_SUCCESS;
}

static int role_add_topic_observe(cJSON *j_roles)
{
	cJSON *j_role, *j_acls;

	j_role = cJSON_CreateObject();
	if(j_role == NULL){
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToArray(j_roles, j_role);

	if(cJSON_AddStringToObject(j_role, "rolename", "topic-observe") == NULL
			|| cJSON_AddStringToObject(j_role, "textdescription",
				"Read only access to the full application topic hierarchy.") == NULL
			|| (j_acls = cJSON_AddArrayToObject(j_role, "acls")) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}

	if(acl_add(j_acls, "publishClientReceive", "#", 0, true)
			|| acl_add(j_acls, "subscribePattern", "#", 0, true)
			|| acl_add(j_acls, "unsubscribePattern", "#", 0, true)
			){

		return MOSQ_ERR_NOMEM;
	}
	return MOSQ_ERR_SUCCESS;
}


static int add_roles(cJSON *j_tree)
{
	cJSON *j_roles;

	j_roles = cJSON_AddArrayToObject(j_tree, "roles");
	if(j_roles == NULL){
		return MOSQ_ERR_NOMEM;
	}

	if(add_role_with_full_permission(j_roles, "client", "Read/write access to the full application topic hierarchy.", "#")
		|| add_role_with_full_permission(j_roles, "broker-admin", "Grants access to administer general broker configuration.", "$CONTROL/broker/#")
		|| add_role_with_full_permission(j_roles, "dynsec-admin", "Grants access to administer clients/groups/roles.", "$CONTROL/dynamic-security/#")
		|| add_role_with_full_permission(j_roles, "super-admin", "Grants access to administer all kind of broker controls", "$CONTROL/#")
		|| role_add_sys_notify(j_roles) || role_add_sys_observe(j_roles) || role_add_topic_observe(j_roles)){
		return MOSQ_ERR_NOMEM;
	}

	return MOSQ_ERR_SUCCESS;
}


int dynsec__config_init(struct dynsec__data *data)
{
	FILE *fptr;
	cJSON *j_tree;
	char *json_str;

	mosquitto_log_printf(MOSQ_LOG_INFO, "Dynamic security plugin config not found, generating a default config.");

	if(data->password_init_file){
		mosquitto_log_printf(MOSQ_LOG_INFO, "  Using admin password from file '%s'", data->password_init_file);
		data->init_mode = dpwim_file;
	}else if(getenv("MOSQUITTO_DYNSEC_PASSWORD")){
		mosquitto_log_printf(MOSQ_LOG_INFO, "  Using admin password from MOSQUITTO_DYNSEC_PASSWORD environment variable");
		data->init_mode = dpwim_env;
	}else{
		mosquitto_log_printf(MOSQ_LOG_INFO, "  Generated passwords are at %s.pw", data->config_file);
		data->init_mode = dpwim_random;
	}

	j_tree = cJSON_CreateObject();
	if(j_tree == NULL){
		return MOSQ_ERR_NOMEM;
	}

	if(add_default_access(j_tree) != MOSQ_ERR_SUCCESS
			|| add_clients(data, j_tree) != MOSQ_ERR_SUCCESS
			|| add_groups(j_tree) != MOSQ_ERR_SUCCESS
			|| add_roles(j_tree) != MOSQ_ERR_SUCCESS
			|| cJSON_AddStringToObject(j_tree, "anonymousGroup", "unauthenticated") == NULL
			){

		cJSON_Delete(j_tree);
		return MOSQ_ERR_NOMEM;
	}

	json_str = cJSON_Print(j_tree);
	cJSON_Delete(j_tree);
	if(json_str == NULL){
		return MOSQ_ERR_NOMEM;
	}

	fptr = mosquitto_fopen(data->config_file, "wb", true);
	if(fptr == NULL){
		return MOSQ_ERR_UNKNOWN;
	}
	fprintf(fptr, "%s", json_str);
	free(json_str);
	fclose(fptr);

	return MOSQ_ERR_SUCCESS;
}
