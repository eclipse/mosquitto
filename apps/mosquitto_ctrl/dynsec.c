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
#include "config.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mosquitto_ctrl.h"
#include "mosquitto.h"
#include "password_mosq.h"
#include "get_password.h"

void dynsec__print_usage(void)
{
	printf("\nDynamic Security module\n");
	printf("=======================\n");
	printf("\nInitialisation\n--------------\n");
	printf("Create a new configuration file with an admin user:\n");
	printf("    mosquitto_ctrl dynsec init <new-config-file> <admin-username> [admin-password]\n");

	printf("\nGeneral\n-------\n");
	printf("Get ACL default access:          getDefaultACLAccess\n");
	printf("Set ACL default access:          setDefaultACLAccess <acltype> allow|deny\n");
	printf("Get group for anonymous clients: getAnonymousGroup\n");
	printf("Set group for anonymous clients: setAnonymousGroup   <groupname>\n");

	printf("\nClients\n-------\n");
	printf("Create a new client:         createClient      <username> [-c clientid] [-p password]\n");
	printf("Delete a client:             deleteClient      <username>\n");
	printf("Set a client password:       setClientPassword <username> [password]\n");
	printf("Set a client id:             setClientId       <username> [clientid]\n");
	printf("Add a role to a client:      addClientRole     <username> <rolename> [priority]\n");
	printf("    Higher priority (larger numerical value) roles are evaluated first.\n");
	printf("Remove role from a client:   removeClientRole  <username> <rolename>\n");
	printf("Get client information:      getClient         <username>\n");
	printf("List all clients:            listClients       [count [offset]]\n");
	printf("Enable client:               enableClient      <username>\n");
	printf("Disable client:              disableClient     <username>\n");

	printf("\nGroups\n------\n");
	printf("Create a new group:          createGroup       <groupname>\n");
	printf("Delete a group:              deleteGroup       <groupname>\n");
	printf("Add a role to a group:       addGroupRole      <groupname> <rolename> [priority]\n");
	printf("    Higher priority (larger numerical value) roles are evaluated first.\n");
	printf("Remove role from a group:    removeGroupRole   <groupname> <rolename>\n");
	printf("Add client to a group:       addGroupClient    <groupname> <username> [priority]\n");
	printf("    Priority sets the group priority for the given client only.\n");
	printf("    Higher priority (larger numerical value) groups are evaluated first.\n");
	printf("Remove client from a group:  removeGroupClient <groupname> <username>\n");
	printf("Get group information:       getGroup          <groupname>\n");
	printf("List all groups:             listGroups        [count [offset]]\n");

	printf("\nRoles\n------\n");
	printf("Create a new role:           createRole        <rolename>\n");
	printf("Delete a role:               deleteRole        <rolename>\n");
	printf("Add an ACL to a role:        addRoleACL        <rolename> <aclspec> [priority]\n");
	printf("    Higher priority (larger numerical value) ACLs are evaluated first.\n");
	printf("Remove ACL from a role:      removeRoleACL     <rolename> <aclspec>\n");
	printf("Get role information:        getRole           <rolename>\n");
	printf("List all roles:              listRoles         [count [offset]]\n");
	printf("\naclspec:                     <acltype> <topicFilter> allow|deny\n");
	printf("acltype:                     publishClientSend|publishClientReceive\n");
	printf("                              |subscribeLiteral|subscribePattern\n");
	printf("                              |unsubscribeLiteral|unsubscribePattern\n");
}

cJSON *cJSON_AddIntToObject(cJSON * const object, const char * const name, int number)
{
	char buf[30];

	snprintf(buf, sizeof(buf), "%d", number);
	return cJSON_AddRawToObject(object, name, buf);
}

/* ################################################################
 * #
 * # Payload callback
 * #
 * ################################################################ */

static void print_list(cJSON *j_response, const char *arrayname, const char *keyname)
{
	cJSON *j_data, *j_array, *j_elem, *j_name;

	j_data = cJSON_GetObjectItem(j_response, "data");
	if(j_data == NULL){
		fprintf(stderr, "Error: Invalid response from server.\n");
		return;
	}

	j_array = cJSON_GetObjectItem(j_data, arrayname);
	if(j_array == NULL || !cJSON_IsArray(j_array)){
		fprintf(stderr, "Error: Invalid response from server.\n");
		return;
	}

	cJSON_ArrayForEach(j_elem, j_array){
		if(cJSON_IsObject(j_elem)){
			j_name = cJSON_GetObjectItem(j_elem, keyname);
			if(j_name && cJSON_IsString(j_name)){
				printf("%s\n", j_name->valuestring);
			}
		}else if(cJSON_IsString(j_elem)){
			printf("%s\n", j_elem->valuestring);
		}
	}
}


static void print_client(cJSON *j_response)
{
	cJSON *j_data, *j_client, *j_array, *j_elem, *jtmp;
	bool first;

	j_data = cJSON_GetObjectItem(j_response, "data");
	if(j_data == NULL || !cJSON_IsObject(j_data)){
		fprintf(stderr, "Error: Invalid response from server.\n");
		return;
	}

	j_client = cJSON_GetObjectItem(j_data, "client");
	if(j_client == NULL || !cJSON_IsObject(j_client)){
		fprintf(stderr, "Error: Invalid response from server.\n");
		return;
	}

	jtmp = cJSON_GetObjectItem(j_client, "username");
	if(jtmp == NULL || !cJSON_IsString(jtmp)){
		fprintf(stderr, "Error: Invalid response from server.\n");
		return;
	}
	printf("Username: %s\n", jtmp->valuestring);

	jtmp = cJSON_GetObjectItem(j_client, "clientid");
	if(jtmp && cJSON_IsString(jtmp)){
		printf("Clientid: %s\n", jtmp->valuestring);
	}else{
		printf("Clientid:\n");
	}

	jtmp = cJSON_GetObjectItem(j_client, "disabled");
	if(jtmp && cJSON_IsBool(jtmp)){
		printf("Disabled: %s\n", cJSON_IsTrue(jtmp)?"true":"false");
	}

	j_array = cJSON_GetObjectItem(j_client, "roles");
	if(j_array && cJSON_IsArray(j_array)){
		first = true;
		cJSON_ArrayForEach(j_elem, j_array){
			jtmp = cJSON_GetObjectItem(j_elem, "rolename");
			if(jtmp && cJSON_IsString(jtmp)){
				if(first){
					first = false;
					printf("Roles:    %s", jtmp->valuestring);
				}else{
					printf("          %s", jtmp->valuestring);
				}
				jtmp = cJSON_GetObjectItem(j_elem, "priority");
				if(jtmp && cJSON_IsNumber(jtmp)){
					printf(" (priority: %d)", (int)jtmp->valuedouble);
				}else{
					printf(" (priority: -1)");
				}
				printf("\n");
			}
		}
	}else{
		printf("Roles:\n");
	}
	j_array = cJSON_GetObjectItem(j_client, "groups");
	if(j_array && cJSON_IsArray(j_array)){
		first = true;
		cJSON_ArrayForEach(j_elem, j_array){
			jtmp = cJSON_GetObjectItem(j_elem, "groupname");
			if(jtmp && cJSON_IsString(jtmp)){
				if(first){
					printf("Groups:   %s", jtmp->valuestring);
					first = false;
				}else{
					printf("          %s", jtmp->valuestring);
				}
				jtmp = cJSON_GetObjectItem(j_elem, "priority");
				if(jtmp && cJSON_IsNumber(jtmp)){
					printf(" (priority: %d)", (int)jtmp->valuedouble);
				}else{
					printf(" (priority: -1)");
				}
				printf("\n");
			}
		}
	}else{
		printf("Groups:\n");
	}
}


static void print_group(cJSON *j_response)
{
	cJSON *j_data, *j_group, *j_array, *j_elem, *jtmp;
	bool first;

	j_data = cJSON_GetObjectItem(j_response, "data");
	if(j_data == NULL || !cJSON_IsObject(j_data)){
		fprintf(stderr, "Error: Invalid response from server.\n");
		return;
	}

	j_group = cJSON_GetObjectItem(j_data, "group");
	if(j_group == NULL || !cJSON_IsObject(j_group)){
		fprintf(stderr, "Error: Invalid response from server.\n");
		return;
	}

	jtmp = cJSON_GetObjectItem(j_group, "groupname");
	if(jtmp == NULL || !cJSON_IsString(jtmp)){
		fprintf(stderr, "Error: Invalid response from server.\n");
		return;
	}
	printf("Groupname: %s\n", jtmp->valuestring);

	j_array = cJSON_GetObjectItem(j_group, "roles");
	if(j_array && cJSON_IsArray(j_array)){
		first = true;
		cJSON_ArrayForEach(j_elem, j_array){
			jtmp = cJSON_GetObjectItem(j_elem, "groupname");
			if(jtmp && cJSON_IsString(jtmp)){
				if(first){
					first = false;
					printf("Roles:  %s", jtmp->valuestring);
				}else{
					printf("    %s", jtmp->valuestring);
				}
				jtmp = cJSON_GetObjectItem(j_elem, "priority");
				if(jtmp && cJSON_IsNumber(jtmp)){
					printf(" (priority: %d)", (int)jtmp->valuedouble);
				}else{
					printf(" (priority: -1)");
				}
				printf("\n");
			}
		}
	}

	j_array = cJSON_GetObjectItem(j_group, "clients");
	if(j_array && cJSON_IsArray(j_array)){
		first = true;
		cJSON_ArrayForEach(j_elem, j_array){
			jtmp = cJSON_GetObjectItem(j_elem, "username");
			if(jtmp && cJSON_IsString(jtmp)){
				if(first){
					first = false;
					printf("Clients:   %s\n", jtmp->valuestring);
				}else{
					printf("           %s\n", jtmp->valuestring);
				}
			}
		}
	}
}


static void print_role(cJSON *j_response)
{
	cJSON *j_data, *j_role, *j_array, *j_elem, *jtmp;
	bool first;

	j_data = cJSON_GetObjectItem(j_response, "data");
	if(j_data == NULL || !cJSON_IsObject(j_data)){
		fprintf(stderr, "Error: Invalid response from server.\n");
		return;
	}

	j_role = cJSON_GetObjectItem(j_data, "role");
	if(j_role == NULL || !cJSON_IsObject(j_role)){
		fprintf(stderr, "Error: Invalid response from server.\n");
		return;
	}

	jtmp = cJSON_GetObjectItem(j_role, "rolename");
	if(jtmp == NULL || !cJSON_IsString(jtmp)){
		fprintf(stderr, "Error: Invalid response from server.\n");
		return;
	}
	printf("Rolename: %s\n", jtmp->valuestring);

	j_array = cJSON_GetObjectItem(j_role, "acls");
	if(j_array && cJSON_IsArray(j_array)){
		first = true;
		cJSON_ArrayForEach(j_elem, j_array){
			jtmp = cJSON_GetObjectItem(j_elem, "acltype");
			if(jtmp && cJSON_IsString(jtmp)){
				if(first){
					first = false;
					printf("ACLs:     %-20s", jtmp->valuestring);
				}else{
					printf("          %-20s", jtmp->valuestring);
				}

				jtmp = cJSON_GetObjectItem(j_elem, "allow");
				if(jtmp && cJSON_IsBool(jtmp)){
					printf(" : %s", cJSON_IsTrue(jtmp)?"allow":"deny ");
				}
				jtmp = cJSON_GetObjectItem(j_elem, "topic");
				if(jtmp && cJSON_IsString(jtmp)){
					printf(" : %s", jtmp->valuestring);
				}
				jtmp = cJSON_GetObjectItem(j_elem, "priority");
				if(jtmp && cJSON_IsNumber(jtmp)){
					printf(" (priority: %d)", (int)jtmp->valuedouble);
				}else{
					printf(" (priority: -1)");
				}
				printf("\n");
			}
		}
	}
}


static void print_anonymous_group(cJSON *j_response)
{
	cJSON *j_data, *j_group, *j_groupname;

	j_data = cJSON_GetObjectItem(j_response, "data");
	if(j_data == NULL || !cJSON_IsObject(j_data)){
		fprintf(stderr, "Error: Invalid response from server.\n");
		return;
	}

	j_group = cJSON_GetObjectItem(j_data, "group");
	if(j_group == NULL || !cJSON_IsObject(j_group)){
		fprintf(stderr, "Error: Invalid response from server.\n");
		return;
	}

	j_groupname = cJSON_GetObjectItem(j_group, "groupname");
	if(j_groupname == NULL || !cJSON_IsString(j_groupname)){
		fprintf(stderr, "Error: Invalid response from server.\n");
		return;
	}
	printf("%s\n", j_groupname->valuestring);
}

static void print_default_acl_access(cJSON *j_response)
{
	cJSON *j_data, *j_acls, *j_acl, *j_acltype, *j_allow;

	j_data = cJSON_GetObjectItem(j_response, "data");
	if(j_data == NULL || !cJSON_IsObject(j_data)){
		fprintf(stderr, "Error: Invalid response from server.\n");
		return;
	}

	j_acls = cJSON_GetObjectItem(j_data, "acls");
	if(j_acls == NULL || !cJSON_IsArray(j_acls)){
		fprintf(stderr, "Error: Invalid response from server.\n");
		return;
	}

	cJSON_ArrayForEach(j_acl, j_acls){
		j_acltype = cJSON_GetObjectItem(j_acl, "acltype");
		j_allow = cJSON_GetObjectItem(j_acl, "allow");

		if(j_acltype == NULL || !cJSON_IsString(j_acltype)
				|| j_allow == NULL || !cJSON_IsBool(j_allow)
				){
			
			fprintf(stderr, "Error: Invalid response from server.\n");
			return;
		}
		printf("%-20s : %s\n", j_acltype->valuestring, cJSON_IsTrue(j_allow)?"allow":"deny");
	}
}

static void dynsec__payload_callback(struct mosq_ctrl *ctrl, long payloadlen, const void *payload)
{
	cJSON *tree, *j_responses, *j_response, *j_command, *j_error;

	tree = cJSON_Parse(payload);
	if(tree == NULL){
		fprintf(stderr, "Error: Payload not JSON.\n");
		return;
	}

	j_responses = cJSON_GetObjectItem(tree, "responses");
	if(j_responses == NULL || !cJSON_IsArray(j_responses)){
		fprintf(stderr, "Error: Payload missing data.\n");
		cJSON_Delete(tree);
		return;
	}

	j_response = cJSON_GetArrayItem(j_responses, 0);
	if(j_response == NULL){
		fprintf(stderr, "Error: Payload missing data.\n");
		cJSON_Delete(tree);
		return;
	}

	j_command = cJSON_GetObjectItem(j_response, "command");
	if(j_command == NULL){
		fprintf(stderr, "Error: Payload missing data.\n");
		cJSON_Delete(tree);
		return;
	}

	j_error = cJSON_GetObjectItem(j_response, "error");
	if(j_error){
		fprintf(stderr, "%s: Error: %s\n", j_command->valuestring, j_error->valuestring);
	}else{
		if(!strcasecmp(j_command->valuestring, "listClients")){
			print_list(j_response, "clients", "username");
		}else if(!strcasecmp(j_command->valuestring, "listGroups")){
			print_list(j_response, "groups", "groupname");
		}else if(!strcasecmp(j_command->valuestring, "listRoles")){
			print_list(j_response, "roles", "rolename");
		}else if(!strcasecmp(j_command->valuestring, "getClient")){
			print_client(j_response);
		}else if(!strcasecmp(j_command->valuestring, "getGroup")){
			print_group(j_response);
		}else if(!strcasecmp(j_command->valuestring, "getRole")){
			print_role(j_response);
		}else if(!strcasecmp(j_command->valuestring, "getDefaultACLAccess")){
			print_default_acl_access(j_response);
		}else if(!strcasecmp(j_command->valuestring, "getAnonymousGroup")){
			print_anonymous_group(j_response);
		}else{
			//fprintf(stderr, "%s: Success\n", j_command->valuestring);
		}
	}
	cJSON_Delete(tree);
}

/* ################################################################
 * #
 * # Default ACL access
 * #
 * ################################################################ */

static int dynsec__set_default_acl_access(int argc, char *argv[], cJSON *j_command)
{
	char *acltype, *access;
	cJSON *j_acls, *j_acl;

	if(argc == 2){
		acltype = argv[0];
		access = argv[1];
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(strcasecmp(acltype, "publishClientSend")
			&& strcasecmp(acltype, "publishClientReceive")
			&& strcasecmp(acltype, "subscribe")
			&& strcasecmp(acltype, "unsubscribe")){

		return MOSQ_ERR_INVAL;
	}

	if(strcasecmp(access, "allow") && strcasecmp(access, "deny")){
		fprintf(stderr, "Error: access must be \"allow\" or \"deny\".\n");
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "setDefaultACLAccess") == NULL
			|| (j_acls = cJSON_AddArrayToObject(j_command, "acls")) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}

	j_acl = cJSON_CreateObject();
	if(j_acl == NULL){
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToArray(j_acls, j_acl);
	if(cJSON_AddStringToObject(j_acl, "acltype", acltype) == NULL
			|| cJSON_AddStringToObject(j_acl, "access", access) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}

	return MOSQ_ERR_SUCCESS;
}

static int dynsec__get_default_acl_access(int argc, char *argv[], cJSON *j_command)
{
	if(cJSON_AddStringToObject(j_command, "command", "getDefaultACLAccess") == NULL
			){

		return MOSQ_ERR_NOMEM;
	}

	return MOSQ_ERR_SUCCESS;
}

/* ################################################################
 * #
 * # Init
 * #
 * ################################################################ */

static cJSON *init_add_acl_to_role(cJSON *j_acls, const char *type, const char *topic)
{
	cJSON *j_acl;

	j_acl = cJSON_CreateObject();
	if(j_acl == NULL) return NULL;

	if(cJSON_AddStringToObject(j_acl, "acltype", type) == NULL
			|| cJSON_AddStringToObject(j_acl, "topic", topic) == NULL
			|| cJSON_AddBoolToObject(j_acl, "allow", true) == NULL
			){

		cJSON_Delete(j_acl);
		return NULL;
	}
	cJSON_AddItemToArray(j_acls, j_acl);
	return j_acl;
}

static cJSON *init_add_role(const char *rolename)
{
	cJSON *j_role, *j_acls;

	j_role = cJSON_CreateObject();
	if(j_role == NULL){
		return NULL;
	}
	if(cJSON_AddStringToObject(j_role, "rolename", rolename) == NULL){
		cJSON_Delete(j_role);
		return NULL;
	}

	j_acls = cJSON_CreateArray();
	if(j_acls == NULL){
		cJSON_Delete(j_role);
		return NULL;
	}
	cJSON_AddItemToObject(j_role, "acls", j_acls);
	if(init_add_acl_to_role(j_acls, "publishClientSend", "$CONTROL/dynamic-security/#") == NULL
			|| init_add_acl_to_role(j_acls, "publishClientReceive", "$CONTROL/dynamic-security/#") == NULL
			|| init_add_acl_to_role(j_acls, "subscribePattern", "$CONTROL/dynamic-security/#") == NULL
			|| init_add_acl_to_role(j_acls, "publishClientReceive", "$SYS/#") == NULL
			|| init_add_acl_to_role(j_acls, "subscribePattern", "$SYS/#") == NULL
			|| init_add_acl_to_role(j_acls, "publishClientReceive", "#") == NULL
			|| init_add_acl_to_role(j_acls, "subscribePattern", "#") == NULL
			|| init_add_acl_to_role(j_acls, "unsubscribePattern", "#") == NULL
			){

		cJSON_Delete(j_role);
		return NULL;
	}
	return j_role;
}

static cJSON *init_add_client(const char *username, const char *password, const char *rolename)
{
	cJSON *j_client, *j_roles, *j_role;
	struct mosquitto_pw pw;
	char *salt64 = NULL, *hash64 = NULL;
	char buf[10];

	memset(&pw, 0, sizeof(pw));
	pw.hashtype = pw_sha512_pbkdf2;

	if(pw__hash(password, &pw, true, PW_DEFAULT_ITERATIONS) != 0){
		return NULL;
	}
	if(base64__encode(pw.salt, sizeof(pw.salt), &salt64)
		|| base64__encode(pw.password_hash, sizeof(pw.password_hash), &hash64)
		){

		fprintf(stderr, "dynsec init: Internal error while encoding password.\n");
		free(salt64);
		free(hash64);
		return NULL;
	}

	j_client = cJSON_CreateObject();
	if(j_client == NULL){
		free(salt64);
		free(hash64);
		return NULL;
	}

	snprintf(buf, sizeof(buf), "%d", PW_DEFAULT_ITERATIONS);
	if(cJSON_AddStringToObject(j_client, "username", username) == NULL
			|| cJSON_AddStringToObject(j_client, "textName", "Dynsec admin user") == NULL
			|| cJSON_AddStringToObject(j_client, "password", hash64) == NULL
			|| cJSON_AddStringToObject(j_client, "salt", salt64) == NULL
			|| cJSON_AddRawToObject(j_client, "iterations", buf) == NULL
			){

		free(salt64);
		free(hash64);
		cJSON_Delete(j_client);
		return NULL;
	}
	free(salt64);
	free(hash64);

	j_roles = cJSON_CreateArray();
	if(j_roles == NULL){
		cJSON_Delete(j_client);
		return NULL;
	}
	cJSON_AddItemToObject(j_client, "roles", j_roles);

	j_role = cJSON_CreateObject();
	if(j_role == NULL){
		cJSON_Delete(j_client);
		return NULL;
	}
	cJSON_AddItemToArray(j_roles, j_role);
	if(cJSON_AddStringToObject(j_role, "rolename", rolename) == NULL){
		cJSON_Delete(j_client);
		return NULL;
	}

	return j_client;
}

static cJSON *init_create(const char *username, const char *password, const char *rolename)
{
	cJSON *tree, *j_clients, *j_client, *j_roles, *j_role;
	cJSON *j_default_access;

	tree = cJSON_CreateObject();
	if(tree == NULL) return NULL;

	if((j_clients = cJSON_AddArrayToObject(tree, "clients")) == NULL
			|| (j_roles = cJSON_AddArrayToObject(tree, "roles")) == NULL
			|| (j_default_access = cJSON_AddObjectToObject(tree, "defaultACLAccess")) == NULL
			){

		cJSON_Delete(tree);
		return NULL;
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

		cJSON_Delete(tree);
		return NULL;
	}

	j_client = init_add_client(username, password, rolename);
	if(j_client == NULL){
		cJSON_Delete(tree);
		return NULL;
	}
	cJSON_AddItemToArray(j_clients, j_client);

	j_role = init_add_role(rolename);
	if(j_role == NULL){
		cJSON_Delete(tree);
		return NULL;
	}
	cJSON_AddItemToArray(j_roles, j_role);

	return tree;
}

/* mosquitto_ctrl dynsec init <filename> <admin-user> <admin-password> [role-name] */
int dynsec_init(int argc, char *argv[])
{
	char *filename;
	char *admin_user;
	char *admin_password;
	char *json_str;
	cJSON *tree;
	FILE *fptr;
	char prompt[200], verify_prompt[200];
	char password[200];
	int rc;

	if(argc < 2){
		fprintf(stderr, "dynsec init: Not enough arguments - filename, or admin-user missing.\n");
		return MOSQ_ERR_INVAL;
	}

	if(argc > 3){
		fprintf(stderr, "dynsec init: Too many arguments.\n");
		return MOSQ_ERR_INVAL;
	}

	filename = argv[0];
	admin_user = argv[1];

	if(argc == 3){
		admin_password = argv[2];
	}else{
		snprintf(prompt, sizeof(prompt), "New password for %s: ", admin_user);
		snprintf(verify_prompt, sizeof(verify_prompt), "Reenter password for %s: ", admin_user);
		rc = get_password(prompt, verify_prompt, false, password, sizeof(password));
		if(rc){
			fprintf(stderr, "Error getting password.\n");
			mosquitto_lib_cleanup();
			return 1;
		}
		admin_password = password;
	}

	fptr = fopen(filename, "rb");
	if(fptr){
		fclose(fptr);
		fprintf(stderr, "dynsec init: '%s' already exists. Remove the file or use a different location..\n", filename);
		return -1;
	}

	tree = init_create(admin_user, admin_password, "admin");
	if(tree == NULL){
		fprintf(stderr, "dynsec init: Out of memory.\n");
		return MOSQ_ERR_NOMEM;
	}
	json_str = cJSON_Print(tree);
	cJSON_Delete(tree);

	fptr = fopen(filename, "wb");
	if(fptr){
		fprintf(fptr, "%s", json_str);
		free(json_str);
		fclose(fptr);
	}else{
		free(json_str);
		fprintf(stderr, "dynsec init: Unable to open '%s' for writing.\n", filename);
		return -1;
	}

	printf("The client '%s' has been created in the file '%s'.\n", admin_user, filename);
	printf("This client is configured to allow you to administer the dynamic security plugin only.\n");
	printf("It does not have access to publish messages to normal topics.\n");
	printf("You should create your application clients to do that, for example:\n");
	printf("   mosquitto_ctrl <connect options> dynsec createClient <username>\n");
	printf("   mosquitto_ctrl <connect options> dynsec createRole <rolename>\n");
	printf("   mosquitto_ctrl <connect options> dynsec addRoleACL <rolename> publishClientSend my/topic [priority]\n");
	printf("   mosquitto_ctrl <connect options> dynsec addClientRole <username> <rolename> [priority]\n");
	printf("See https://mosquitto.org/documentation/dynamic-security/ for details of all commands.\n");

	return -1; /* Suppress client connection */
}

/* ################################################################
 * #
 * # Main
 * #
 * ################################################################ */

int dynsec__main(int argc, char *argv[], struct mosq_ctrl *ctrl)
{
	int rc = -1;
	cJSON *j_tree;
	cJSON *j_commands, *j_command;

	if(!strcasecmp(argv[0], "help")){
		dynsec__print_usage();
		return -1;
	}else if(!strcasecmp(argv[0], "init")){
		return dynsec_init(argc-1, &argv[1]);
	}

	/* The remaining commands need a network connection and JSON command. */

	ctrl->payload_callback = dynsec__payload_callback;
	ctrl->request_topic = strdup("$CONTROL/dynamic-security/v1");
	ctrl->response_topic = strdup("$CONTROL/dynamic-security/v1/response");
	if(ctrl->request_topic == NULL || ctrl->response_topic == NULL){
		return MOSQ_ERR_NOMEM;
	}
	j_tree = cJSON_CreateObject();
	if(j_tree == NULL) return MOSQ_ERR_NOMEM;
	j_commands = cJSON_AddArrayToObject(j_tree, "commands");
	if(j_commands == NULL){
		cJSON_Delete(j_tree);
		j_tree = NULL;
		return MOSQ_ERR_NOMEM;
	}
	j_command = cJSON_CreateObject();
	if(j_command == NULL){
		cJSON_Delete(j_tree);
		j_tree = NULL;
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToArray(j_commands, j_command);

	if(!strcasecmp(argv[0], "setDefaultACLAccess")){
		rc = dynsec__set_default_acl_access(argc-1, &argv[1], j_command);
	}else if(!strcasecmp(argv[0], "getDefaultACLAccess")){
		rc = dynsec__get_default_acl_access(argc-1, &argv[1], j_command);

	}else if(!strcasecmp(argv[0], "createClient")){
		rc = dynsec_client__create(argc-1, &argv[1], j_command);
	}else if(!strcasecmp(argv[0], "deleteClient")){
		rc = dynsec_client__delete(argc-1, &argv[1], j_command);
	}else if(!strcasecmp(argv[0], "getClient")){
		rc = dynsec_client__get(argc-1, &argv[1], j_command);
	}else if(!strcasecmp(argv[0], "listClients")){
		rc = dynsec_client__list_all(argc-1, &argv[1], j_command);
	}else if(!strcasecmp(argv[0], "setClientId")){
		rc = dynsec_client__set_id(argc-1, &argv[1], j_command);
	}else if(!strcasecmp(argv[0], "setClientPassword")){
		rc = dynsec_client__set_password(argc-1, &argv[1], j_command);
	}else if(!strcasecmp(argv[0], "addClientRole")){
		rc = dynsec_client__add_remove_role(argc-1, &argv[1], j_command, argv[0]);
	}else if(!strcasecmp(argv[0], "removeClientRole")){
		rc = dynsec_client__add_remove_role(argc-1, &argv[1], j_command, argv[0]);
	}else if(!strcasecmp(argv[0], "enableClient")){
		rc = dynsec_client__enable_disable(argc-1, &argv[1], j_command, argv[0]);
	}else if(!strcasecmp(argv[0], "disableClient")){
		rc = dynsec_client__enable_disable(argc-1, &argv[1], j_command, argv[0]);

	}else if(!strcasecmp(argv[0], "createGroup")){
		rc = dynsec_group__create(argc-1, &argv[1], j_command);
	}else if(!strcasecmp(argv[0], "deleteGroup")){
		rc = dynsec_group__delete(argc-1, &argv[1], j_command);
	}else if(!strcasecmp(argv[0], "getGroup")){
		rc = dynsec_group__get(argc-1, &argv[1], j_command);
	}else if(!strcasecmp(argv[0], "listGroups")){
		rc = dynsec_group__list_all(argc-1, &argv[1], j_command);
	}else if(!strcasecmp(argv[0], "addGroupRole")){
		rc = dynsec_group__add_remove_role(argc-1, &argv[1], j_command, argv[0]);
	}else if(!strcasecmp(argv[0], "removeGroupRole")){
		rc = dynsec_group__add_remove_role(argc-1, &argv[1], j_command, argv[0]);
	}else if(!strcasecmp(argv[0], "addGroupClient")){
		rc = dynsec_group__add_remove_client(argc-1, &argv[1], j_command, argv[0]);
	}else if(!strcasecmp(argv[0], "removeGroupClient")){
		rc = dynsec_group__add_remove_client(argc-1, &argv[1], j_command, argv[0]);
	}else if(!strcasecmp(argv[0], "setAnonymousGroup")){
		rc = dynsec_group__set_anonymous(argc-1, &argv[1], j_command);
	}else if(!strcasecmp(argv[0], "getAnonymousGroup")){
		rc = dynsec_group__get_anonymous(argc-1, &argv[1], j_command);

	}else if(!strcasecmp(argv[0], "createRole")){
		rc = dynsec_role__create(argc-1, &argv[1], j_command);
	}else if(!strcasecmp(argv[0], "deleteRole")){
		rc = dynsec_role__delete(argc-1, &argv[1], j_command);
	}else if(!strcasecmp(argv[0], "getRole")){
		rc = dynsec_role__get(argc-1, &argv[1], j_command);
	}else if(!strcasecmp(argv[0], "listRoles")){
		rc = dynsec_role__list_all(argc-1, &argv[1], j_command);
	}else if(!strcasecmp(argv[0], "addRoleACL")){
		rc = dynsec_role__add_acl(argc-1, &argv[1], j_command);
	}else if(!strcasecmp(argv[0], "removeRoleACL")){
		rc = dynsec_role__remove_acl(argc-1, &argv[1], j_command);

	}else{
		fprintf(stderr, "Command '%s' not recognised.\n", argv[0]);
		return MOSQ_ERR_UNKNOWN;
	}

	if(rc == MOSQ_ERR_SUCCESS){
		ctrl->payload = cJSON_PrintUnformatted(j_tree);
		cJSON_Delete(j_tree);
		if(ctrl->payload == NULL){
			fprintf(stderr, "Error: Out of memory.\n");
			return MOSQ_ERR_NOMEM;
		}
	}
	return rc;
}
