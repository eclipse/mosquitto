/*
Copyright (c) 2023 Roger Light <roger@atchoo.org>

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
#include <config.h>

#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "ctrl_shell_internal.h"
#include "json_help.h"

#ifdef WITH_CTRL_SHELL

#define UNUSED(A) (void)(A)

static struct completion_tree_root *commands_dynsec = NULL;
static struct completion_tree_arg_list *tree_clients = NULL;
static struct completion_tree_arg_list *tree_groups = NULL;
static struct completion_tree_arg_list *tree_roles = NULL;
static bool do_print_list = false;


static void command_tree_create(void)
{
	struct completion_tree_cmd *cmd;
	struct completion_tree_arg_list *arg_list;
	struct completion_tree_arg_list *help_arg_list;

	completion_tree_arg_list_args_free(tree_clients);
	completion_tree_arg_list_args_free(tree_groups);
	completion_tree_arg_list_args_free(tree_roles);

	if(commands_dynsec){
		return;
	}

	commands_dynsec = calloc(1, sizeof(struct completion_tree_root));

	if(!tree_clients){
		tree_clients = completion_tree_cmd_new_arg_list();
		tree_clients->is_shared = true;
	}

	if(!tree_groups){
		tree_groups = completion_tree_cmd_new_arg_list();
		tree_groups->is_shared = true;
	}

	if(!tree_roles){
		tree_roles = completion_tree_cmd_new_arg_list();
		tree_roles->is_shared = true;
	}

	cmd = completion_tree_cmd_add(commands_dynsec, NULL, "help");
	help_arg_list = completion_tree_cmd_add_arg_list(cmd);

	cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "addClientRole");
	completion_tree_cmd_append_arg_list(cmd, tree_clients);
	completion_tree_cmd_append_arg_list(cmd, tree_roles);

	cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "addGroupClient");
	completion_tree_cmd_append_arg_list(cmd, tree_groups);
	completion_tree_cmd_append_arg_list(cmd, tree_clients);

	cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "addGroupRole");
	completion_tree_cmd_append_arg_list(cmd, tree_groups);
	completion_tree_cmd_append_arg_list(cmd, tree_roles);

	{
		cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "addRoleACL");
		completion_tree_cmd_append_arg_list(cmd, tree_roles);

		arg_list = completion_tree_cmd_add_arg_list(cmd);
		completion_tree_arg_list_add_arg(arg_list, "publishClientReceive");
		completion_tree_arg_list_add_arg(arg_list, "publishClientSend");
		completion_tree_arg_list_add_arg(arg_list, "subscribeLiteral");
		completion_tree_arg_list_add_arg(arg_list, "subscribePattern");
		completion_tree_arg_list_add_arg(arg_list, "unsubscribeLiteral");
		completion_tree_arg_list_add_arg(arg_list, "unsubscribePattern");

		arg_list = completion_tree_cmd_add_arg_list(cmd);
		completion_tree_arg_list_add_arg(arg_list, "allow");
		completion_tree_arg_list_add_arg(arg_list, "deny");
	}

	completion_tree_cmd_add(commands_dynsec, help_arg_list, "createClient");
	completion_tree_cmd_add(commands_dynsec, help_arg_list, "createGroup");
	completion_tree_cmd_add(commands_dynsec, help_arg_list, "createRole");

	cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "deleteClient");
	completion_tree_cmd_append_arg_list(cmd, tree_clients);

	cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "deleteGroup");
	completion_tree_cmd_append_arg_list(cmd, tree_groups);

	cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "deleteRole");
	completion_tree_cmd_append_arg_list(cmd, tree_roles);

	cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "disableClient");
	completion_tree_cmd_append_arg_list(cmd, tree_clients);

	cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "enableClient");
	completion_tree_cmd_append_arg_list(cmd, tree_clients);

	completion_tree_cmd_add(commands_dynsec, help_arg_list, "getAnonymousGroup");

	completion_tree_cmd_add(commands_dynsec, help_arg_list, "getDetails");

	cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "getClient");
	completion_tree_cmd_append_arg_list(cmd, tree_clients);

	completion_tree_cmd_add(commands_dynsec, help_arg_list, "getDefaultACLAccess");

	cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "getGroup");
	completion_tree_cmd_append_arg_list(cmd, tree_groups);

	cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "getRole");
	completion_tree_cmd_append_arg_list(cmd, tree_roles);

	completion_tree_cmd_add(commands_dynsec, help_arg_list, "listClients");
	completion_tree_cmd_add(commands_dynsec, help_arg_list, "listGroups");
	completion_tree_cmd_add(commands_dynsec, help_arg_list, "listRoles");

	cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "removeClientRole");
	completion_tree_cmd_append_arg_list(cmd, tree_clients);
	completion_tree_cmd_append_arg_list(cmd, tree_roles);

	cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "removeGroupClient");
	completion_tree_cmd_append_arg_list(cmd, tree_groups);
	completion_tree_cmd_append_arg_list(cmd, tree_clients);

	cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "removeGroupRole");
	completion_tree_cmd_append_arg_list(cmd, tree_groups);
	completion_tree_cmd_append_arg_list(cmd, tree_roles);

	{
		cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "removeRoleACL");
		completion_tree_cmd_append_arg_list(cmd, tree_roles);

		arg_list = completion_tree_cmd_add_arg_list(cmd);
		completion_tree_arg_list_add_arg(arg_list, "publishClientReceive");
		completion_tree_arg_list_add_arg(arg_list, "publishClientSend");
		completion_tree_arg_list_add_arg(arg_list, "subscribeLiteral");
		completion_tree_arg_list_add_arg(arg_list, "subscribePattern");
		completion_tree_arg_list_add_arg(arg_list, "unsubscribeLiteral");
		completion_tree_arg_list_add_arg(arg_list, "unsubscribePattern");
	}

	cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "setAnonymousGroup");
	completion_tree_cmd_append_arg_list(cmd, tree_groups);

	cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "setClientId");
	completion_tree_cmd_append_arg_list(cmd, tree_clients);

	cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "setClientPassword");
	completion_tree_cmd_append_arg_list(cmd, tree_clients);

	{
		cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "modifyClient");
		completion_tree_cmd_append_arg_list(cmd, tree_clients);

		arg_list = completion_tree_cmd_add_arg_list(cmd);
		completion_tree_arg_list_add_arg(arg_list, "textName");
		completion_tree_arg_list_add_arg(arg_list, "textDescription");
	}

	{
		cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "modifyGroup");
		completion_tree_cmd_append_arg_list(cmd, tree_groups);

		arg_list = completion_tree_cmd_add_arg_list(cmd);
		completion_tree_arg_list_add_arg(arg_list, "textName");
		completion_tree_arg_list_add_arg(arg_list, "textDescription");
	}

	{
		cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "modifyRole");
		completion_tree_cmd_append_arg_list(cmd, tree_roles);

		arg_list = completion_tree_cmd_add_arg_list(cmd);
		completion_tree_arg_list_add_arg(arg_list, "allowWildcardSubs");
		completion_tree_arg_list_add_arg(arg_list, "maxPublishSize");
		completion_tree_arg_list_add_arg(arg_list, "publishRateLimit");
		completion_tree_arg_list_add_arg(arg_list, "textName");
		completion_tree_arg_list_add_arg(arg_list, "textDescription");
	}

	{
		cmd = completion_tree_cmd_add(commands_dynsec, help_arg_list, "setDefaultACLAccess");

		arg_list = completion_tree_cmd_add_arg_list(cmd);
		completion_tree_arg_list_add_arg(arg_list, "publishClientReceive");
		completion_tree_arg_list_add_arg(arg_list, "publishClientSend");
		completion_tree_arg_list_add_arg(arg_list, "subscribe");
		completion_tree_arg_list_add_arg(arg_list, "unsubscribe");

		arg_list = completion_tree_cmd_add_arg_list(cmd);
		completion_tree_arg_list_add_arg(arg_list, "allow");
		completion_tree_arg_list_add_arg(arg_list, "deny");
	}

	completion_tree_cmd_add(commands_dynsec, help_arg_list, "disconnect");
	completion_tree_cmd_add(commands_dynsec, help_arg_list, "return");
	completion_tree_cmd_add(commands_dynsec, help_arg_list, "exit");
}


static void print_help(char **saveptr)
{
	char *command = strtok_r(NULL, " ", saveptr);
	if(command){
		if(!strcasecmp(command, "addClientRole")){
			ctrl_shell_print_help_command("addClientRole <username> <rolename>");
			ctrl_shell_printf("\nAdds a role directly to a client.\n");
		}else if(!strcasecmp(command, "addGroupClient")){
			ctrl_shell_print_help_command("addGroupClient <groupname> <username>");
			ctrl_shell_printf("\nAdds a client to a group.\n");
		}else if(!strcasecmp(command, "addGroupRole")){
			ctrl_shell_print_help_command("addGroupRole <groupname> <rolename>");
			ctrl_shell_printf("\nAdds a role to a group.\n");
		}else if(!strcasecmp(command, "addRoleACL")){
			ctrl_shell_print_help_command("addRoleACL <rolename> publishClientReceive allow|deny [priority] <topic>");
			ctrl_shell_print_help_command("addRoleACL <rolename> publishClientSend allow|deny [priority] <topic>");
			ctrl_shell_print_help_command("addRoleACL <rolename> subscribeLiteral allow|deny [priority] <topic>");
			ctrl_shell_print_help_command("addRoleACL <rolename> subscribePattern allow|deny [priority] <topic>");
			ctrl_shell_print_help_command("addRoleACL <rolename> unsubscribeLiteral allow|deny [priority] <topic>");
			ctrl_shell_print_help_command("addRoleACL <rolename> unsubscribePattern allow|deny [priority] <topic>");
			ctrl_shell_printf("\nAdds an ACL to a role, with an optional priority.\n");
			ctrl_shell_printf("\nACLs of a specific type within a role are processed in order from highest to lowest priority with the first matching ACL applying.\n");
		}else if(!strcasecmp(command, "createClient")){
			ctrl_shell_print_help_command("createClient <username> [password [clientid]]");
			ctrl_shell_printf("\nCreate a client with password and optional client id.\n");
		}else if(!strcasecmp(command, "createGroup")){
			ctrl_shell_print_help_command("createGroup <groupname>");
			ctrl_shell_printf("\nCreate a new group.\n");
		}else if(!strcasecmp(command, "createRole")){
			ctrl_shell_print_help_command("createRole <rolename>");
			ctrl_shell_printf("\nCreate a new role.\n");
		}else if(!strcasecmp(command, "deleteClient")){
			ctrl_shell_print_help_command("deleteClient <username>");
			ctrl_shell_printf("\nDelete a client\n");
		}else if(!strcasecmp(command, "deleteGroup")){
			ctrl_shell_print_help_command("deleteGroup <groupname>");
			ctrl_shell_printf("\nDelete a group\n");
		}else if(!strcasecmp(command, "deleteRole")){
			ctrl_shell_print_help_command("deleteRole <rolename>");
			ctrl_shell_printf("\nDelete a role\n");
		}else if(!strcasecmp(command, "disableClient")){
			ctrl_shell_print_help_command("disableClient <username>");
			ctrl_shell_printf("\nDisable a client. This client will not be able to log in, and will be kicked if it has an existing session.\n");
		}else if(!strcasecmp(command, "enableClient")){
			ctrl_shell_print_help_command("enableClient <username>");
			ctrl_shell_printf("\nEnable a client. Disabled clients are unable to log in.\n");
		}else if(!strcasecmp(command, "getAnonymousGroup")){
			ctrl_shell_print_help_command("getAnonymousGroup");
			ctrl_shell_printf("\nPrint the group configured as the anonymous group.\n");
		}else if(!strcasecmp(command, "getDetails")){
			ctrl_shell_print_help_command("getDetails");
			ctrl_shell_printf("\nPrint details including the client, group, and role count, and the current change index.\n");
		}else if(!strcasecmp(command, "getClient")){
			ctrl_shell_print_help_command("getClient <username>");
			ctrl_shell_printf("\nPrint details of a client and its groups and direct roles.\n");
		}else if(!strcasecmp(command, "getDefaultACLAccess")){
			ctrl_shell_print_help_command("getDefaultACLAccess");
			ctrl_shell_printf("\nPrint the default allow/deny values for the different classes of ACL.\n");
		}else if(!strcasecmp(command, "getGroup")){
			ctrl_shell_print_help_command("getGroup <groupname>");
			ctrl_shell_printf("\nPrint details of a group and its roles.\n");
		}else if(!strcasecmp(command, "getRole")){
			ctrl_shell_print_help_command("getRole <rolename>");
			ctrl_shell_printf("\nPrint details of a role and its ACLs.\n");
		}else if(!strcasecmp(command, "listClients")){
			ctrl_shell_print_help_command("listClients [count [offset]]");
			ctrl_shell_printf("\nPrint a list of clients configured in the dynsec plugin, with an optional total count and list offset.\n");
		}else if(!strcasecmp(command, "listGroups")){
			ctrl_shell_print_help_command("listGroups [count [offset]]");
			ctrl_shell_printf("\nPrint a list of groups configured in the dynsec plugin, with an optional total count and list offset.\n");
		}else if(!strcasecmp(command, "listRoles")){
			ctrl_shell_print_help_command("listRoles [count [offset]]");
			ctrl_shell_printf("\nPrint a list of roles configured in the dynsec plugin, with an optional total count and list offset.\n");
		}else if(!strcasecmp(command, "removeClientRole")){
			ctrl_shell_print_help_command("removeClientRole <username> <rolename>");
			ctrl_shell_printf("\nRemoves a role from a client, where the role was directly attached to the client.\n");
		}else if(!strcasecmp(command, "removeGroupClient")){
			ctrl_shell_print_help_command("removeGroupClient <groupname> <username>");
			ctrl_shell_printf("\nRemoves a client from a group.\n");
		}else if(!strcasecmp(command, "removeGroupRole")){
			ctrl_shell_print_help_command("removeGroupRole <groupname> <rolename>");
			ctrl_shell_printf("\nRemoves a role from a group.\n");
		}else if(!strcasecmp(command, "removeRoleACL")){
			ctrl_shell_print_help_command("removeRoleACL <rolename> publishClientReceive <topic>");
			ctrl_shell_print_help_command("removeRoleACL <rolename> publishClientSend <topic>");
			ctrl_shell_print_help_command("removeRoleACL <rolename> subscribeLiteral <topic>");
			ctrl_shell_print_help_command("removeRoleACL <rolename> subscribePattern <topic>");
			ctrl_shell_print_help_command("removeRoleACL <rolename> unsubscribeLiteral <topic>");
			ctrl_shell_print_help_command("removeRoleACL <rolename> unsubscribePattern <topic>");
			ctrl_shell_printf("\nRemoves an ACL from a role.\n");
		}else if(!strcasecmp(command, "setAnonymousGroup")){
			ctrl_shell_print_help_command("setAnonymousGroup <groupname>");
			ctrl_shell_printf("\nSets the anonymous group to a new group.\n");
		}else if(!strcasecmp(command, "setClientId")){
			ctrl_shell_print_help_command("setClientId <username>");
			ctrl_shell_print_help_command("setClientId <username> <clientid>");
			ctrl_shell_printf("\nSets or clears the clientid associated with a client. If a client has a clientid, all three of username, password, and clientid must match for a client to be able to authenticate.\n");
		}else if(!strcasecmp(command, "setClientPassword")){
			ctrl_shell_print_help_command("setClientPassword <username> [password]");
			ctrl_shell_printf("\nSets a new password for a client.\n");
		}else if(!strcasecmp(command, "setDefaultACLAccess")){
			ctrl_shell_print_help_command("setDefaultACLAccess publishClientReceive allow|deny");
			ctrl_shell_print_help_command("setDefaultACLAccess publishClientSend allow|deny");
			ctrl_shell_print_help_command("setDefaultACLAccess subscribe allow|deny");
			ctrl_shell_print_help_command("setDefaultACLAccess unsubscribe allow|deny");
			ctrl_shell_printf("\nSets the default ACL access to use for an ACL type. The default access will be applied if no other ACL rules match.\n");
			ctrl_shell_printf("Setting a rule to 'allow' means that if no ACLs match, it will be accepted.\n");
			ctrl_shell_printf("Setting a rule to 'deny' means that if no ACLs match, it will be denied.\n");
		}else if(!strcasecmp(command, "modifyClient")){
			ctrl_shell_print_help_command("modifyClient <username> textName <textname>");
			ctrl_shell_print_help_command("modifyClient <username> textDescription <textdescription>");
			ctrl_shell_printf("\nModify the text name or text description for a client.\n");
			ctrl_shell_printf("These are free-text fields for your own use.\n");
		}else if(!strcasecmp(command, "modifyGroup")){
			ctrl_shell_print_help_command("modifyGroup <groupname> textName <textname>");
			ctrl_shell_print_help_command("modifyGroup <groupname> textDescription <textdescription>");
			ctrl_shell_printf("\nModify the text name or text description for a group.\n");
			ctrl_shell_printf("These are free-text fields for your own use.\n");
		}else if(!strcasecmp(command, "modifyRole")){
			ctrl_shell_print_help_command("modifyRole <rolename> allowWildcardSubs true|false");
			ctrl_shell_print_help_command("modifyRole <rolename> maxPublishSize <bytes, or 0 to disable>");
			ctrl_shell_print_help_command("modifyRole <rolename> publishRateLimit {\"messages\":50,\"perSeconds\":1,\"burst\":200}|null");
			ctrl_shell_print_help_command("modifyRole <rolename> textName <textname>");
			ctrl_shell_print_help_command("modifyRole <rolename> textDescription <textdescription>");
			ctrl_shell_printf("\nModify the text name or text description for a role.\n");
			ctrl_shell_printf("These are free-text fields for your own use.\n");
		}else{
			ctrl_shell_print_help_final(command, "dynsec");
		}
	}else{
		ctrl_shell_printf("This is the mosquitto_ctrl interactive shell, for controlling aspects of a mosquitto broker.\n");
		ctrl_shell_printf("You are in dynsec mode, for controlling the dynamic-security clients, groups, and roles used in authentication and authorisation.\n");
		ctrl_shell_printf("Use '%sreturn%s' to leave dynsec mode.\n", ANSI_INPUT, ANSI_RESET);

		ctrl_shell_printf("Find help on a command using '%shelp <command>%s'\n", ANSI_INPUT, ANSI_RESET);
		ctrl_shell_printf("Press tab multiple times to find currently available commands.\n\n");
	}
}


static int send_set_default_acl_access(char **saveptr)
{
	const char *acltype, *allow_s;

	acltype = strtok_r(NULL, " ", saveptr);
	if(!acltype ||
			(
				strcasecmp(acltype, "publishClientReceive")
				&& strcasecmp(acltype, "publishClientSend")
				&& strcasecmp(acltype, "subscribe")
				&& strcasecmp(acltype, "unsubscribe")
			)){
		ctrl_shell_printf("setDefaultACLAccess acltype allow|deny\n");
		return MOSQ_ERR_INVAL;
	}

	allow_s = strtok_r(NULL, " ", saveptr);
	if(!allow_s ||
			(
				strcasecmp(allow_s, "allow")
				&& strcasecmp(allow_s, "deny")
			)){
		ctrl_shell_printf("setDefaultACLAccess acltype allow|deny\n");
		return MOSQ_ERR_INVAL;
	}

	cJSON *j_command = cJSON_CreateObject();
	cJSON_AddStringToObject(j_command, "command", "setDefaultACLAccess");
	cJSON *j_acls = cJSON_AddArrayToObject(j_command, "acls");
	cJSON *j_acl = cJSON_CreateObject();
	cJSON_AddItemToArray(j_acls, j_acl);
	cJSON_AddStringToObject(j_acl, "acltype", acltype);
	cJSON_AddBoolToObject(j_acl, "allow", !strcmp(allow_s, "allow"));

	return ctrl_shell_publish_blocking(j_command);
}


static int list_update(const char *command)
{
	cJSON *j_command = cJSON_CreateObject();
	cJSON_AddStringToObject(j_command, "command", command);

	do_print_list = false;

	return ctrl_shell_publish_blocking(j_command);
}


static int list_generic(const char *command, char **saveptr)
{
	const char *count, *offset;

	count = strtok_r(NULL, " ", saveptr);
	offset = strtok_r(NULL, " ", saveptr);

	cJSON *j_command = cJSON_CreateObject();
	cJSON_AddStringToObject(j_command, "command", command);
	if(count){
		cJSON_AddNumberToObject(j_command, "count", atoi(count));
	}
	if(offset){
		cJSON_AddNumberToObject(j_command, "offset", atoi(offset));
	}

	return ctrl_shell_publish_blocking(j_command);
}


static int send_create_client(char **saveptr)
{
	char *username = strtok_r(NULL, " ", saveptr);
	if(!username){
		ctrl_shell_printf("createClient username [password [clientid]]\n");
		ctrl_shell_printf("createClient username password [clientid]\n");
		return MOSQ_ERR_INVAL;
	}
	char *password = strtok_r(NULL, " ", saveptr);
	char pwbuf1[200];
	char pwbuf2[200];
	char *clientid = NULL;
	if(password){
		clientid = strtok_r(NULL, " ", saveptr);
	}else{
		if(!ctrl_shell_get_password(pwbuf1, sizeof(pwbuf1))
				|| !ctrl_shell_get_password(pwbuf2, sizeof(pwbuf2))){

			ctrl_shell_printf("No password.\n");
			return MOSQ_ERR_INVAL;
		}

		if(strcmp(pwbuf1, pwbuf2)){
			ctrl_shell_printf("Passwords do not match.\n");
			return MOSQ_ERR_INVAL;
		}

		password = pwbuf1;
	}

	cJSON *j_command = cJSON_CreateObject();
	cJSON_AddStringToObject(j_command, "command", "createClient");
	cJSON_AddStringToObject(j_command, "username", username);
	cJSON_AddStringToObject(j_command, "password", password);
	if(clientid){
		cJSON_AddStringToObject(j_command, "clientid", clientid);
	}
	ctrl_shell_publish_blocking(j_command);

	return MOSQ_ERR_SUCCESS;
}


static int send_add_role_acl(char **saveptr)
{
	char *rolename = strtok_r(NULL, " ", saveptr);
	char *acltype = strtok_r(NULL, " ", saveptr);
	char *allow_s = strtok_r(NULL, " ", saveptr);
	char *s_priority = strtok_r(NULL, " ", saveptr);
	char *topic = strtok_r(NULL, " ", saveptr);
	int priority = -1;

	if(s_priority){
		if(topic){
			priority = atoi(s_priority);
		}else{
			topic = s_priority;
		}
	}

	if(!rolename || !acltype || !allow_s || !topic){
		ctrl_shell_printf("addRoleACL rolename acltype allow|deny [priority] topic\n");
		return MOSQ_ERR_INVAL;
	}

	if(strcasecmp(acltype, "publishClientReceive")
			&& strcasecmp(acltype, "publishClientSend")
			&& strcasecmp(acltype, "subscribeLiteral")
			&& strcasecmp(acltype, "subscribePattern")
			&& strcasecmp(acltype, "unsubscribeLiteral")
			&& strcasecmp(acltype, "unsubscribePattern")
			){

		ctrl_shell_printf("addRoleACL rolename acltype allow|deny [priority] topic\n");
		ctrl_shell_printf("Invalid acltype '%s'\n", acltype);
		return MOSQ_ERR_INVAL;
	}

	if(strcasecmp(allow_s, "allow") && strcasecmp(allow_s, "deny")){
		ctrl_shell_printf("addRoleACL rolename acltype allow|deny [priority] topic\n");
		ctrl_shell_printf("Invalid allow/deny '%s'\n", allow_s);
		return MOSQ_ERR_INVAL;
	}

	cJSON *j_command = cJSON_CreateObject();
	cJSON_AddStringToObject(j_command, "command", "addRoleACL");
	cJSON_AddStringToObject(j_command, "rolename", rolename);
	cJSON_AddStringToObject(j_command, "acltype", acltype);
	cJSON_AddNumberToObject(j_command, "priority", priority);
	cJSON_AddStringToObject(j_command, "topic", topic);
	cJSON_AddBoolToObject(j_command, "allow", !strcasecmp(allow_s, "allow"));

	return ctrl_shell_publish_blocking(j_command);
}


static int send_remove_role_acl(char **saveptr)
{
	char *rolename = strtok_r(NULL, " ", saveptr);
	char *acltype = strtok_r(NULL, " ", saveptr);
	char *topic = strtok_r(NULL, " ", saveptr);

	if(!rolename || !acltype || !topic){
		ctrl_shell_printf("removeRoleACL rolename acltype topic\n");
		return MOSQ_ERR_INVAL;
	}

	if(strcasecmp(acltype, "publishClientReceive")
			&& strcasecmp(acltype, "publishClientSend")
			&& strcasecmp(acltype, "subscribeLiteral")
			&& strcasecmp(acltype, "subscribePattern")
			&& strcasecmp(acltype, "unsubscribeLiteral")
			&& strcasecmp(acltype, "unsubscribePattern")
			){


		ctrl_shell_printf("removeRoleACL rolename acltype topic\n");
		ctrl_shell_printf("Invalid acltype '%s'\n", acltype);
		return MOSQ_ERR_INVAL;
	}

	cJSON *j_command = cJSON_CreateObject();
	cJSON_AddStringToObject(j_command, "command", "removeRoleACL");
	cJSON_AddStringToObject(j_command, "rolename", rolename);
	cJSON_AddStringToObject(j_command, "acltype", acltype);
	cJSON_AddStringToObject(j_command, "topic", topic);

	return ctrl_shell_publish_blocking(j_command);

}


static int send_modify(const char *command, const char *objectname, char **saveptr)
{
	cJSON *j_value = NULL;
	char *name = strtok_r(NULL, " ", saveptr);
	char *itemlabel = strtok_r(NULL, " ", saveptr);
	char *itemvalue = *saveptr;
	if(!name || !itemlabel || !itemvalue){
		ctrl_shell_printf("%s %s <property> <value>\n", command, objectname);
		return MOSQ_ERR_INVAL;
	}

	bool publish_limit = !strcasecmp(command, "modifyRole")
			&& (!strcasecmp(itemlabel, "maxPublishSize") || !strcasecmp(itemlabel, "publishRateLimit"));
	if(!publish_limit && strcasecmp(itemlabel, "textName") && strcasecmp(itemlabel, "textDescription") && strcasecmp(itemlabel, "allowWildcardSubs")){
		ctrl_shell_printf("%s %s <property> <value>\n", command, objectname);
		ctrl_shell_printf("Unknown property '%s'\n", itemlabel);
		return MOSQ_ERR_INVAL;
	}

	if(!strcasecmp(itemlabel, "allowWildcardSubs")){
		if(strcasecmp(itemvalue, "true") && strcasecmp(itemvalue, "false")){
			ctrl_shell_printf("%s %s <property> <value>\n", command, objectname);
			ctrl_shell_printf("Invalid value '%s'\n", itemvalue);
			return MOSQ_ERR_INVAL;
		}
	}

	if(publish_limit){
		/* Preserve JSON numbers, objects and null for the broker's policy
		 * validation, and reject trailing text instead of sending a partial value. */
		j_value = cJSON_ParseWithOpts(itemvalue, NULL, true);
		if(!j_value
				|| (!strcasecmp(itemlabel, "maxPublishSize") && !cJSON_IsNumber(j_value))
				|| (!strcasecmp(itemlabel, "publishRateLimit") && !cJSON_IsObject(j_value) && !cJSON_IsNull(j_value))){
			cJSON_Delete(j_value);
			ctrl_shell_printf("Invalid publish limit '%s'\n", itemvalue);
			return MOSQ_ERR_INVAL;
		}
	}

	cJSON *j_command = cJSON_CreateObject();
	if(!j_command){
		cJSON_Delete(j_value);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddStringToObject(j_command, "command", command);
	cJSON_AddStringToObject(j_command, objectname, name);
	if(publish_limit){
		if(!cJSON_AddItemToObject(j_command, itemlabel, j_value)){
			cJSON_Delete(j_value);
			cJSON_Delete(j_command);
			return MOSQ_ERR_NOMEM;
		}
	}else if(!strcasecmp(itemlabel, "allowWildcardSubs")){
		cJSON_AddBoolToObject(j_command, itemlabel, !strcasecmp(itemvalue, "true"));
	}else{
		cJSON_AddStringToObject(j_command, itemlabel, itemvalue);
	}

	return ctrl_shell_publish_blocking(j_command);
}


static int send_set_client_password(char **saveptr)
{
	char *username, *password;
	char pwbuf1[200], pwbuf2[200];

	username = strtok_r(NULL, " ", saveptr);
	if(!username){
		ctrl_shell_printf("setClientPassword <username> [password]\n");
		return MOSQ_ERR_INVAL;
	}
	password = strtok_r(NULL, " ", saveptr);
	if(!password){
		if(!ctrl_shell_get_password(pwbuf1, sizeof(pwbuf1))
				|| !ctrl_shell_get_password(pwbuf2, sizeof(pwbuf2))){

			ctrl_shell_printf("No password.\n");
			return MOSQ_ERR_INVAL;
		}

		if(strcmp(pwbuf1, pwbuf2)){
			ctrl_shell_printf("Passwords do not match.\n");
			return MOSQ_ERR_INVAL;
		}

		password = pwbuf1;
	}

	cJSON *j_command = cJSON_CreateObject();
	cJSON_AddStringToObject(j_command, "command", "setClientPassword");
	cJSON_AddStringToObject(j_command, "username", username);
	cJSON_AddStringToObject(j_command, "password", password);

	return ctrl_shell_publish_blocking(j_command);
}


static void line_callback(char *line)
{
	if(!line){
		ctrl_shell_callback_final(NULL);
		return;
	}
	ctrl_shell_rtrim(line);
	if(strlen(line) > 0){
		add_history(line);
	}else{
		free(line);
		return;
	}

	char *saveptr = NULL;
	char *command = strtok_r(line, " ", &saveptr);

	if(!command){
		free(line);
		return;
	}

	if(!strcasecmp(command, "addClientRole")){
		ctrl_shell_command_generic_arg2("addClientRole", "username", "rolename", &saveptr);
	}else if(!strcasecmp(command, "addGroupClient")){
		ctrl_shell_command_generic_arg2("addGroupClient", "groupname", "username", &saveptr);
	}else if(!strcasecmp(command, "addGroupRole")){
		ctrl_shell_command_generic_arg2("addGroupRole", "groupname", "rolename", &saveptr);
	}else if(!strcasecmp(command, "addRoleACL")){
		send_add_role_acl(&saveptr);
	}else if(!strcasecmp(command, "createClient")){
		if(send_create_client(&saveptr) == MOSQ_ERR_SUCCESS){
			list_update("listClients");
		}
	}else if(!strcasecmp(command, "createGroup")){
		if(ctrl_shell_command_generic_arg1("createGroup", "groupname", &saveptr) == MOSQ_ERR_SUCCESS){
			list_update("listGroups");
		}
	}else if(!strcasecmp(command, "createRole")){
		if(ctrl_shell_command_generic_arg1("createRole", "rolename", &saveptr) == MOSQ_ERR_SUCCESS){
			list_update("listRoles");
		}
	}else if(!strcasecmp(command, "deleteClient")){
		if(ctrl_shell_command_generic_arg1("deleteClient", "username", &saveptr) == MOSQ_ERR_SUCCESS){
			list_update("listClients");
		}
	}else if(!strcasecmp(command, "deleteGroup")){
		if(ctrl_shell_command_generic_arg1("deleteGroup", "groupname", &saveptr) == MOSQ_ERR_SUCCESS){
			list_update("listGroups");
		}
	}else if(!strcasecmp(command, "deleteRole")){
		if(ctrl_shell_command_generic_arg1("deleteRole", "rolename", &saveptr) == MOSQ_ERR_SUCCESS){
			list_update("listRoles");
		}
	}else if(!strcasecmp(command, "disableClient")){
		ctrl_shell_command_generic_arg1("disableClient", "username", &saveptr);
	}else if(!strcasecmp(command, "enableClient")){
		ctrl_shell_command_generic_arg1("enableClient", "username", &saveptr);
	}else if(!strcasecmp(command, "getAnonymousGroup")){
		ctrl_shell_command_generic_arg0("getAnonymousGroup");
	}else if(!strcasecmp(command, "getDetails")){
		ctrl_shell_command_generic_arg0("getDetails");
	}else if(!strcasecmp(command, "getClient")){
		ctrl_shell_command_generic_arg1("getClient", "username", &saveptr);
	}else if(!strcasecmp(command, "getDefaultACLAccess")){
		ctrl_shell_command_generic_arg0("getDefaultACLAccess");
	}else if(!strcasecmp(command, "getGroup")){
		ctrl_shell_command_generic_arg1("getGroup", "groupname", &saveptr);
	}else if(!strcasecmp(command, "getRole")){
		ctrl_shell_command_generic_arg1("getRole", "rolename", &saveptr);
	}else if(!strcasecmp(command, "listClients")){
		do_print_list = true;
		list_generic("listClients", &saveptr);
	}else if(!strcasecmp(command, "listGroups")){
		do_print_list = true;
		list_generic("listGroups", &saveptr);
	}else if(!strcasecmp(command, "listRoles")){
		do_print_list = true;
		list_generic("listRoles", &saveptr);
	}else if(!strcasecmp(command, "removeClientRole")){
		ctrl_shell_command_generic_arg2("removeClientRole", "username", "rolename", &saveptr);
	}else if(!strcasecmp(command, "removeGroupClient")){
		ctrl_shell_command_generic_arg2("removeGroupClient", "groupname", "username", &saveptr);
	}else if(!strcasecmp(command, "removeGroupRole")){
		ctrl_shell_command_generic_arg2("removeGroupRole", "groupname", "rolename", &saveptr);
	}else if(!strcasecmp(command, "removeRoleACL")){
		send_remove_role_acl(&saveptr);
	}else if(!strcasecmp(command, "setAnonymousGroup")){
		ctrl_shell_command_generic_arg1("setAnonymousGroup", "groupname", &saveptr);
	}else if(!strcasecmp(command, "setClientId")){
		ctrl_shell_command_generic_arg2("setClientId", "username", "clientid", &saveptr);
	}else if(!strcasecmp(command, "setClientPassword")){
		send_set_client_password(&saveptr);
	}else if(!strcasecmp(command, "modifyClient")){
		send_modify("modifyClient", "username", &saveptr);
	}else if(!strcasecmp(command, "modifyGroup")){
		send_modify("modifyGroup", "groupname", &saveptr);
	}else if(!strcasecmp(command, "modifyRole")){
		send_modify("modifyRole", "rolename", &saveptr);
	}else if(!strcasecmp(command, "setDefaultACLAccess")){
		send_set_default_acl_access(&saveptr);
	}else if(!strcasecmp(command, "help")){
		print_help(&saveptr);
	}else{
		if(!ctrl_shell_callback_final(line)){
			ctrl_shell_printf("Unknown command '%s'\n", command);
		}
	}

	free(line);
}


static void print_json_value(cJSON *value, const char *null_value)
{
	if(value){
		if(cJSON_IsString(value)){
			if(value->valuestring){
				ctrl_shell_print_value(0, "%s", value->valuestring);
			}
		}else{
			char buffer[1024];
			cJSON_PrintPreallocated(value, buffer, sizeof(buffer), 0);
			ctrl_shell_print_value(0, "%s", buffer);
		}
	}else if(null_value){
		ctrl_shell_print_value(0, "%s", null_value);
	}
}


static void print_json_array(cJSON *j_list, const char *label, const char *element_name, const char *optional_element_name, const char *optional_element_null_value)
{
	cJSON *j_elem;

	if(j_list && cJSON_IsArray(j_list) && cJSON_GetArraySize(j_list) > 0){
		ctrl_shell_print_label(0, label);
		cJSON_ArrayForEach(j_elem, j_list){
			if(cJSON_IsObject(j_elem)){
				const char *stmp;
				if(json_get_string(j_elem, element_name, &stmp, false) != MOSQ_ERR_SUCCESS){
					continue;
				}
				ctrl_shell_print_value(1, "%s", stmp);
				if(optional_element_name){
					ctrl_shell_print_value(0, " (%s: ", optional_element_name);
					print_json_value(cJSON_GetObjectItem(j_elem, optional_element_name), optional_element_null_value);
					ctrl_shell_print_value(0, ")");
				}
			}else if(cJSON_IsString(j_elem) && j_elem->valuestring){
				ctrl_shell_print_value(1, "%s", j_elem->valuestring);
			}
			ctrl_shell_print_value(0, "\n");
		}
	}
}


static void print_details(cJSON *j_data)
{
	int64_t clientcount;
	int64_t groupcount;
	int64_t rolecount;
	int64_t changeindex;
	int align = (int)strlen("Change index: ");
	json_get_int64(j_data, "clientCount", &clientcount, true, 0);
	json_get_int64(j_data, "groupCount", &groupcount, true, 0);
	json_get_int64(j_data, "roleCount", &rolecount, true, 0);
	json_get_int64(j_data, "changeIndex", &changeindex, true, 0);

	ctrl_shell_print_label_value(0, "Client count:", align, "%ld\n", clientcount);
	ctrl_shell_print_label_value(0, "Group count:", align, "%ld\n", groupcount);
	ctrl_shell_print_label_value(0, "Role count:", align, "%ld\n", rolecount);
	ctrl_shell_print_label_value(0, "Change index:", align, "%ld\n", changeindex);
}


static void print_client(cJSON *j_data)
{
	cJSON *j_client, *jtmp;

	j_client = cJSON_GetObjectItem(j_data, "client");
	if(j_client == NULL){
		ctrl_shell_printf("Invalid response from broker.\n");
		return;
	}

	const char *username;
	if(json_get_string(j_client, "username", &username, false) != MOSQ_ERR_SUCCESS){
		ctrl_shell_printf("Invalid response from broker.\n");
		return;
	}
	ctrl_shell_print_label(0, "Username:");
	ctrl_shell_print_value(1, "%s\n", username);

	const char *clientid;
	if(json_get_string(j_client, "clientid", &clientid, false) == MOSQ_ERR_SUCCESS){
		ctrl_shell_print_label(0, "Clientid:");
		ctrl_shell_print_value(1, "%s\n", clientid);
	}

	jtmp = cJSON_GetObjectItem(j_client, "disabled");
	if(jtmp && cJSON_IsBool(jtmp) && cJSON_IsTrue(jtmp)){
		ctrl_shell_print_label(0, "Disabled:");
		ctrl_shell_print_value(1, "true\n");
	}

	const char *textname;
	if(json_get_string(j_client, "textname", &textname, false) == MOSQ_ERR_SUCCESS){
		ctrl_shell_print_label(0, "Text name:");
		ctrl_shell_print_value(1, "%s\n", textname);
	}

	const char *textdescription;
	if(json_get_string(j_client, "textdescription", &textdescription, false) == MOSQ_ERR_SUCCESS){
		ctrl_shell_print_label(0, "Text description:");
		ctrl_shell_print_value(1, "%s\n", textdescription);
	}

	print_json_array(cJSON_GetObjectItem(j_client, "roles"), "Roles:", "rolename", "priority", "-1");
	print_json_array(cJSON_GetObjectItem(j_client, "groups"), "Groups:", "groupname", "priority", "-1");
}


static void print_group(cJSON *j_data)
{
	cJSON *j_group;

	j_group = cJSON_GetObjectItem(j_data, "group");
	if(j_group == NULL){
		ctrl_shell_printf("Invalid response from broker.\n");
		return;
	}

	const char *groupname;
	if(json_get_string(j_group, "groupname", &groupname, false) != MOSQ_ERR_SUCCESS){
		ctrl_shell_printf("Invalid response from broker.\n");
		return;
	}
	ctrl_shell_print_label(0, "Group name:");
	ctrl_shell_print_value(1, "%s\n", groupname);

	const char *textname;
	if(json_get_string(j_group, "textname", &textname, false) == MOSQ_ERR_SUCCESS){
		ctrl_shell_print_label(0, "Text name:");
		ctrl_shell_print_value(1, "%s\n", textname);
	}

	const char *textdescription;
	if(json_get_string(j_group, "textdescription", &textdescription, false) == MOSQ_ERR_SUCCESS){
		ctrl_shell_print_label(0, "Text description:");
		ctrl_shell_print_value(1, "%s\n", textdescription);
	}

	print_json_array(cJSON_GetObjectItem(j_group, "roles"), "Roles:", "rolename", "priority", "-1");
	print_json_array(cJSON_GetObjectItem(j_group, "clients"), "Clients:", "username", NULL, NULL);
}


static void print_role(cJSON *j_data)
{
	cJSON *j_role;

	j_role = cJSON_GetObjectItem(j_data, "role");
	if(j_role == NULL){
		ctrl_shell_printf("Invalid response from broker.\n");
		return;
	}

	const char *rolename;
	if(json_get_string(j_role, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		ctrl_shell_printf("Invalid response from broker.\n");
		return;
	}
	ctrl_shell_print_label(0, "Role name:");
	ctrl_shell_print_value(1, "%s\n", rolename);

	const char *textname;
	if(json_get_string(j_role, "textname", &textname, false) == MOSQ_ERR_SUCCESS){
		ctrl_shell_print_label(0, "Text name:");
		ctrl_shell_print_value(1, "%s\n", textname);
	}

	const char *textdescription;
	if(json_get_string(j_role, "textdescription", &textdescription, false) == MOSQ_ERR_SUCCESS){
		ctrl_shell_print_label(0, "Text description:");
		ctrl_shell_print_value(1, "%s\n", textdescription);
	}

	bool allowwildcardsubs;
	if(json_get_bool(j_role, "allowwildcardsubs", &allowwildcardsubs, false, false) == MOSQ_ERR_SUCCESS){
		ctrl_shell_print_label(0, "Allow wildcard subscriptions:");
		ctrl_shell_print_value(1, "%s\n", allowwildcardsubs?"true":"false");
	}

	int max_publish_size, messages, per_seconds, burst;
	if(json_get_int(j_role, "maxPublishSize", &max_publish_size, false, 0) == MOSQ_ERR_SUCCESS){
		ctrl_shell_print_label(0, "Maximum publish payload:");
		ctrl_shell_print_value(1, "%d bytes\n", max_publish_size);
	}
	cJSON *j_rate = cJSON_GetObjectItem(j_role, "publishRateLimit");
	if(j_rate
			&& json_get_int(j_rate, "messages", &messages, false, 0) == MOSQ_ERR_SUCCESS
			&& json_get_int(j_rate, "perSeconds", &per_seconds, false, 0) == MOSQ_ERR_SUCCESS
			&& json_get_int(j_rate, "burst", &burst, false, 0) == MOSQ_ERR_SUCCESS){
		ctrl_shell_print_label(0, "Publish rate limit:");
		ctrl_shell_print_value(1, "%d messages per %d seconds, burst %d\n", messages, per_seconds, burst);
	}

	cJSON *j_acls = cJSON_GetObjectItem(j_role, "acls");
	if(j_acls && cJSON_GetArraySize(j_acls) > 0){
		ctrl_shell_print_label(0, "ACLs:");

		cJSON *j_acl;
		cJSON_ArrayForEach(j_acl, j_acls){
			const char *acltype;
			const char *topic;
			int priority;
			bool allow;

			if(json_get_string(j_acl, "acltype", &acltype, false) == MOSQ_ERR_SUCCESS
					&& json_get_string(j_acl, "topic", &topic, false) == MOSQ_ERR_SUCCESS
					&& json_get_int(j_acl, "priority", &priority, true, -1) == MOSQ_ERR_SUCCESS
					&& json_get_bool(j_acl, "allow", &allow, false, false) == MOSQ_ERR_SUCCESS
					){

				const char *ANSI_ALLOW = allow?ANSI_POSITIVE:ANSI_NEGATIVE;
				ctrl_shell_print_value(1, "%-*s %s%s%s %s%s%s (priority %d)\n", (int)strlen("publishClientReceive"), acltype, ANSI_ALLOW, allow?"allow":"deny", ANSI_RESET, ANSI_TOPIC, topic, ANSI_RESET, priority);
			}
		}
	}
}


static void print_default_acls(cJSON *j_data)
{
	cJSON *j_acls = cJSON_GetObjectItem(j_data, "acls");

	if(j_acls && cJSON_GetArraySize(j_acls) > 0){
		cJSON *j_acl;
		cJSON_ArrayForEach(j_acl, j_acls){
			const char *acltype;
			bool allow;

			if(json_get_string(j_acl, "acltype", &acltype, false) == MOSQ_ERR_SUCCESS
					&& json_get_bool(j_acl, "allow", &allow, false, false) == MOSQ_ERR_SUCCESS
					){

				ctrl_shell_print_value(0, "%-*s %s\n", (int)strlen("publishClientReceive"), acltype, allow?"allow":"deny");
			}
		}
	}
}


static void response_callback(const char *command, cJSON *j_data, const char *payload)
{
	UNUSED(payload);

	if(!strcmp(command, "listClients")){
		completion_tree_arg_list_args_free(tree_clients);

		cJSON *clients, *client;

		clients = cJSON_GetObjectItem(j_data, "clients");
		cJSON_ArrayForEach(client, clients){
			if(do_print_list){
				ctrl_shell_print_value(0, "%s\n", client->valuestring);
			}
			completion_tree_arg_list_add_arg(tree_clients, client->valuestring);
		}
		do_print_list = false;
	}else if(!strcmp(command, "listGroups")){
		completion_tree_arg_list_args_free(tree_groups);

		cJSON *groups, *group;

		groups = cJSON_GetObjectItem(j_data, "groups");
		cJSON_ArrayForEach(group, groups){
			if(do_print_list){
				ctrl_shell_print_value(0, "%s\n", group->valuestring);
			}
			completion_tree_arg_list_add_arg(tree_groups, group->valuestring);
		}
		do_print_list = false;
	}else if(!strcmp(command, "listRoles")){
		completion_tree_arg_list_args_free(tree_roles);

		cJSON *roles, *role;

		roles = cJSON_GetObjectItem(j_data, "roles");
		cJSON_ArrayForEach(role, roles){
			if(do_print_list){
				ctrl_shell_print_value(0, "%s\n", role->valuestring);
			}
			completion_tree_arg_list_add_arg(tree_roles, role->valuestring);
		}
		do_print_list = false;
	}else if(!strcasecmp(command, "getAnonymousGroup")){
		cJSON *group, *groupname;

		group = cJSON_GetObjectItem(j_data, "group");
		groupname = cJSON_GetObjectItem(group, "groupname");
		ctrl_shell_print_value(0, "%s\n", groupname->valuestring);
	}else if(!strcasecmp(command, "getDetails")){
		print_details(j_data);
	}else if(!strcasecmp(command, "getClient")){
		print_client(j_data);
	}else if(!strcasecmp(command, "getGroup")){
		print_group(j_data);
	}else if(!strcasecmp(command, "getRole")){
		print_role(j_data);
	}else if(!strcasecmp(command, "getDefaultACLAccess")){
		print_default_acls(j_data);
	}else{
		//ctrl_shell_printf("%s %s\n", command, payload);
	}
}


static void on_subscribe(void)
{
	int rc;

	rc = list_update("listClients");
	if(rc){
		ctrl_shell_printf("Check the dynsec module is configured on the broker.\n");
		return;
	}
	list_update("listGroups");
	list_update("listRoles");
}


static void ctrl_shell__dynsec_cleanup(void)
{
	completion_tree_free(commands_dynsec);
	commands_dynsec = NULL;

	completion_tree_arg_list_args_free(tree_clients);
	completion_tree_arg_list_args_free(tree_groups);
	completion_tree_arg_list_args_free(tree_roles);

	free(tree_clients);
	free(tree_groups);
	free(tree_roles);

	tree_clients = NULL;
	tree_groups = NULL;
	tree_roles = NULL;
}


void ctrl_shell__dynsec_init(struct ctrl_shell__module *mod)
{
	command_tree_create();

	mod->completion_commands = commands_dynsec;
	mod->request_topic = "$CONTROL/dynamic-security/v1";
	mod->response_topic = "$CONTROL/dynamic-security/v1/response";
	mod->line_callback = line_callback;
	mod->response_callback = response_callback;
	mod->on_subscribe = on_subscribe;
	mod->cleanup = ctrl_shell__dynsec_cleanup;
}
#endif
