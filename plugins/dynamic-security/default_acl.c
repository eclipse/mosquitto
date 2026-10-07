/*
Copyright (c) 2020-2021 Roger Light <roger@atchoo.org>

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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "dynamic_security.h"
#include "json_help.h"


int dynsec__process_set_default_acl_access(struct dynsec__data *data, struct mosquitto_control_cmd *cmd)
{
	cJSON *j_actions, *j_action;
	bool allow;
	const char *admin_clientid, *admin_username;
	const char *acltype;

	j_actions = cJSON_GetObjectItem(cmd->j_command, "acls");
	if(j_actions == NULL || !cJSON_IsArray(j_actions)){
		mosquitto_control_command_reply(cmd, "Missing/invalid actions array");
		return MOSQ_ERR_INVAL;
	}

	admin_clientid = mosquitto_client_id(cmd->client);
	admin_username = mosquitto_client_username(cmd->client);

	cJSON_ArrayForEach(j_action, j_actions){
		if(json_get_string(j_action, "acltype", &acltype, false) == MOSQ_ERR_SUCCESS
				&& json_get_bool(j_action, "allow", &allow, false, false) == MOSQ_ERR_SUCCESS){

			if(!strcasecmp(acltype, ACL_TYPE_PUB_C_SEND)){
				data->default_access.publish_c_send = allow;
			}else if(!strcasecmp(acltype, ACL_TYPE_PUB_C_RECV)){
				data->default_access.publish_c_recv = allow;
			}else if(!strcasecmp(acltype, ACL_TYPE_SUB_GENERIC)){
				data->default_access.subscribe = allow;
			}else if(!strcasecmp(acltype, ACL_TYPE_UNSUB_GENERIC)){
				data->default_access.unsubscribe = allow;
			}
			mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | setDefaultACLAccess | acltype=%s | allow=%s",
					admin_clientid, admin_username, acltype, allow?"true":"false");
		}
	}

	dynsec__config_batch_save(data);
	mosquitto_control_command_reply(cmd, NULL);
	return MOSQ_ERR_SUCCESS;
}


int dynsec__process_get_default_acl_access(struct dynsec__data *data, struct mosquitto_control_cmd *cmd)
{
	cJSON *tree, *jtmp, *j_data, *j_acls, *j_acl;
	const char *admin_clientid, *admin_username;

	tree = cJSON_CreateObject();
	if(tree == NULL){
		mosquitto_control_command_reply(cmd, "Internal error");
		return MOSQ_ERR_NOMEM;
	}

	admin_clientid = mosquitto_client_id(cmd->client);
	admin_username = mosquitto_client_username(cmd->client);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | getDefaultACLAccess",
			admin_clientid, admin_username);

	if(cJSON_AddStringToObject(tree, "command", "getDefaultACLAccess") == NULL
			|| ((j_data = cJSON_AddObjectToObject(tree, "data")) == NULL)

			){
		goto internal_error;
	}

	j_acls = cJSON_AddArrayToObject(j_data, "acls");
	if(j_acls == NULL){
		goto internal_error;
	}

	/* publishClientSend */
	j_acl = cJSON_CreateObject();
	if(j_acl == NULL){
		goto internal_error;
	}
	cJSON_AddItemToArray(j_acls, j_acl);
	if(cJSON_AddStringToObject(j_acl, "acltype", ACL_TYPE_PUB_C_SEND) == NULL
			|| cJSON_AddBoolToObject(j_acl, "allow", data->default_access.publish_c_send) == NULL
			){

		goto internal_error;
	}

	/* publishClientReceive */
	j_acl = cJSON_CreateObject();
	if(j_acl == NULL){
		goto internal_error;
	}
	cJSON_AddItemToArray(j_acls, j_acl);
	if(cJSON_AddStringToObject(j_acl, "acltype", ACL_TYPE_PUB_C_RECV) == NULL
			|| cJSON_AddBoolToObject(j_acl, "allow", data->default_access.publish_c_recv) == NULL
			){

		goto internal_error;
	}

	/* subscribe */
	j_acl = cJSON_CreateObject();
	if(j_acl == NULL){
		goto internal_error;
	}
	cJSON_AddItemToArray(j_acls, j_acl);
	if(cJSON_AddStringToObject(j_acl, "acltype", ACL_TYPE_SUB_GENERIC) == NULL
			|| cJSON_AddBoolToObject(j_acl, "allow", data->default_access.subscribe) == NULL
			){

		goto internal_error;
	}

	/* unsubscribe */
	j_acl = cJSON_CreateObject();
	if(j_acl == NULL){
		goto internal_error;
	}
	cJSON_AddItemToArray(j_acls, j_acl);
	if(cJSON_AddStringToObject(j_acl, "acltype", ACL_TYPE_UNSUB_GENERIC) == NULL
			|| cJSON_AddBoolToObject(j_acl, "allow", data->default_access.unsubscribe) == NULL
			){

		goto internal_error;
	}

	if(cmd->correlation_data){
		jtmp = cJSON_AddStringToObject(tree, "correlationData", cmd->correlation_data);
		if(jtmp == NULL){
			goto internal_error;
		}
	}

	cJSON_AddItemToArray(cmd->j_responses, tree);

	return MOSQ_ERR_SUCCESS;

internal_error:
	cJSON_Delete(tree);
	mosquitto_control_command_reply(cmd, "Internal error");
	return MOSQ_ERR_NOMEM;
}
