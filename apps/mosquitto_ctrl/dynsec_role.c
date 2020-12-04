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

#include "mosquitto.h"
#include "mosquitto_ctrl.h"
#include "password_mosq.h"

int dynsec_role__create(int argc, char *argv[], cJSON *j_command)
{
	char *rolename = NULL;

	if(argc == 1){
		rolename = argv[0];
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "createRole") == NULL
			|| cJSON_AddStringToObject(j_command, "rolename", rolename) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_role__delete(int argc, char *argv[], cJSON *j_command)
{
	char *rolename = NULL;

	if(argc == 1){
		rolename = argv[0];
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "deleteRole") == NULL
			|| cJSON_AddStringToObject(j_command, "rolename", rolename) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_role__get(int argc, char *argv[], cJSON *j_command)
{
	char *rolename = NULL;

	if(argc == 1){
		rolename = argv[0];
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "getRole") == NULL
			|| cJSON_AddStringToObject(j_command, "rolename", rolename) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_role__list_all(int argc, char *argv[], cJSON *j_command)
{
	int count = -1, offset = -1;

	if(argc == 0){
		/* All roles */
	}else if(argc == 1){
		count = atoi(argv[0]);
	}else if(argc == 2){
		count = atoi(argv[0]);
		offset = atoi(argv[1]);
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "listRoles") == NULL
			|| (count > 0 && cJSON_AddIntToObject(j_command, "count", count) == NULL)
			|| (offset > 0 && cJSON_AddIntToObject(j_command, "offset", offset) == NULL)
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_role__add_acl(int argc, char *argv[], cJSON *j_command)
{
	char *rolename, *acltype, *topic, *action;
	bool allow;
	int priority = -1;

	if(argc == 5){
		rolename = argv[0];
		acltype = argv[1];
		topic = argv[2];
		action = argv[3];
		priority = atoi(argv[4]);
	}else if(argc == 4){
		rolename = argv[0];
		acltype = argv[1];
		topic = argv[2];
		action = argv[3];
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(strcasecmp(acltype, "publishClientSend")
			&& strcasecmp(acltype, "publishClientReceive")
			&& strcasecmp(acltype, "subscribeLiteral")
			&& strcasecmp(acltype, "subscribePattern")
			&& strcasecmp(acltype, "unsubscribeLiteral")
			&& strcasecmp(acltype, "unsubscribePattern")){

		return MOSQ_ERR_INVAL;
	}
	if(!strcasecmp(action, "allow")){
		allow = true;
	}else if(!strcasecmp(action, "deny")){
		allow = false;
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "addRoleACL") == NULL
			|| cJSON_AddStringToObject(j_command, "rolename", rolename) == NULL
			|| cJSON_AddStringToObject(j_command, "acltype", acltype) == NULL
			|| cJSON_AddStringToObject(j_command, "topic", topic) == NULL
			|| cJSON_AddBoolToObject(j_command, "allow", allow) == NULL
			|| (priority != -1 && cJSON_AddIntToObject(j_command, "priority", priority) == NULL)
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_role__remove_acl(int argc, char *argv[], cJSON *j_command)
{
	char *rolename, *acltype, *topic;

	if(argc == 3){
		rolename = argv[0];
		acltype = argv[1];
		topic = argv[2];
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(strcasecmp(acltype, "publishClientSend")
			&& strcasecmp(acltype, "publishClientReceive")
			&& strcasecmp(acltype, "subscribeLiteral")
			&& strcasecmp(acltype, "subscribePattern")
			&& strcasecmp(acltype, "unsubscribeLiteral")
			&& strcasecmp(acltype, "unsubscribePattern")){

		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "removeRoleACL") == NULL
			|| cJSON_AddStringToObject(j_command, "rolename", rolename) == NULL
			|| cJSON_AddStringToObject(j_command, "acltype", acltype) == NULL
			|| cJSON_AddStringToObject(j_command, "topic", topic) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}
