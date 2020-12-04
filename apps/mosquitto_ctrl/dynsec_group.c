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
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mosquitto.h"
#include "mosquitto_ctrl.h"
#include "password_mosq.h"

int dynsec_group__create(int argc, char *argv[], cJSON *j_command)
{
	char *groupname = NULL;

	if(argc == 1){
		groupname = argv[0];
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "createGroup") == NULL
			|| cJSON_AddStringToObject(j_command, "groupname", groupname) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_group__delete(int argc, char *argv[], cJSON *j_command)
{
	char *groupname = NULL;

	if(argc == 1){
		groupname = argv[0];
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "deleteGroup") == NULL
			|| cJSON_AddStringToObject(j_command, "groupname", groupname) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_group__get_anonymous(int argc, char *argv[], cJSON *j_command)
{
	if(cJSON_AddStringToObject(j_command, "command", "getAnonymousGroup") == NULL
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_group__set_anonymous(int argc, char *argv[], cJSON *j_command)
{
	char *groupname = NULL;

	if(argc == 1){
		groupname = argv[0];
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "setAnonymousGroup") == NULL
			|| cJSON_AddStringToObject(j_command, "groupname", groupname) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_group__get(int argc, char *argv[], cJSON *j_command)
{
	char *groupname = NULL;

	if(argc == 1){
		groupname = argv[0];
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "getGroup") == NULL
			|| cJSON_AddStringToObject(j_command, "groupname", groupname) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_group__add_remove_role(int argc, char *argv[], cJSON *j_command, const char *command)
{
	char *groupname = NULL, *rolename = NULL;
	int priority = -1;

	if(argc == 2){
		groupname = argv[0];
		rolename = argv[1];
	}else if(argc == 3){
		groupname = argv[0];
		rolename = argv[1];
		priority = atoi(argv[2]);
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", command) == NULL
			|| cJSON_AddStringToObject(j_command, "groupname", groupname) == NULL
			|| cJSON_AddStringToObject(j_command, "rolename", rolename) == NULL
			|| (priority != -1 && cJSON_AddIntToObject(j_command, "priority", priority) == NULL)
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_group__list_all(int argc, char *argv[], cJSON *j_command)
{
	int count = -1, offset = -1;

	if(argc == 0){
		/* All groups */
	}else if(argc == 1){
		count = atoi(argv[0]);
	}else if(argc == 2){
		count = atoi(argv[0]);
		offset = atoi(argv[1]);
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "listGroups") == NULL
			|| (count > 0 && cJSON_AddIntToObject(j_command, "count", count) == NULL)
			|| (offset > 0 && cJSON_AddIntToObject(j_command, "offset", offset) == NULL)
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_group__add_remove_client(int argc, char *argv[], cJSON *j_command, const char *command)
{
	char *username, *groupname;
	int priority = -1;

	if(argc == 2){
		groupname = argv[0];
		username = argv[1];
	}else if(argc == 3){
		groupname = argv[0];
		username = argv[1];
		priority = atoi(argv[2]);
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", command) == NULL
			|| cJSON_AddStringToObject(j_command, "username", username) == NULL
			|| cJSON_AddStringToObject(j_command, "groupname", groupname) == NULL
			|| (priority != -1 && cJSON_AddIntToObject(j_command, "priority", priority) == NULL)
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}
