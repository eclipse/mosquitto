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
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mosquitto.h"
#include "mosquitto_ctrl.h"
#include "get_password.h"
#include "json_help.h"
#include "password_mosq.h"
#include "dynamic_security.h"

int dynsec_client__create(int argc, char *argv[], cJSON *j_command)
{
	char *username = NULL, *password = NULL, *clientid = NULL;
	char prompt[200], verify_prompt[200];
	char password_buf[200];
	int rc;
	int i;
	bool request_password = true;

	if(argc == 0){
		return MOSQ_ERR_INVAL;
	}
	username = argv[0];

	for(i=1; i<argc; i++){
		if(!strcmp(argv[i], "-c")){
			if(i+1 == argc){
				fprintf(stderr, "Error: -c argument given, but no clientid provided.\n");
				return MOSQ_ERR_INVAL;
			}
			clientid = argv[i+1];
			i++;
		}else if(!strcmp(argv[i], "-p")){
			if(i+1 == argc){
				fprintf(stderr, "Error: -p argument given, but no password provided.\n");
				return MOSQ_ERR_INVAL;
			}
			password = argv[i+1];
			i++;
			request_password = false;
		} else if (!strcmp(argv[i], "--no-password")) {
			if (password != NULL) {
				fprintf(stderr, "Error: -p and --no-password are mutually exclusive.\n");
				return MOSQ_ERR_INVAL;
			}

			request_password = false;
		}
	}

	if(request_password){
		printf("Enter new password for %s. Press return for no password (user will be unable to login).\n", username);
		snprintf(prompt, sizeof(prompt), "New password for %s: ", username);
		snprintf(verify_prompt, sizeof(verify_prompt), "Reenter password for %s: ", username);
		rc = get_password(prompt, verify_prompt, true, password_buf, sizeof(password_buf));
		if(rc == 0){
			password = password_buf;
		}else if(rc == 2){
			fprintf(stderr, "Error: Passwords do not match.\n");
			return -1;
		}else{
			password = NULL;
			printf("\n");
		}
	}
	if(cJSON_AddStringToObject(j_command, "command", "createClient") == NULL
			|| cJSON_AddStringToObject(j_command, "username", username) == NULL
			|| (clientid && cJSON_AddStringToObject(j_command, "clientid", clientid) == NULL)
			|| (password && cJSON_AddStringToObject(j_command, "password", password) == NULL)
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_client__delete(int argc, char *argv[], cJSON *j_command)
{
	char *username = NULL;

	if(argc == 1){
		username = argv[0];
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "deleteClient") == NULL
			|| cJSON_AddStringToObject(j_command, "username", username) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_client__enable_disable(int argc, char *argv[], cJSON *j_command, const char *command)
{
	char *username = NULL;

	if(argc == 1){
		username = argv[0];
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", command) == NULL
			|| cJSON_AddStringToObject(j_command, "username", username) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_client__set_id(int argc, char *argv[], cJSON *j_command)
{
	char *username = NULL, *clientid = NULL;

	if(argc == 2){
		username = argv[0];
		clientid = argv[1];
	}else if(argc == 1){
		username = argv[0];
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "setClientId") == NULL
			|| cJSON_AddStringToObject(j_command, "username", username) == NULL
			|| (clientid && cJSON_AddStringToObject(j_command, "clientid", clientid) == NULL)
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_client__file_set_password(int argc, char *argv[], const char *file)
{
	char *username = NULL, *password = NULL;
	long len;
	FILE *fptr;
	char *fstr;
	cJSON *j_tree, *j_clients, *j_client;
	cJSON *j_username, *j_password = NULL, *j_salt = NULL, *j_iterations = NULL;
	struct dynsec__client client;
	char *pw_buf = NULL, *salt_buf = NULL;
	char *json_str;
	int i;
	int rc = MOSQ_ERR_UNKNOWN;

	memset(&client, 0, sizeof(client));

	if(argc >= 2){
		username = argv[0];
		password = argv[1];
	}else{
		return MOSQ_ERR_INVAL;
	}
	for(i=2; i<argc; i++){
		if(!strcmp(argv[i], "-i")){
			if(i+1 == argc){
				fprintf(stderr, "Error: -i argument given, but no iterations provided.\n");
				return MOSQ_ERR_INVAL;
			}
			client.pw.iterations = atoi(argv[i+1]);
			i++;
		}else{
			fprintf(stderr, "Error: Unknown argument: %s\n", argv[i]);
			return MOSQ_ERR_INVAL;
		}
	}

	fptr = fopen(file, "rb");
	if(fptr == NULL){
		fprintf(stderr, "Error: Unable to open %s.\n", file);
		return MOSQ_ERR_INVAL;
	}
	fseek(fptr, 0, SEEK_END);
	len = ftell(fptr);
	fseek(fptr, 0, SEEK_SET);
	if(len <= 0){
		fprintf(stderr, "Error: %s is empty.\n", file);
		fclose(fptr);
		return MOSQ_ERR_INVAL;
	}

	fstr = calloc(1, (size_t)len+1);
	if(fstr == NULL){
		fclose(fptr);
		return MOSQ_ERR_NOMEM;
	}
	if(fread(fstr, 1, (size_t)len, fptr) != (size_t)len){
		fprintf(stderr, "Error: Incomplete read of %s.\n", file);
		fclose(fptr);
		free(fstr);
		return MOSQ_ERR_NOMEM;
	}
	fclose(fptr);

	j_tree = cJSON_Parse(fstr);
	free(fstr);

	if(j_tree == NULL){
		fprintf(stderr, "Error: %s is not valid JSON.\n", file);
		return MOSQ_ERR_INVAL;
	}

	j_clients = cJSON_GetObjectItem(j_tree, "clients");
	if(j_clients == NULL || !cJSON_IsArray(j_clients)){
		fprintf(stderr, "Error: %s is not a valid dynamic-security config file.\n", file);
		cJSON_Delete(j_tree);
		return MOSQ_ERR_INVAL;
	}

	cJSON_ArrayForEach(j_client, j_clients){
		if(cJSON_IsObject(j_client) == true){
			j_username = cJSON_GetObjectItem(j_client, "username");
			if(j_username && cJSON_IsString(j_username)){
				if(!strcmp(j_username->valuestring, username)){
					if(dynsec_auth__pw_hash(&client, password, client.pw.password_hash, sizeof(client.pw.password_hash), true) != MOSQ_ERR_SUCCESS){
						fprintf(stderr, "Error: Problem generating password hash.\n");
						goto error;
					}

					if(base64__encode(client.pw.password_hash, sizeof(client.pw.password_hash), &pw_buf) != MOSQ_ERR_SUCCESS){
						fprintf(stderr, "Error: Problem generating password hash.\n");
						rc = MOSQ_ERR_NOMEM;
						goto error;
					}
					if(base64__encode(client.pw.salt, client.pw.salt_len, &salt_buf) != MOSQ_ERR_SUCCESS){
						fprintf(stderr, "Error: Problem generating password hash.\n");
						goto error;
					}
					if((j_password = cJSON_CreateString(pw_buf)) == NULL
							|| (j_salt = cJSON_CreateString(salt_buf)) == NULL
							|| (j_iterations = cJSON_CreateNumber(client.pw.iterations)) == NULL
							){

						fprintf(stderr, "Error: Out of memory.\n");
						rc = MOSQ_ERR_NOMEM;
						goto error;
					}
					cJSON_ReplaceItemInObject(j_client, "password", j_password);
					cJSON_ReplaceItemInObject(j_client, "salt", j_salt);
					cJSON_ReplaceItemInObject(j_client, "iterations", j_iterations);
					j_password = NULL;
					j_salt = NULL;
					j_iterations = NULL;
					free(pw_buf);
					pw_buf = NULL;
					free(salt_buf);
					salt_buf = NULL;

					json_str = cJSON_Print(j_tree);
					cJSON_Delete(j_tree);
					if(json_str == NULL){
						fprintf(stderr, "Error: Out of memory.\n");
						return MOSQ_ERR_NOMEM;
					}
					fptr = fopen(file, "wb");
					if(fptr == NULL){
						fprintf(stderr, "Error: Unable to write to %s.\n", file);
						free(json_str);
						return MOSQ_ERR_UNKNOWN;
					}
					fprintf(fptr, "%s", json_str);
					free(json_str);
					fclose(fptr);
					return MOSQ_ERR_SUCCESS;
				}
			}
		}
	}

	fprintf(stderr, "Error: Client %s not found.\n", username);
	return MOSQ_ERR_SUCCESS;
error:
	cJSON_Delete(j_password);
	cJSON_Delete(j_salt);
	cJSON_Delete(j_tree);
	free(pw_buf);
	free(salt_buf);
	return rc;
}

int dynsec_client__set_password(int argc, char *argv[], cJSON *j_command)
{
	char *username = NULL, *password = NULL;
	char prompt[200], verify_prompt[200];
	char password_buf[200];
	int rc;

	if(argc == 2){
		username = argv[0];
		password = argv[1];
	}else if(argc == 1){
		username = argv[0];

		snprintf(prompt, sizeof(prompt), "New password for %s: ", username);
		snprintf(verify_prompt, sizeof(verify_prompt), "Reenter password for %s: ", username);
		rc = get_password(prompt, verify_prompt, false, password_buf, sizeof(password_buf));
		if(rc){
			return -1;
		}
		password = password_buf;
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "setClientPassword") == NULL
			|| cJSON_AddStringToObject(j_command, "username", username) == NULL
			|| cJSON_AddStringToObject(j_command, "password", password) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_client__get(int argc, char *argv[], cJSON *j_command)
{
	char *username = NULL;

	if(argc == 1){
		username = argv[0];
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "getClient") == NULL
			|| cJSON_AddStringToObject(j_command, "username", username) == NULL
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_client__add_remove_role(int argc, char *argv[], cJSON *j_command, const char *command)
{
	char *username = NULL, *rolename = NULL;
	int priority = -1;

	if(argc == 2){
		username = argv[0];
		rolename = argv[1];
	}else if(argc == 3){
		username = argv[0];
		rolename = argv[1];
		priority = atoi(argv[2]);
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", command) == NULL
			|| cJSON_AddStringToObject(j_command, "username", username) == NULL
			|| cJSON_AddStringToObject(j_command, "rolename", rolename) == NULL
			|| (priority != -1 && cJSON_AddIntToObject(j_command, "priority", priority) == NULL)
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}

int dynsec_client__list_all(int argc, char *argv[], cJSON *j_command)
{
	int count = -1, offset = -1;

	if(argc == 0){
		/* All clients */
	}else if(argc == 1){
		count = atoi(argv[0]);
	}else if(argc == 2){
		count = atoi(argv[0]);
		offset = atoi(argv[1]);
	}else{
		return MOSQ_ERR_INVAL;
	}

	if(cJSON_AddStringToObject(j_command, "command", "listClients") == NULL
			|| (count > 0 && cJSON_AddIntToObject(j_command, "count", count) == NULL)
			|| (offset > 0 && cJSON_AddIntToObject(j_command, "offset", offset) == NULL)
			){

		return MOSQ_ERR_NOMEM;
	}else{
		return MOSQ_ERR_SUCCESS;
	}
}
