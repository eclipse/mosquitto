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
   Akos Vandra-Meyer - addition of YAML file format
*/

#include "config.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <uthash.h>
#include <errno.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "json_help.h"

#include "dynamic_security.h"


static int dynsec__general_config_load_json(struct dynsec__data *data, cJSON *tree)
{
    cJSON *j_default_access;

    j_default_access = cJSON_GetObjectItem(tree, "defaultACLAccess");
    if(j_default_access && cJSON_IsObject(j_default_access)){
        json_get_bool(j_default_access, ACL_TYPE_PUB_C_SEND, &data->default_access.publish_c_send, true, false);
        json_get_bool(j_default_access, ACL_TYPE_PUB_C_RECV, &data->default_access.publish_c_recv, true, false);
        json_get_bool(j_default_access, ACL_TYPE_SUB_GENERIC, &data->default_access.subscribe, true, false);
        json_get_bool(j_default_access, ACL_TYPE_UNSUB_GENERIC, &data->default_access.unsubscribe, true, false);
    }
    return MOSQ_ERR_SUCCESS;
}

static int dynsec__general_config_save_json(struct dynsec__data *data, cJSON *tree)
{
    cJSON *j_default_access;

    j_default_access = cJSON_CreateObject();
    if(j_default_access == NULL){
        return 1;
    }
    cJSON_AddItemToObject(tree, "defaultACLAccess", j_default_access);

    if(cJSON_AddBoolToObject(j_default_access, ACL_TYPE_PUB_C_SEND, data->default_access.publish_c_send) == NULL
       || cJSON_AddBoolToObject(j_default_access, ACL_TYPE_PUB_C_RECV, data->default_access.publish_c_recv) == NULL
       || cJSON_AddBoolToObject(j_default_access, ACL_TYPE_SUB_GENERIC, data->default_access.subscribe) == NULL
       || cJSON_AddBoolToObject(j_default_access, ACL_TYPE_UNSUB_GENERIC, data->default_access.unsubscribe) == NULL
            ){

        return 1;
    }

    return MOSQ_ERR_SUCCESS;
}


int dynsec__config_load_json(struct dynsec__data *data, FILE* fptr)
{
    size_t flen;
    long flen_l;
    char *json_str;
    cJSON *tree;

    fseek(fptr, 0, SEEK_END);
    flen_l = ftell(fptr);
    if (flen_l < 0) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error loading Dynamic security plugin config: %s", strerror(errno));
        return 1;
    } else if (flen_l == 0){
        return 0;
    }
    flen = (size_t)flen_l;
    fseek(fptr, 0, SEEK_SET);
    json_str = mosquitto_calloc(flen+1, sizeof(char));
    if (json_str == NULL) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Out of memory.");
        return 1;
    }
    if (fread(json_str, 1, flen, fptr) != flen) {
        mosquitto_log_printf(MOSQ_LOG_WARNING, "Error loading Dynamic security plugin config: Unable to read file contents.\n");
        mosquitto_free(json_str);
        return 1;
    }

    tree = cJSON_Parse(json_str);
    if(tree == NULL){
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error loading Dynamic security plugin config: File is not valid JSON.");
        return 1;
    }

    if(dynsec__general_config_load_json(data, tree)
       || dynsec_roles__config_load_json(data, tree)
       || dynsec_clients__config_load_json(data, tree)
       || dynsec_groups__config_load_json(data, tree)
            ){

        cJSON_Delete(tree);
        return 1;
    }

    cJSON_Delete(tree);
    return 0;
}

char *dynsec__config_to_json(struct dynsec__data *data)
{
    cJSON *tree;
    char *json_str;

    tree = cJSON_CreateObject();
    if(tree == NULL) return NULL;

    if(dynsec__general_config_save_json(data, tree)
       || dynsec_clients__config_save_json(data, tree)
       || dynsec_groups__config_save_json(data, tree)
       || dynsec_roles__config_save_json(data, tree)){

        cJSON_Delete(tree);
        return NULL;
    }

    /* Print json to string */
    json_str = cJSON_Print(tree);
    cJSON_Delete(tree);
    return json_str;
}

int dynsec__write_json_config(FILE* fptr, void* user_data)
{
    struct dynsec__data *data = (struct dynsec__data *)user_data;
    char *json_str;
    size_t json_str_len;
    int rc = MOSQ_ERR_SUCCESS;

    json_str = dynsec__config_to_json(data);
    if(json_str == NULL){
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error saving Dynamic security plugin config: Out of memory.\n");
        return MOSQ_ERR_NOMEM;
    }
    json_str_len = strlen(json_str);

    if (fwrite(json_str, 1, json_str_len, fptr) != json_str_len){
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error saving Dynamic security plugin config: Cannot write whole config (%ld) bytes to file %s", json_str_len, data->config_file);
        rc = MOSQ_ERR_UNKNOWN;
    }

    mosquitto_free(json_str);
    return rc;
}
