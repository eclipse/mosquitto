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

#include "json_help.h"
#include "misc_mosq.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mqtt_protocol.h"

#include "dynamic_security.h"
#include <yaml.h>
#include "config/yaml_help.h"

void dynsec__log_write_error(const char* msg)
{
	mosquitto_log_printf(MOSQ_LOG_ERR, "Error saving Dynamic security plugin config: %s", msg);
}

void dynsec__config_batch_save(struct dynsec__data *data)
{
	data->need_save = true;
}

static int str_ends_with(const char *str, const char *suffix) {
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);

    return (str_len >= suffix_len) &&
           (!memcmp(str + str_len - suffix_len, suffix, suffix_len));
}

//TODO Conditional compilation of yaml format.
int dynsec__config_load(struct dynsec__data *data)
{
    FILE *fptr;
    int rc;

    /* Load from file */
    fptr = fopen(data->config_file, "rb");
    if(fptr == NULL){
        /* Attempt to initialise a new config file */
        if(dynsec__config_init(data) == MOSQ_ERR_SUCCESS){
            /* If it works, try to open the file again */
            fptr = fopen(data->config_file, "rb");
        }

        if(fptr == NULL){
            mosquitto_log_printf(MOSQ_LOG_ERR,
                                 "Error loading Dynamic security plugin config: File is not readable - check permissions.");
            return MOSQ_ERR_UNKNOWN;
        }
    }

    if (str_ends_with(data->config_file, ".yaml") || str_ends_with(data->config_file, ".yml")) {
        rc = dynsec__config_load_yaml(data, fptr);
    } else {
        rc = dynsec__config_load_json(data, fptr);
    }

    fclose(fptr);

    return rc;
}

//TODO Conditional compilation of yaml format.
void dynsec__config_save(struct dynsec__data *data)
{
	data->need_save = false;

    if (str_ends_with(data->config_file, ".yaml") || str_ends_with(data->config_file, ".yml")) {
        mosquitto_write_file(data->config_file, true, &dynsec__write_yaml_config, data, &dynsec__log_write_error);
    } else {
        mosquitto_write_file(data->config_file, true, &dynsec__write_json_config, data, &dynsec__log_write_error);
    }
}
