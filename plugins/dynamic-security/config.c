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

    int (*load_config)(struct dynsec__data*, FILE*) = dynsec__config_load_json;

#ifdef WITH_YAML
    if (data->config_format == CONFIG_FORMAT_YAML) load_config = &dynsec__config_load_yaml;
#endif

    rc = load_config(data, fptr);

    fclose(fptr);

    return rc;
}

void dynsec__config_save(struct dynsec__data *data)
{
	data->need_save = false;

    int (*write_config)(FILE*, void*) = &dynsec__write_json_config;

#ifdef WITH_YAML
    if (data->config_format == CONFIG_FORMAT_YAML) write_config = &dynsec__write_yaml_config;
#endif

    mosquitto_write_file(data->config_file, true, write_config, data, &dynsec__log_write_error);
}
