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

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mosquitto.h>
#include <mqtt_protocol.h>
#include "mosquitto_ctrl.h"

static int run = 1;

static void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg, const mosquitto_property *properties)
{
	struct mosq_ctrl *ctrl = obj;

	if(ctrl->payload_callback){
		ctrl->payload_callback(ctrl, msg->payloadlen, msg->payload);
	}

	mosquitto_disconnect_v5(mosq, 0, NULL);
	run = 0;
}


static void on_publish(struct mosquitto *mosq, void *obj, int mid, int reason_code, const mosquitto_property *properties)
{
	if(reason_code > 127){
		fprintf(stderr, "Publish error: %s\n", mosquitto_reason_string(reason_code));
		run = 0;
		mosquitto_disconnect_v5(mosq, 0, NULL);
	}
}


static void on_subscribe(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos, const mosquitto_property *properties)
{
	struct mosq_ctrl *ctrl = obj;

	if(qos_count == 1){
		if(granted_qos[0] < 128){
			/* Success */
			mosquitto_publish(mosq, NULL, ctrl->request_topic, (int)strlen(ctrl->payload), ctrl->payload, ctrl->cfg.qos, 0);
			free(ctrl->request_topic);
			ctrl->request_topic = NULL;
			free(ctrl->payload);
			ctrl->payload = NULL;
		}else{
			if(ctrl->cfg.protocol_version == MQTT_PROTOCOL_V5){
				fprintf(stderr, "Subscribe error: %s\n", mosquitto_reason_string(granted_qos[0]));
			}else{
				fprintf(stderr, "Subscribe error: Subscription refused.\n");
			}
			run = 0;
			mosquitto_disconnect_v5(mosq, 0, NULL);
		}
	}else{
		run = 0;
		mosquitto_disconnect_v5(mosq, 0, NULL);
	}
}


static void on_connect(struct mosquitto *mosq, void *obj, int reason_code, int flags, const mosquitto_property *properties)
{
	struct mosq_ctrl *ctrl = obj;

	if(reason_code == 0){
		if(ctrl->response_topic){
			mosquitto_subscribe(mosq, NULL, ctrl->response_topic, ctrl->cfg.qos);
			free(ctrl->response_topic);
			ctrl->response_topic = NULL;
		}
	}else{
		if(ctrl->cfg.protocol_version == MQTT_PROTOCOL_V5){
			if(reason_code == MQTT_RC_UNSUPPORTED_PROTOCOL_VERSION){
				fprintf(stderr, "Connection error: %s. Try connecting to an MQTT v5 broker, or use MQTT v3.x mode.\n", mosquitto_reason_string(reason_code));
			}else{
				fprintf(stderr, "Connection error: %s\n", mosquitto_reason_string(reason_code));
			}
		}else{
			fprintf(stderr, "Connection error: %s\n", mosquitto_connack_string(reason_code));
		}
		run = 0;
		mosquitto_disconnect_v5(mosq, 0, NULL);
	}
}


int client_request_response(struct mosq_ctrl *ctrl)
{
	struct mosquitto *mosq;
	int rc;
	time_t start;

	if(ctrl->cfg.cafile == NULL && ctrl->cfg.capath == NULL){
		fprintf(stderr, "Warning: You are running mosquitto_ctrl without encryption.\nThis means all of the configuration changes you are making are visible on the network, including passwords.\n\n");
	}

	mosquitto_lib_init();

	mosq = mosquitto_new(ctrl->cfg.id, true, ctrl);
	rc = client_opts_set(mosq, &ctrl->cfg);
	if(rc) goto cleanup;

	mosquitto_connect_v5_callback_set(mosq, on_connect);
	mosquitto_subscribe_v5_callback_set(mosq, on_subscribe);
	mosquitto_publish_v5_callback_set(mosq, on_publish);
	mosquitto_message_v5_callback_set(mosq, on_message);

	rc = client_connect(mosq, &ctrl->cfg);
	if(rc) goto cleanup;

	start = time(NULL);
	while(run && start+10 > time(NULL)){
		mosquitto_loop(mosq, -1, 1);
	}

cleanup:
	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	return rc;
}
