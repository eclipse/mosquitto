#ifndef CONTROLLUGIN_COMMON_H
#define CONTROLLUGIN_COMMON_H

#include <cjson/cJSON.h>
#include "mosquitto_broker.h"

struct control_cmd{
	cJSON *j_responses;
	cJSON *j_command;
	char *correlation_data;
	const char *command_name;
};

void control__command_reply(struct control_cmd *cmd, const char *error);
void control__send_response(cJSON *tree, const char* topic);
int control__generic_control_callback(struct mosquitto_evt_control *event_data, const char *response_topic, void *userdata,
		int (*cmd_cb)(struct control_cmd *cmd, struct mosquitto *context, const char *command, void *userdata));

#endif
