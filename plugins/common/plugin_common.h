#ifndef PLUGIN_SHARED_H
#define PLUGIN_SHARED_H

#include <cjson/cJSON.h>
#include "mosquitto_broker.h"

struct plugin_cmd{
	cJSON *j_responses;
	cJSON *j_command;
	char *correlation_data;
	const char *command_name;
};

void plugin__command_reply(struct plugin_cmd *cmd, const char *error);
void plugin__send_response(cJSON *tree, const char* topic);
int plugin__generic_control_callback(struct mosquitto_evt_control *event_data, const char *response_topic, void *userdata,
		int (*cmd_cb)(struct plugin_cmd *cmd, struct mosquitto *context, const char *command, void *userdata));

#endif
