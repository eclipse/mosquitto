#include "config.h"

#ifdef WITH_CJSON

#include "control_common.h"
#include "json_help.h"
#include <mqtt_protocol.h>
#include <mosquitto_broker.h>

#include <stdlib.h>
#include <string.h>

void control__command_reply(struct control_cmd *cmd, const char *error)
{
	cJSON *j_response;

	j_response = cJSON_CreateObject();
	if(j_response == NULL) return;

	if(cJSON_AddStringToObject(j_response, "command", cmd->command_name) == NULL
			|| (error && cJSON_AddStringToObject(j_response, "error", error) == NULL)
			|| (cmd->correlation_data && cJSON_AddStringToObject(j_response, "correlationData", cmd->correlation_data) == NULL)
			){

		cJSON_Delete(j_response);
		return;
	}

	cJSON_AddItemToArray(cmd->j_responses, j_response);
}

void control__send_response(cJSON *tree, const char *topic)
{
	char *payload;
	size_t payload_len;

	payload = cJSON_PrintUnformatted(tree);
	cJSON_Delete(tree);
	if(payload == NULL) return;

	payload_len = strlen(payload);
	if(payload_len > MQTT_MAX_PAYLOAD){
		free(payload);
		return;
	}
	mosquitto_broker_publish(NULL, topic, (int)payload_len, payload, 0, 0, NULL);
}


static int control__generic_handle_commands(struct control_cmd *cmd, struct mosquitto *context, cJSON *commands, void *userdata, int (*cmd_cb)(struct control_cmd *cmd, struct mosquitto *context, const char *command, void *userdata))
{
	cJSON *aiter;
	char *command;

	cJSON_ArrayForEach(aiter, commands){
		cmd->command_name = "Unknown command";
		if(cJSON_IsObject(aiter)){
			if(json_get_string(aiter, "command", &command, false) == MOSQ_ERR_SUCCESS){
				cmd->j_command = aiter;
				cmd->correlation_data = NULL;
				cmd->command_name = command;

				if(json_get_string(aiter, "correlationData", &cmd->correlation_data, true) != MOSQ_ERR_SUCCESS){
					control__command_reply(cmd, "Invalid correlationData data type.");
					return MOSQ_ERR_INVAL;
				}

				cmd_cb(cmd, context, command, userdata);
			}else{
				control__command_reply(cmd, "Missing command");
				return MOSQ_ERR_INVAL;
			}
		}else{
			control__command_reply(cmd, "Command not an object");
			return MOSQ_ERR_INVAL;
		}
	}
	return MOSQ_ERR_SUCCESS;
}

int control__generic_control_callback(struct mosquitto_evt_control *event_data, const char *response_topic, void *userdata,
		int (*cmd_cb)(struct control_cmd *cmd, struct mosquitto *context, const char *command, void *userdata))

{
	struct mosquitto_evt_control *ed = event_data;
	struct control_cmd cmd;
	cJSON *tree, *commands;
	cJSON *j_response_tree;

	if(!event_data || !cmd_cb){
		return MOSQ_ERR_INVAL;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.command_name = "Unknown command";

	/* Create object for responses */
	j_response_tree = cJSON_CreateObject();
	if(j_response_tree == NULL){
		return MOSQ_ERR_NOMEM;
	}
	cmd.j_responses = cJSON_AddArrayToObject(j_response_tree, "responses");
	if(cmd.j_responses == NULL){
		cJSON_Delete(j_response_tree);
		return MOSQ_ERR_NOMEM;
	}

	/* Parse cJSON tree.
	 * Using cJSON_ParseWithLength() is the best choice here, but Mosquitto
	 * always adds an extra 0 to the end of the payload memory, so using
	 * cJSON_Parse() on its own will still not overrun. */
#if CJSON_VERSION_FULL < 1007013
	tree = cJSON_Parse(ed->payload);
#else
	tree = cJSON_ParseWithLength(ed->payload, ed->payloadlen);
#endif
	if(tree == NULL){
		control__command_reply(&cmd, "Payload not valid JSON");
		control__send_response(j_response_tree, response_topic);
		return MOSQ_ERR_SUCCESS;
	}
	commands = cJSON_GetObjectItem(tree, "commands");
	if(commands == NULL || !cJSON_IsArray(commands)){
		cJSON_Delete(tree);
		control__command_reply(&cmd, "Invalid/missing commands");
		control__send_response(j_response_tree, response_topic);
		return MOSQ_ERR_SUCCESS;
	}

	/* Handle commands */
	control__generic_handle_commands(&cmd, ed->client, commands, userdata, cmd_cb);
	cJSON_Delete(tree);

	control__send_response(j_response_tree, response_topic);

	return MOSQ_ERR_SUCCESS;
}
#endif
