#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto/broker.h>
#include <mosquitto/broker_plugin.h>

int mosquitto_auth_acl_check_v5(int event, void *event_data, void *user_data);
int mosquitto_auth_unpwd_check_v5(int event, void *event_data, void *user_data);

static mosquitto_plugin_id_t *plg_id;

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);


int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	(void)user_data;
	(void)auth_opts;
	(void)auth_opt_count;

	plg_id = identifier;

	mosquitto_callback_register(plg_id, MOSQ_EVT_ACL_CHECK, mosquitto_auth_acl_check_v5, NULL, NULL);
	mosquitto_callback_register(plg_id, MOSQ_EVT_BASIC_AUTH, mosquitto_auth_unpwd_check_v5, NULL, NULL);

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	(void)user_data;
	(void)auth_opts;
	(void)auth_opt_count;

	mosquitto_callback_unregister(plg_id, MOSQ_EVT_ACL_CHECK, mosquitto_auth_acl_check_v5, NULL);
	mosquitto_callback_unregister(plg_id, MOSQ_EVT_BASIC_AUTH, mosquitto_auth_unpwd_check_v5, NULL);

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_auth_acl_check_v5(int event, void *event_data, void *user_data)
{
	struct mosquitto_evt_acl_check *ed = event_data;
	const char *username = mosquitto_client_username(ed->client);
	char *prop_name = NULL, *prop_value = NULL;

	(void)user_data;

	if(event != MOSQ_EVT_ACL_CHECK){
		abort();
	}

	if(username && !strcmp(username, "readonly") && ed->access == MOSQ_ACL_READ){
		return MOSQ_ERR_SUCCESS;
	}else if(username && !strcmp(username, "readonly") && ed->access == MOSQ_ACL_SUBSCRIBE &&!strchr(ed->topic, '#') && !strchr(ed->topic, '+')){
		return MOSQ_ERR_SUCCESS;
	}else if(username && !strcmp(username, "readwrite")){
		if((!strcmp(ed->topic, "readonly") && ed->access == MOSQ_ACL_READ)
				|| !strcmp(ed->topic, "writeable")){

			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_ACL_DENIED;
		}
	}else if(mosquitto_property_read_string_pair(ed->properties, MQTT_PROP_USER_PROPERTY, &prop_name, &prop_value, false)
			&& !strcmp(prop_name, "custom-name") && !strcmp(prop_value, "custom-value")){

		mosquitto_FREE(prop_name);
		mosquitto_FREE(prop_value);
		return MOSQ_ERR_SUCCESS;
	}else{
		mosquitto_FREE(prop_name);
		mosquitto_FREE(prop_value);
		return MOSQ_ERR_ACL_DENIED;
	}
}


int mosquitto_auth_unpwd_check_v5(int event, void *event_data, void *user_data)
{
	struct mosquitto_evt_basic_auth *ed = event_data;
	const char binary_pw[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

	(void)user_data;

	if(event != MOSQ_EVT_BASIC_AUTH){
		abort();
	}

	if(ed->username
			&& !strcmp(ed->username, "test-username")
			&& ed->password
			&& !strcmp(ed->password, "cnwTICONIURW")
			&& strlen("cnwTICONIURW") == ed->password_len
			){

		return MOSQ_ERR_SUCCESS;
	}else if(ed->username
			&& !strcmp(ed->username, "binary-password")
			&& ed->password
			&& ed->password_len == sizeof(binary_pw)
			&& !memcmp(ed->password, binary_pw, ed->password_len)
			){

		return MOSQ_ERR_SUCCESS;
	}else if(ed->username && (!strcmp(ed->username, "readonly") || !strcmp(ed->username, "readwrite"))){
		return MOSQ_ERR_SUCCESS;
	}else if(ed->username && !strcmp(ed->username, "test-username@v2")){
		return MOSQ_ERR_PLUGIN_DEFER;
	}else{
		return MOSQ_ERR_AUTH;
	}
}
