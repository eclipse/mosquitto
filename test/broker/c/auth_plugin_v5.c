#include <stdio.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

int mosquitto_auth_acl_check_v5(int event, void *event_data, void *user_data);
int mosquitto_auth_unpwd_check_v5(int event, void *event_data, void *user_data);

static mosquitto_plugin_id_t *plg_id;


int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)
{
	return 5;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	plg_id = identifier;

	mosquitto_callback_register(plg_id, MOSQ_EVT_ACL_CHECK, mosquitto_auth_acl_check_v5, NULL, NULL);
	mosquitto_callback_register(plg_id, MOSQ_EVT_BASIC_AUTH, mosquitto_auth_unpwd_check_v5, NULL, NULL);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	mosquitto_callback_unregister(plg_id, MOSQ_EVT_ACL_CHECK, mosquitto_auth_acl_check_v5, NULL);
	mosquitto_callback_unregister(plg_id, MOSQ_EVT_BASIC_AUTH, mosquitto_auth_unpwd_check_v5, NULL);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check_v5(int event, void *event_data, void *user_data)
{
	struct mosquitto_evt_acl_check *ed = event_data;
	const char *username = mosquitto_client_username(ed->client);

	if(username && !strcmp(username, "readonly") && ed->access == MOSQ_ACL_READ){
		return MOSQ_ERR_SUCCESS;
	}else if(username && !strcmp(username, "readonly") && ed->access == MOSQ_ACL_SUBSCRIBE &&!strchr(ed->topic, '#') && !strchr(ed->topic, '+')) {
		return MOSQ_ERR_SUCCESS;
	}else if(username && !strcmp(username, "readwrite")){
		if((!strcmp(ed->topic, "readonly") && ed->access == MOSQ_ACL_READ)
				|| !strcmp(ed->topic, "writeable")){

			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_ACL_DENIED;
		}

	}else{
		return MOSQ_ERR_ACL_DENIED;
	}
}

int mosquitto_auth_unpwd_check_v5(int event, void *event_data, void *user_data)
{
	struct mosquitto_evt_basic_auth *ed = event_data;

	if(!strcmp(ed->username, "test-username") && ed->password && !strcmp(ed->password, "cnwTICONIURW")){
		return MOSQ_ERR_SUCCESS;
	}else if(!strcmp(ed->username, "readonly") || !strcmp(ed->username, "readwrite")){
		return MOSQ_ERR_SUCCESS;
	}else if(!strcmp(ed->username, "test-username@v2")){
		return MOSQ_ERR_PLUGIN_DEFER;
	}else{
		return MOSQ_ERR_AUTH;
	}
}
