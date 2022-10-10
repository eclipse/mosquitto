#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

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
	int rc;

	(void)user_data;

	if(event != MOSQ_EVT_ACL_CHECK){
		abort();
	}

	if(!strcmp(mosquitto_client_id(ed->client), "allowed")){
		/* Attempt to change to a different existing ID after we have
		 * authenticated - should fail */
		rc = mosquitto_set_clientid(ed->client, "already-exists");
		if(rc != MOSQ_ERR_ALREADY_EXISTS){
			exit(1);
		}
	}


	if(!strcmp(mosquitto_client_id(ed->client), "allowed")){
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_ACL_DENIED;
	}
}

int mosquitto_auth_unpwd_check_v5(int event, void *event_data, void *user_data)
{
	struct mosquitto_evt_basic_auth *ed = event_data;
	const char *clientid;
	int rc;

	(void)user_data;

	clientid = mosquitto_client_id(ed->client);

	if(event != MOSQ_EVT_BASIC_AUTH){
		abort();
	}

	if(!strcmp(clientid, "id-change-test")){
		rc = mosquitto_set_clientid(ed->client, "allowed");
		if(strcmp(mosquitto_client_id(ed->client), "allowed")){
			rc = MOSQ_ERR_INVAL;
		}
		if(rc != MOSQ_ERR_SUCCESS){
			exit(1);
		}
	}

	return MOSQ_ERR_SUCCESS;
}
