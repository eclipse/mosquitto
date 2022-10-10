#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

static int tick_callback(int event, void *event_data, void *user_data);
static int unpwd_check_callback(int event, void *event_data, void *user_data);

static mosquitto_plugin_id_t *plg_id;

static char *username = NULL;
static char *password = NULL;
static char *client_id = NULL;
static int auth_delay = -1;

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	(void)user_data;
	(void)auth_opts;
	(void)auth_opt_count;

	plg_id = identifier;

	mosquitto_callback_register(plg_id, MOSQ_EVT_TICK, tick_callback, NULL, NULL);
	mosquitto_callback_register(plg_id, MOSQ_EVT_BASIC_AUTH, unpwd_check_callback, NULL, NULL);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	(void)user_data;
	(void)auth_opts;
	(void)auth_opt_count;

	free(username);
	free(password);
	free(client_id);

	mosquitto_callback_unregister(plg_id, MOSQ_EVT_BASIC_AUTH, unpwd_check_callback, NULL);
	mosquitto_callback_unregister(plg_id, MOSQ_EVT_TICK, tick_callback, NULL);

	return MOSQ_ERR_SUCCESS;
}

static int tick_callback(int event, void *event_data, void *user_data)
{
	struct mosquitto_evt_tick *ed = event_data;

	(void)user_data;

	if(event != MOSQ_EVT_TICK){
		abort();
	}

	if(auth_delay == 0){
		if(client_id && username && password
			&& !strcmp(username, "delayed-username") && !strcmp(password, "good")){

			mosquitto_complete_basic_auth(client_id, MOSQ_ERR_SUCCESS);
		}else{
			mosquitto_complete_basic_auth(client_id, MOSQ_ERR_AUTH);
		}
		free(username);
		free(password);
		free(client_id);
		username = NULL;
		password = NULL;
		client_id = NULL;
	}else if(auth_delay > 0){
		auth_delay--;
	}

	/* fast turn around for quick testing */
	ed->next_ms = 100;

	return MOSQ_ERR_SUCCESS;
}

static int unpwd_check_callback(int event, void *event_data, void *user_data)
{
	struct mosquitto_evt_basic_auth *ed = event_data;

	(void)event;
	(void)user_data;

	free(username);
	free(password);
	free(client_id);

	if(ed->username){
		username = strdup(ed->username);
	}
	if(ed->password){
		password = strdup(ed->password);
	}
	client_id = strdup(mosquitto_client_id(ed->client));
	/* Delay for arbitrary 10 ticks */
	auth_delay = 10;

	return MOSQ_ERR_AUTH_DELAYED;
}
