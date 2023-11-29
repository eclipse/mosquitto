#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <gsasl.h>


#define SAFE_STR(str) ((str) == NULL ? "(null)":str)
#define UNUSED(x) (void)x

struct method_list
{
	char *method;
	struct method_list *next;
};

struct login_pass_pair_list
{
	char *username;
	char *password;
	struct login_pass_pair_list *next;
};

struct session_clientid_pair_list{
	Gsasl_session *session;
	char *clientid;
	struct session_clientid_pair_list *next;
};

struct simple_plugin_config
{
	struct method_list *allowed_methods;
	struct login_pass_pair_list *users;
	mosquitto_plugin_id_t *identifier;
	Gsasl *gsasl_lib_ctx;
	struct session_clientid_pair_list *sessions;
};


#define TAG "SIMPLE PLUGIN"
#define log_debug(format, ...)      mosquitto_log_printf(MOSQ_LOG_DEBUG, "[%s]\tDEBUG\t%s:%s:%d\t" format, TAG, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);
#define log_info(format, ...)       mosquitto_log_printf(MOSQ_LOG_INFO, "[%s]\tINFO\t%s:%s:%d\t" format, TAG, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);
#define log_warning(format, ...)    mosquitto_log_printf(MOSQ_LOG_WARNING, "[%s]\tWARNING\t%s:%s:%d\t" format, TAG, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);
#define log_error(format, ...)      mosquitto_log_printf(MOSQ_LOG_ERR,  "[%s]\tERROR\t%s:%s:%d\t" format, TAG, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);


static int 	simple_plugin_extended_auth_start_handler(int EVENT, void *_event_data, void *userdata);
static int 	simple_plugin_extended_auth_continue_handler(int EVENT, void *_event_data, void *userdata);
static int 	simple_plugin_parse_config(struct mosquitto_opt *options, int option_count, struct simple_plugin_config *out);
static void	simple_plugin_cleanup(struct simple_plugin_config *config);

static bool simple_plugin_have_username(struct login_pass_pair_list *users, char *username);
static int 	simple_plugin_add_userpass(struct login_pass_pair_list **users, const char *username, const char *password);
static struct login_pass_pair_list *simple_plugin_get_pair(struct login_pass_pair_list *pairs, const char *clientid);
static void simple_plugin_cleanup_logpass_pairs_recursive(struct login_pass_pair_list *cur);

static bool simple_plugin_have_session(struct session_clientid_pair_list *sessions, const char *clientid);
static struct session_clientid_pair_list *simple_plugin_get_session(struct session_clientid_pair_list *sessions, const char *clientid);
static int  simple_plugin_add_session(struct session_clientid_pair_list **sessions, const char *clientid, Gsasl_session *session);
static void simple_plugin_delete_session(struct session_clientid_pair_list **sessions, const char *username);
static void simple_plugin_cleanup_sessions_recursive(struct session_clientid_pair_list *sessions);

static bool	simple_plugin_have_method(struct method_list *methods, const char *method);
static int  simple_plugin_add_method(struct method_list **methods, const char *method);
static void simple_plugin_cleanup_methods_recursive(struct method_list *methods);


int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)
{
	UNUSED(supported_version_count);
	UNUSED(supported_versions);
	return 5;
}


int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **userdata, struct mosquitto_opt *options, int option_count)
{
	int rc;
	struct simple_plugin_config *config;
	
	if (!identifier || !userdata) return MOSQ_ERR_INVAL;
	if (option_count > 0 && !options) return MOSQ_ERR_INVAL;

	*userdata = malloc(sizeof(struct simple_plugin_config));
	if (!(*userdata))
	{
		return MOSQ_ERR_NOMEM;
	}
	memset(*userdata, 0, sizeof(struct simple_plugin_config));
	config = (struct simple_plugin_config*)userdata;

	rc = gsasl_init(&config->gsasl_lib_ctx);
	if (rc != GSASL_OK)
	{
		log_error("gsasl init failure(%d ~ %s)", rc, gsasl_strerror(rc));
		simple_plugin_cleanup(config);
		return MOSQ_ERR_UNKNOWN;
	}

	config->identifier = identifier;

	rc = simple_plugin_parse_config(options, option_count, config);
	if (rc != MOSQ_ERR_SUCCESS){
		simple_plugin_cleanup(config);
		return rc;
	}

	rc = mosquitto_callback_register(
		config->identifier, 
		MOSQ_EVT_EXT_AUTH_START, 
		simple_plugin_extended_auth_start_handler, 
		NULL, config);
	if (rc != MOSQ_ERR_SUCCESS){
		log_error("cant register for auth_start callback");
		simple_plugin_cleanup(config);
		return rc;
	}

	rc = mosquitto_callback_register(
		config->identifier, 
		MOSQ_EVT_EXT_AUTH_CONTINUE, 
		simple_plugin_extended_auth_continue_handler, 
		NULL, config);
	if (rc != MOSQ_ERR_SUCCESS)
	{
		log_error("cant register for auth_cont callback");
		simple_plugin_cleanup(config);
		return rc;
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count)
{
	struct simple_plugin_config *config;

	UNUSED(options);
	UNUSED(option_count);

	config = (struct simple_plugin_config*)userdata;
	log_info("cleaning up");
	simple_plugin_cleanup(config);
	return MOSQ_ERR_SUCCESS;
}


int simple_plugin_extended_auth_start_handler(int EVENT, void *_event_data, void *userdata)
{
	int rc;
	const char *username;
	struct login_pass_pair_list *user;
	struct mosquitto_evt_extended_auth *event_data;
	Gsasl_session *new_session;
	const char *clientid;
	struct simple_plugin_config *config;

	UNUSED(EVENT);
	if (!_event_data || !userdata) return MOSQ_ERR_INVAL;

	config = (struct simple_plugin_config*)userdata;

	event_data = (struct mosquitto_evt_extended_auth *) _event_data;
	log_debug("get auth with type = %s and data = %s, data_len = %d", 
								event_data->auth_method, 
								SAFE_STR(event_data->data_in), 
								event_data->data_in_len);
	if (!simple_plugin_have_method(config->allowed_methods, event_data->auth_method))
	{
		log_error("unsupported method %s", event_data->auth_method);
		return MOSQ_ERR_PLUGIN_DEFER;
	}
	clientid = mosquitto_client_id(event_data->client);
	if (!clientid)
	{
		log_error("client should have client id");
		return MOSQ_ERR_INVAL;
	}
	username = mosquitto_client_username(event_data->client);
	if (!username)
	{
		log_error("cant authenticate user without username");
		return MOSQ_ERR_AUTH;
	}
	user = simple_plugin_get_pair(config->users, username);
	if (!user)
	{
		log_error("No user with username - %s", username);
		return MOSQ_ERR_AUTH;
	}
	if (simple_plugin_have_session(config->sessions, clientid)){
		simple_plugin_delete_session(&config->sessions, clientid);
	}

	rc = gsasl_server_start(config->gsasl_lib_ctx, event_data->auth_method, &new_session);
	if (rc != GSASL_OK)
	{
		log_error("gsasl start error(%d~%s)", rc, gsasl_strerror(rc));
		return MOSQ_ERR_UNKNOWN;
	}
	rc = simple_plugin_add_session(&config->sessions, clientid, new_session);
	if (rc != MOSQ_ERR_SUCCESS) return rc;

	gsasl_property_set(new_session, GSASL_PASSWORD, user->password);
	gsasl_property_set(new_session, GSASL_AUTHID, user->username);

	rc = gsasl_step(
		new_session, 
		event_data->data_in, event_data->data_in_len, 
		(char **)&event_data->data_out, (size_t *)&event_data->data_out_len
	);

	if (rc != GSASL_OK && rc != GSASL_NEEDS_MORE)
	{
		log_error("gsasl_server_step error(%d~%s)", rc, gsasl_strerror(rc));
		return MOSQ_ERR_AUTH;
	}
	if (rc == GSASL_OK) 
	{
		simple_plugin_delete_session(&config->sessions, clientid);
		return MOSQ_ERR_SUCCESS;
	}
	else return MOSQ_ERR_AUTH_CONTINUE;
}


int simple_plugin_extended_auth_continue_handler(int EVENT, void *_event_data, void *userdata)
{
	int rc;
	struct mosquitto_evt_extended_auth *event_data;
	const char *clientid;
	struct session_clientid_pair_list *session;
	struct simple_plugin_config *config;

	UNUSED(EVENT);
	if (!_event_data || !userdata) return MOSQ_ERR_INVAL;

	config = (struct simple_plugin_config*)userdata;

	event_data = (struct mosquitto_evt_extended_auth *)_event_data;
	clientid = mosquitto_client_id(event_data->client);
	session = simple_plugin_get_session(config->sessions, clientid);
	if (!session) return MOSQ_ERR_AUTH;

	log_debug("get auth continue with type = %s and data = %s", event_data->auth_method, event_data->data_in);
	rc = gsasl_step(
		session->session, 
		event_data->data_in, event_data->data_in_len, 
		(char **)&event_data->data_out, (size_t *)&event_data->data_out_len
	);
	if (rc != GSASL_OK && rc != GSASL_NEEDS_MORE)
	{
		log_error("gsasl_server_step error(%d~%s)", rc, gsasl_strerror(rc));
		return MOSQ_ERR_AUTH;
	}
	if (rc == GSASL_OK){
		simple_plugin_delete_session(&config->sessions, clientid);
		return MOSQ_ERR_SUCCESS;	
	} 
	else return MOSQ_ERR_AUTH_CONTINUE;
}


int simple_plugin_parse_config(struct mosquitto_opt *options, int option_count, struct simple_plugin_config *out)
{
#define METHOD_CONFIG_KEY "method"
#define LOGINPASS_CONFIG_KEY "loginpass"
#define CRAM_MD5_METHOD_STRING "CRAM-MD5"
#define PLAIN_METHOD_STRING "PLAIN"
#define SCRAM_METHOD_STRING "SCRAM-SHA-1"
	int i;
	int rc;
	struct method_list *cur;
	char *username;
	char *password;
	char *delimiter_ptr;
	struct login_pass_pair_list *cur_user;


	if (!out) return MOSQ_ERR_INVAL;
	if (option_count > 0 && !options) return MOSQ_ERR_INVAL;

	out->sessions = NULL;
	out->users = NULL;

	out->allowed_methods = NULL;
	rc = simple_plugin_add_method(&out->allowed_methods, CRAM_MD5_METHOD_STRING);
	if (rc != MOSQ_ERR_SUCCESS) return rc;
	rc = simple_plugin_add_method(&out->allowed_methods, PLAIN_METHOD_STRING);
	if (rc != MOSQ_ERR_SUCCESS) return rc;
	rc = simple_plugin_add_method(&out->allowed_methods, SCRAM_METHOD_STRING);
	if (rc != MOSQ_ERR_SUCCESS) return rc;

	for (i = 0; i < option_count; ++i)
	{
		if (strncmp(options[i].key, LOGINPASS_CONFIG_KEY, sizeof(LOGINPASS_CONFIG_KEY)) == 0){
			if (strchr(options[i].value, ':') == NULL){
				log_error("bad login:pass format(need to be username:password)");
				return MOSQ_ERR_INVAL;
			}

			/* make username:password username\0password and copy username and password after */
			delimiter_ptr = strchr(options[i].value, ':');
			*delimiter_ptr = '\0';
			username = NULL;
			password = NULL;
			username = strdup(options[i].value);
			password = strdup(delimiter_ptr + 1);
			*delimiter_ptr = ':';
			if (!username || !password){
				free(username);
				free(password);
				return MOSQ_ERR_NOMEM; 
			}
			if (strlen(username) == 0 || strlen(password) == 0){
				free(username);
				free(password);
				log_error("cant have empty username or password");
				return MOSQ_ERR_INVAL;
			}
			if (simple_plugin_have_username(out->users, username)){
				free(username);
				free(password);
				log_error("all users should have unique names");
				return MOSQ_ERR_INVAL;
			}
			/* this funcion will strdup username and pass by itself, should free after call */
			rc = simple_plugin_add_userpass(&out->users, username, password);
			if (rc != MOSQ_ERR_SUCCESS) return rc;
			free(username);
			free(password);
		}
	}

	cur = out->allowed_methods;
	log_debug("confugured allowed_methods:");
	while (cur){
		log_debug("%s", cur->method);
		cur = cur->next;
	}
	cur_user = out->users;
	log_debug("usernames and passwords:");
	while (cur_user){
		log_debug("%s:%s", cur_user->username, cur_user->password);
		cur_user = cur_user->next;
	}
	return MOSQ_ERR_SUCCESS;
}


bool simple_plugin_have_username(struct login_pass_pair_list *users, char *username)
{
	if (!username) return false;
	if (!users) return false;

	return simple_plugin_get_pair(users, username) != NULL;
}


int simple_plugin_add_userpass(struct login_pass_pair_list **users, const char *username, const char *password)
{
	struct login_pass_pair_list *cur;
	struct login_pass_pair_list *new;

	if (!username || !password) return MOSQ_ERR_INVAL;

	new = malloc(sizeof(struct login_pass_pair_list));
	if (!new) return MOSQ_ERR_NOMEM;
	bzero(new, sizeof(struct login_pass_pair_list));
	new->username = strdup(username);
	new->password = strdup(password);
	if (!new->username || !new->password)
	{
		free(new->username);
		free(new->password);
		free(new);
		return MOSQ_ERR_NOMEM;
	}

	if (*users)
	{
		cur = *users;
		while (cur->next) cur = cur->next;
		cur->next = new;
	}
	else
	{
		*users = new;
	}
	return MOSQ_ERR_SUCCESS;
}


struct login_pass_pair_list *simple_plugin_get_pair(struct login_pass_pair_list *pairs, const char *username)
{
	struct login_pass_pair_list *cur_user;

	if (!pairs) return NULL;
	if (!username) return NULL;

	cur_user = pairs;
	while (cur_user){
		if (strcmp(cur_user->username, username) == 0){
			break;
		}
		cur_user = cur_user->next;
	}
	return cur_user;
}


struct session_clientid_pair_list *simple_plugin_get_session(struct session_clientid_pair_list *sessions, const char *clientid)
{
	struct session_clientid_pair_list *cur;

	if (!clientid) return false;
	if (!sessions) return false;

	cur = sessions;
	while (cur){
		if (strcmp(cur->clientid, clientid) == 0){
			return cur;
		}
		cur = cur->next;
	}
	return NULL;
}


bool simple_plugin_have_session(struct session_clientid_pair_list *sessions, const char *clientid)
{
	if (!clientid) return false;
	if (!sessions) return false;

	return simple_plugin_get_session(sessions, clientid) == NULL ? false : true;
}


int simple_plugin_add_session(struct session_clientid_pair_list **sessions, const char *clientid, Gsasl_session *session)
{
	struct session_clientid_pair_list *cur;
	struct session_clientid_pair_list *new;

	if (!clientid || !session) return MOSQ_ERR_INVAL;

	new = malloc(sizeof(struct session_clientid_pair_list));
	if (!new) return MOSQ_ERR_NOMEM;
	new->next = NULL;
	new->session = session;
	new->clientid = strdup(clientid);
	if (!clientid)
	{
		free(new);
		return MOSQ_ERR_NOMEM;
	}

	if (*sessions)
	{
		cur = *sessions;
		while (cur->next) cur = cur->next;
		cur->next = new;
	}
	else
	{
		*sessions = new;
	}
	return MOSQ_ERR_SUCCESS;

}


void simple_plugin_delete_session(struct session_clientid_pair_list **sessions, const char *clientid)
{
	struct session_clientid_pair_list *cur;
	struct session_clientid_pair_list *prev;

	if (!sessions) return;
	if (!*sessions) return;
	if (!clientid) return;

	prev = *sessions;
	cur = prev->next;
	if (strcmp(prev->clientid, clientid) == 0){
		*sessions = prev->next;
		gsasl_finish(prev->session);
		free(prev->clientid);
		free(prev);
	}else{
		while (cur){
			if (strcmp(cur->clientid, clientid) == 0){
				prev->next = cur->next;
				gsasl_finish(cur->session);
				free(prev->clientid);
				free(cur);
			}
			prev = cur;
			cur = prev->next;
		}
	}
}


bool simple_plugin_have_method(struct method_list *methods, const char *method)
{
	struct method_list *cur;

	if (!methods || !method) return false;

	cur = methods;
	while (cur)
	{
		if (strcmp(cur->method, method) == 0)
		{
			return true;
		}
		cur = cur->next;
	}
	return false;
}


int simple_plugin_add_method(struct method_list **methods, const char *method)
{
	struct method_list *cur;
	struct method_list *new;

	if (!method) return MOSQ_ERR_INVAL;

	new = malloc(sizeof(struct method_list));
	if (!new) return MOSQ_ERR_NOMEM;
	new->next = NULL;
	new->method = strdup(method);
	if (!new->method)
	{
		free(new);
		return MOSQ_ERR_NOMEM;
	}

	if (*methods)
	{
		cur = *methods;
		while (cur->next) cur = cur->next;
		cur->next = new;
	} 
	else
	{
		(*methods) = new;
	}
	return MOSQ_ERR_SUCCESS;
}



void simple_plugin_cleanup(struct simple_plugin_config *config)
{
	if (!config) return;

	simple_plugin_cleanup_logpass_pairs_recursive(config->users);
	simple_plugin_cleanup_methods_recursive(config->allowed_methods);
	simple_plugin_cleanup_sessions_recursive(config->sessions);
	config->users = NULL;
	config->allowed_methods = NULL;

	mosquitto_callback_unregister(config->identifier, MOSQ_EVT_EXT_AUTH_START, 
											simple_plugin_extended_auth_continue_handler, NULL);
	mosquitto_callback_unregister(config->identifier, MOSQ_EVT_EXT_AUTH_START, 
											simple_plugin_extended_auth_start_handler, NULL);

	gsasl_done(config->gsasl_lib_ctx);
	free(config);
}


void simple_plugin_cleanup_logpass_pairs_recursive(struct login_pass_pair_list *users)
{
	if (!users) return;

	simple_plugin_cleanup_logpass_pairs_recursive(users->next);
	free(users->username);
	free(users->password);
	free(users);
}


void simple_plugin_cleanup_methods_recursive(struct method_list *methods)
{
	if (!methods) return;

	simple_plugin_cleanup_methods_recursive(methods->next);
	free(methods->method);
	free(methods);
}


void simple_plugin_cleanup_sessions_recursive(struct session_clientid_pair_list *sessions)
{
	if (!sessions) return;

	simple_plugin_cleanup_sessions_recursive(sessions->next);
	gsasl_finish(sessions->session);
	free(sessions->clientid);
	free(sessions);
}