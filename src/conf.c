/*
Copyright (c) 2009-2015 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
*/

#include <config.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef WIN32
#else
#  include <dirent.h>
#endif

#ifndef WIN32
#  include <netdb.h>
#  include <sys/socket.h>
#else
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif

#if !defined(WIN32) && !defined(__CYGWIN__)
#  include <sys/syslog.h>
#endif

#include "mosquitto_broker.h"
#include "memory_mosq.h"
#include "tls_mosq.h"
#include "util_mosq.h"
#include "mqtt3_protocol.h"

struct config_recurse {
	int log_dest;
	int log_dest_set;
	int log_type;
	int log_type_set;
	int max_inflight_messages;
	int max_queued_messages;
};

#if defined(WIN32) || defined(__CYGWIN__)
#include <windows.h>
extern SERVICE_STATUS_HANDLE service_handle;
#endif

static int conf__parse_bool(char **token, const char *name, bool *value, char *saveptr);
static int conf__parse_int(char **token, const char *name, int *value, char *saveptr);
static int conf__parse_string(char **token, const char *name, char **value, char *saveptr);
static int config__read_file(struct mosquitto__config *config, bool reload, const char *file, struct config_recurse *config_tmp, int level, int *lineno);
static int config__check(struct mosquitto__config *config);

static int conf__attempt_resolve(const char *host, const char *text, int log, const char *msg)
{
	struct addrinfo gai_hints;
	struct addrinfo *gai_res;
	int rc;

	memset(&gai_hints, 0, sizeof(struct addrinfo));
	gai_hints.ai_family = PF_UNSPEC;
	gai_hints.ai_flags = AI_ADDRCONFIG;
	gai_hints.ai_socktype = SOCK_STREAM;
	gai_res = NULL;
	rc = getaddrinfo(host, NULL, &gai_hints, &gai_res);
	if(gai_res){
		freeaddrinfo(gai_res);
	}
	if(rc != 0){
#ifndef WIN32
		if(rc == EAI_SYSTEM){
			if(errno == ENOENT){
				log__printf(NULL, log, "%s: Unable to resolve %s %s.", msg, text, host);
			}else{
				log__printf(NULL, log, "%s: Error resolving %s: %s.", msg, text, strerror(errno));
			}
		}else{
			log__printf(NULL, log, "%s: Error resolving %s: %s.", msg, text, gai_strerror(rc));
		}
#else
		if(rc == WSAHOST_NOT_FOUND){
			log__printf(NULL, log, "%s: Error resolving %s.", msg, text);
		}
#endif
		return MOSQ_ERR_INVAL;
	}
	return MOSQ_ERR_SUCCESS;
}

static void config__init_reload(struct mosquitto__config *config)
{
	int i;
	int j;
	struct mosquitto__auth_plugin_config *plug;

	/* Set defaults */
	mosquitto__free(config->acl_file);
	config->acl_file = NULL;
	config->allow_anonymous = true;
	config->allow_duplicate_messages = false;
	config->allow_zero_length_clientid = true;
	config->auto_id_prefix = NULL;
	config->auto_id_prefix_len = 0;
	config->autosave_interval = 1800;
	config->autosave_on_changes = false;
	mosquitto__free(config->clientid_prefixes);
	config->connection_messages = true;
	config->clientid_prefixes = NULL;
	if(config->log_fptr){
		fclose(config->log_fptr);
		config->log_fptr = NULL;
	}
	mosquitto__free(config->log_file);
	config->log_file = NULL;

#if defined(WIN32) || defined(__CYGWIN__)
	if(service_handle){
		/* This is running as a Windows service. Default to no logging. Using
		 * stdout/stderr is forbidden because the first clients to connect will
		 * get log information sent to them for some reason. */
		config->log_dest = MQTT3_LOG_NONE;
	}else{
		config->log_dest = MQTT3_LOG_STDERR;
	}
#else
	config->log_facility = LOG_DAEMON;
	config->log_dest = MQTT3_LOG_STDERR;
	if(config->verbose){
		config->log_type = INT_MAX;
	}else{
		config->log_type = MOSQ_LOG_ERR | MOSQ_LOG_WARNING | MOSQ_LOG_NOTICE | MOSQ_LOG_INFO;
	}
#endif
	config->log_timestamp = true;
	mosquitto__free(config->password_file);
	config->password_file = NULL;
	config->persistence = false;
	mosquitto__free(config->persistence_location);
	config->persistence_location = NULL;
	mosquitto__free(config->persistence_file);
	config->persistence_file = NULL;
	config->persistent_client_expiration = 0;
	mosquitto__free(config->psk_file);
	config->psk_file = NULL;
	config->queue_qos0_messages = false;
	config->sys_interval = 10;
	config->upgrade_outgoing_qos = false;
	if(config->auth_plugins){
		for(i=0; i<config->auth_plugin_count; i++){
			plug = &config->auth_plugins[i];
			mosquitto__free(plug->path);
			plug->path = NULL;

			if(plug->options){
				for(j=0; j<plug->option_count; j++){
					mosquitto__free(plug->options[j].key);
					mosquitto__free(plug->options[j].value);
				}
				mosquitto__free(plug->options);
				plug->options = NULL;
				plug->option_count = 0;
			}
		}
		mosquitto__free(config->auth_plugins);
		config->auth_plugins = NULL;
	}
}

void config__init(struct mosquitto__config *config)
{
	memset(config, 0, sizeof(struct mosquitto__config));
	config__init_reload(config);
	config->config_file = NULL;
	config->daemon = false;
	config->default_listener.host = NULL;
	config->default_listener.port = 0;
	config->default_listener.max_connections = -1;
	config->default_listener.mount_point = NULL;
	config->default_listener.socks = NULL;
	config->default_listener.sock_count = 0;
	config->default_listener.client_count = 0;
	config->default_listener.protocol = mp_mqtt;
	config->default_listener.use_username_as_clientid = false;
#ifdef WITH_TLS
	config->default_listener.tls_version = NULL;
	config->default_listener.cafile = NULL;
	config->default_listener.capath = NULL;
	config->default_listener.certfile = NULL;
	config->default_listener.keyfile = NULL;
	config->default_listener.ciphers = NULL;
	config->default_listener.psk_hint = NULL;
	config->default_listener.require_certificate = false;
	config->default_listener.crlfile = NULL;
	config->default_listener.use_identity_as_username = false;
	config->default_listener.use_subject_as_username = false;
#endif
	config->listeners = NULL;
	config->listener_count = 0;
	config->pid_file = NULL;
	config->user = NULL;
#ifdef WITH_BRIDGE
	config->bridges = NULL;
	config->bridge_count = 0;
#endif
	config->auth_plugins = NULL;
	config->verbose = false;
	config->message_size_limit = 0;
}

void config__cleanup(struct mosquitto__config *config)
{
	int i;
	int j;
	struct mosquitto__auth_plugin_config *plug;

	mosquitto__free(config->acl_file);
	mosquitto__free(config->auto_id_prefix);
	mosquitto__free(config->clientid_prefixes);
	mosquitto__free(config->config_file);
	mosquitto__free(config->password_file);
	mosquitto__free(config->persistence_location);
	mosquitto__free(config->persistence_file);
	mosquitto__free(config->persistence_filepath);
	mosquitto__free(config->psk_file);
	mosquitto__free(config->pid_file);
	if(config->listeners){
		for(i=0; i<config->listener_count; i++){
			mosquitto__free(config->listeners[i].host);
			mosquitto__free(config->listeners[i].mount_point);
			mosquitto__free(config->listeners[i].socks);
#ifdef WITH_TLS
			mosquitto__free(config->listeners[i].cafile);
			mosquitto__free(config->listeners[i].capath);
			mosquitto__free(config->listeners[i].certfile);
			mosquitto__free(config->listeners[i].keyfile);
			mosquitto__free(config->listeners[i].ciphers);
			mosquitto__free(config->listeners[i].psk_hint);
			mosquitto__free(config->listeners[i].crlfile);
			mosquitto__free(config->listeners[i].tls_version);
			SSL_CTX_free(config->listeners[i].ssl_ctx);
#endif
#ifdef WITH_WEBSOCKETS
			mosquitto__free(config->listeners[i].http_dir);
#endif
		}
		mosquitto__free(config->listeners);
	}
#ifdef WITH_BRIDGE
	if(config->bridges){
		for(i=0; i<config->bridge_count; i++){
			mosquitto__free(config->bridges[i].name);
			if(config->bridges[i].addresses){
				for(j=0; j<config->bridges[i].address_count; j++){
					mosquitto__free(config->bridges[i].addresses[j].address);
				}
				mosquitto__free(config->bridges[i].addresses);
			}
			mosquitto__free(config->bridges[i].remote_clientid);
			mosquitto__free(config->bridges[i].remote_username);
			mosquitto__free(config->bridges[i].remote_password);
			mosquitto__free(config->bridges[i].local_clientid);
			mosquitto__free(config->bridges[i].local_username);
			mosquitto__free(config->bridges[i].local_password);
			if(config->bridges[i].topics){
				for(j=0; j<config->bridges[i].topic_count; j++){
					mosquitto__free(config->bridges[i].topics[j].topic);
					mosquitto__free(config->bridges[i].topics[j].local_prefix);
					mosquitto__free(config->bridges[i].topics[j].remote_prefix);
					mosquitto__free(config->bridges[i].topics[j].local_topic);
					mosquitto__free(config->bridges[i].topics[j].remote_topic);
				}
				mosquitto__free(config->bridges[i].topics);
			}
			mosquitto__free(config->bridges[i].notification_topic);
#ifdef WITH_TLS
			mosquitto__free(config->bridges[i].tls_version);
			mosquitto__free(config->bridges[i].tls_cafile);
#ifdef REAL_WITH_TLS_PSK
			mosquitto__free(config->bridges[i].tls_psk_identity);
			mosquitto__free(config->bridges[i].tls_psk);
#endif
#endif
		}
		mosquitto__free(config->bridges);
	}
#endif
	if(config->auth_plugins){
		for(i=0; i<config->auth_plugin_count; i++){
			plug = &config->auth_plugins[i];
			mosquitto__free(plug->path);
			plug->path = NULL;
			if(plug->options){
				for(j=0; j<plug->option_count; j++){
					mosquitto__free(plug->options[j].key);
					mosquitto__free(plug->options[j].value);
				}
				mosquitto__free(plug->options);
				plug->options = NULL;
				plug->option_count = 0;
			}
		}
		mosquitto__free(config->auth_plugins);
		config->auth_plugins = NULL;
	}

	if(config->log_fptr){
		fclose(config->log_fptr);
		config->log_fptr = NULL;
	}
	if(config->log_file){
		mosquitto__free(config->log_file);
		config->log_file = NULL;
	}
}

static void print_usage(void)
{
	printf("mosquitto version %s (build date %s)\n\n", VERSION, TIMESTAMP);
	printf("mosquitto is an MQTT v3.1.1 broker.\n\n");
	printf("Usage: mosquitto [-c config_file] [-d] [-h] [-p port]\n\n");
	printf(" -c : specify the broker config file.\n");
	printf(" -d : put the broker into the background after starting.\n");
	printf(" -h : display this help.\n");
	printf(" -p : start the broker listening on the specified port.\n");
	printf("      Not recommended in conjunction with the -c option.\n");
	printf(" -v : verbose mode - enable all logging types. This overrides\n");
	printf("      any logging options given in the config file.\n");
	printf("\nSee http://mosquitto.org/ for more information.\n\n");
}

int config__parse_args(struct mosquitto__config *config, int argc, char *argv[])
{
	int i;
	int port_tmp;

	for(i=1; i<argc; i++){
		if(!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config-file")){
			if(i<argc-1){
				config->config_file = mosquitto__strdup(argv[i+1]);
				if(!config->config_file){
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
					return MOSQ_ERR_NOMEM;
				}

				if(config__read(config, false)){
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open configuration file.");
					return MOSQ_ERR_INVAL;
				}
			}else{
				log__printf(NULL, MOSQ_LOG_ERR, "Error: -c argument given, but no config file specified.");
				return MOSQ_ERR_INVAL;
			}
			i++;
		}else if(!strcmp(argv[i], "-d") || !strcmp(argv[i], "--daemon")){
			config->daemon = true;
		}else if(!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")){
			print_usage();
			return MOSQ_ERR_INVAL;
		}else if(!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")){
			if(i<argc-1){
				port_tmp = atoi(argv[i+1]);
				if(port_tmp<1 || port_tmp>65535){
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid port specified (%d).", port_tmp);
					return MOSQ_ERR_INVAL;
				}else{
					if(config->default_listener.port){
						log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Default listener port specified multiple times. Only the latest will be used.");
					}
					config->default_listener.port = port_tmp;
				}
			}else{
				log__printf(NULL, MOSQ_LOG_ERR, "Error: -p argument given, but no port specified.");
				return MOSQ_ERR_INVAL;
			}
			i++;
		}else if(!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")){
			config->verbose = true;
		}else{
			fprintf(stderr, "Error: Unknown option '%s'.\n",argv[i]);
			print_usage();
			return MOSQ_ERR_INVAL;
		}
	}

	if(config->listener_count == 0
#ifdef WITH_TLS
			|| config->default_listener.cafile
			|| config->default_listener.capath
			|| config->default_listener.certfile
			|| config->default_listener.keyfile
			|| config->default_listener.ciphers
			|| config->default_listener.psk_hint
			|| config->default_listener.require_certificate
			|| config->default_listener.crlfile
			|| config->default_listener.use_identity_as_username
			|| config->default_listener.use_subject_as_username
#endif
			|| config->default_listener.use_username_as_clientid
			|| config->default_listener.host
			|| config->default_listener.port
			|| config->default_listener.max_connections != -1
			|| config->default_listener.mount_point
			|| config->default_listener.protocol != mp_mqtt){

		config->listener_count++;
		config->listeners = mosquitto__realloc(config->listeners, sizeof(struct mosquitto__listener)*config->listener_count);
		if(!config->listeners){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
		memset(&config->listeners[config->listener_count-1], 0, sizeof(struct mosquitto__listener));
		if(config->default_listener.port){
			config->listeners[config->listener_count-1].port = config->default_listener.port;
		}else{
			config->listeners[config->listener_count-1].port = 1883;
		}
		if(config->default_listener.host){
			config->listeners[config->listener_count-1].host = config->default_listener.host;
		}else{
			config->listeners[config->listener_count-1].host = NULL;
		}
		if(config->default_listener.mount_point){
			config->listeners[config->listener_count-1].mount_point = config->default_listener.mount_point;
		}else{
			config->listeners[config->listener_count-1].mount_point = NULL;
		}
		config->listeners[config->listener_count-1].max_connections = config->default_listener.max_connections;
		config->listeners[config->listener_count-1].protocol = config->default_listener.protocol;
		config->listeners[config->listener_count-1].client_count = 0;
		config->listeners[config->listener_count-1].socks = NULL;
		config->listeners[config->listener_count-1].sock_count = 0;
		config->listeners[config->listener_count-1].client_count = 0;
		config->listeners[config->listener_count-1].use_username_as_clientid = config->default_listener.use_username_as_clientid;
#ifdef WITH_TLS
		config->listeners[config->listener_count-1].tls_version = config->default_listener.tls_version;
		config->listeners[config->listener_count-1].cafile = config->default_listener.cafile;
		config->listeners[config->listener_count-1].capath = config->default_listener.capath;
		config->listeners[config->listener_count-1].certfile = config->default_listener.certfile;
		config->listeners[config->listener_count-1].keyfile = config->default_listener.keyfile;
		config->listeners[config->listener_count-1].ciphers = config->default_listener.ciphers;
		config->listeners[config->listener_count-1].psk_hint = config->default_listener.psk_hint;
		config->listeners[config->listener_count-1].require_certificate = config->default_listener.require_certificate;
		config->listeners[config->listener_count-1].ssl_ctx = NULL;
		config->listeners[config->listener_count-1].crlfile = config->default_listener.crlfile;
		config->listeners[config->listener_count-1].use_identity_as_username = config->default_listener.use_identity_as_username;
		config->listeners[config->listener_count-1].use_subject_as_username = config->default_listener.use_subject_as_username;
#endif
	}

	/* Default to drop to mosquitto user if we are privileged and no user specified. */
	if(!config->user){
		config->user = "mosquitto";
	}
	if(config->verbose){
		config->log_type = INT_MAX;
	}
	return config__check(config);
}

int config__read(struct mosquitto__config *config, bool reload)
{
	int rc = MOSQ_ERR_SUCCESS;
	struct config_recurse cr;
	int lineno;
	int len;
#ifdef WITH_BRIDGE
	int i;
#endif

	cr.log_dest = MQTT3_LOG_NONE;
	cr.log_dest_set = 0;
	cr.log_type = MOSQ_LOG_NONE;
	cr.log_type_set = 0;
	cr.max_inflight_messages = 20;
	cr.max_queued_messages = 100;

	if(!config->config_file) return 0;

	if(reload){
		/* Re-initialise appropriate config vars to default for reload. */
		config__init_reload(config);
	}
	rc = config__read_file(config, reload, config->config_file, &cr, 0, &lineno);
	if(rc){
		log__printf(NULL, MOSQ_LOG_ERR, "Error found at %s:%d.", config->config_file, lineno);
		return rc;
	}

#ifdef WITH_PERSISTENCE
	if(config->persistence){
		if(!config->persistence_file){
			config->persistence_file = mosquitto__strdup("mosquitto.db");
			if(!config->persistence_file) return MOSQ_ERR_NOMEM;
		}
		mosquitto__free(config->persistence_filepath);
		if(config->persistence_location && strlen(config->persistence_location)){
			len = strlen(config->persistence_location) + strlen(config->persistence_file) + 1;
			config->persistence_filepath = mosquitto__malloc(len);
			if(!config->persistence_filepath) return MOSQ_ERR_NOMEM;
			snprintf(config->persistence_filepath, len, "%s%s", config->persistence_location, config->persistence_file);
		}else{
			config->persistence_filepath = mosquitto__strdup(config->persistence_file);
			if(!config->persistence_filepath) return MOSQ_ERR_NOMEM;
		}
	}
#endif
	/* Default to drop to mosquitto user if no other user specified. This must
	 * remain here even though it is covered in config__parse_args() because this
	 * function may be called on its own. */
	if(!config->user){
		config->user = "mosquitto";
	}

	db__limits_set(cr.max_inflight_messages, cr.max_queued_messages);

#ifdef WITH_BRIDGE
	for(i=0; i<config->bridge_count; i++){
		if(!config->bridges[i].name || !config->bridges[i].addresses || !config->bridges[i].topic_count){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
			return MOSQ_ERR_INVAL;
		}
#ifdef REAL_WITH_TLS_PSK
		if(config->bridges[i].tls_psk && !config->bridges[i].tls_psk_identity){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration: missing bridge_identity.\n");
			return MOSQ_ERR_INVAL;
		}
		if(config->bridges[i].tls_psk_identity && !config->bridges[i].tls_psk){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration: missing bridge_psk.\n");
			return MOSQ_ERR_INVAL;
		}
#endif
	}
#endif

	if(cr.log_dest_set){
		config->log_dest = cr.log_dest;
	}
	if(config->verbose){
		config->log_type = INT_MAX;
	}else if(cr.log_type_set){
		config->log_type = cr.log_type;
	}
	return MOSQ_ERR_SUCCESS;
}

int config__read_file_core(struct mosquitto__config *config, bool reload, const char *file, struct config_recurse *cr, int level, int *lineno, FILE *fptr)
{
	int rc;
	char buf[1024];
	char *token;
	int tmp_int;
	char *saveptr = NULL;
#ifdef WITH_BRIDGE
	struct mosquitto__bridge *cur_bridge = NULL;
	struct mosquitto__bridge_topic *cur_topic;
#endif
	struct mosquitto__auth_plugin_config *cur_auth_plugin = NULL;

	time_t expiration_mult;
	char *key;
	char *conf_file;
#ifdef WIN32
	HANDLE fh;
	char dirpath[MAX_PATH];
	WIN32_FIND_DATA find_data;
#else
	DIR *dh;
	struct dirent *de;
#endif
	int len;
	struct mosquitto__listener *cur_listener = &config->default_listener;
#ifdef WITH_BRIDGE
	char *address;
	int i;
#endif
	int lineno_ext;

	*lineno = 0;

	while(fgets(buf, 1024, fptr)){
		(*lineno)++;
		if(buf[0] != '#' && buf[0] != 10 && buf[0] != 13){
			while(buf[strlen(buf)-1] == 10 || buf[strlen(buf)-1] == 13){
				buf[strlen(buf)-1] = 0;
			}
			token = strtok_r(buf, " ", &saveptr);
			if(token){
				if(!strcmp(token, "acl_file")){
					if(reload){
						mosquitto__free(config->acl_file);
						config->acl_file = NULL;
					}
					if(conf__parse_string(&token, "acl_file", &config->acl_file, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "address") || !strcmp(token, "addresses")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge || cur_bridge->addresses){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					while((token = strtok_r(NULL, " ", &saveptr))){
						cur_bridge->address_count++;
						cur_bridge->addresses = mosquitto__realloc(cur_bridge->addresses, sizeof(struct bridge_address)*cur_bridge->address_count);
						if(!cur_bridge->addresses){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
						cur_bridge->addresses[cur_bridge->address_count-1].address = token;
					}
					for(i=0; i<cur_bridge->address_count; i++){
						address = strtok_r(cur_bridge->addresses[i].address, ":", &saveptr);
						if(address){
							token = strtok_r(NULL, ":", &saveptr);
							if(token){
								tmp_int = atoi(token);
								if(tmp_int < 1 || tmp_int > 65535){
									log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid port value (%d).", tmp_int);
									return MOSQ_ERR_INVAL;
								}
								cur_bridge->addresses[i].port = tmp_int;
							}else{
								cur_bridge->addresses[i].port = 1883;
							}
							cur_bridge->addresses[i].address = mosquitto__strdup(address);
							conf__attempt_resolve(address, "bridge address", MOSQ_LOG_WARNING, "Warning");
						}
					}
					if(cur_bridge->address_count == 0){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty address value in configuration.");
						return MOSQ_ERR_INVAL;
					}
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "allow_anonymous")){
					if(conf__parse_bool(&token, "allow_anonymous", &config->allow_anonymous, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "allow_duplicate_messages")){
					if(conf__parse_bool(&token, "allow_duplicate_messages", &config->allow_duplicate_messages, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "allow_zero_length_clientid")){
					if(conf__parse_bool(&token, "allow_zero_length_clientid", &config->allow_zero_length_clientid, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strncmp(token, "auth_opt_", 9)){
					if(!cur_auth_plugin){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: An auth_opt_ option exists in the config file without an auth_plugin.");
						return MOSQ_ERR_INVAL;
					}
					if(strlen(token) < 12){
						/* auth_opt_ == 9, + one digit key == 10, + one space == 11, + one value == 12 */
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid auth_opt_ config option.");
						return MOSQ_ERR_INVAL;
					}
					key = mosquitto__strdup(&token[9]);
					if(!key){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
						return MOSQ_ERR_NOMEM;
					}else if(STREMPTY(key)){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid auth_opt_ config option.");
						return MOSQ_ERR_INVAL;
					}
					token += 9+strlen(key)+1;
					while(token[0] == ' ' || token[0] == '\t'){
						token++;
					}
					if(token[0]){
						cur_auth_plugin->option_count++;
						cur_auth_plugin->options = mosquitto__realloc(cur_auth_plugin->options, cur_auth_plugin->option_count*sizeof(struct mosquitto_auth_opt));
						if(!cur_auth_plugin->options){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
						cur_auth_plugin->options[cur_auth_plugin->option_count-1].key = key;
						cur_auth_plugin->options[cur_auth_plugin->option_count-1].value = mosquitto__strdup(token);
						if(!cur_auth_plugin->options[cur_auth_plugin->option_count-1].value){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty %s value in configuration.", key);
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "auth_plugin")){
					if(reload) continue; // Auth plugin not currently valid for reloading.
					config->auth_plugins = mosquitto__realloc(config->auth_plugins, (config->auth_plugin_count+1)*sizeof(struct mosquitto__auth_plugin_config));
					if(!config->auth_plugins){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
						return MOSQ_ERR_NOMEM;
					}
					cur_auth_plugin = &config->auth_plugins[config->auth_plugin_count];
					cur_auth_plugin->path = NULL;
					cur_auth_plugin->options = NULL;
					cur_auth_plugin->option_count = 0;
					config->auth_plugin_count++;
					if(conf__parse_string(&token, "auth_plugin", &cur_auth_plugin->path, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "auto_id_prefix")){
					if(conf__parse_string(&token, "auto_id_prefix", &config->auto_id_prefix, saveptr)) return MOSQ_ERR_INVAL;
					if(config->auto_id_prefix){
						config->auto_id_prefix_len = strlen(config->auto_id_prefix);
					}else{
						config->auto_id_prefix_len = 0;
					}
				}else if(!strcmp(token, "autosave_interval")){
					if(conf__parse_int(&token, "autosave_interval", &config->autosave_interval, saveptr)) return MOSQ_ERR_INVAL;
					if(config->autosave_interval < 0) config->autosave_interval = 0;
				}else if(!strcmp(token, "autosave_on_changes")){
					if(conf__parse_bool(&token, "autosave_on_changes", &config->autosave_on_changes, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "bind_address")){
					if(reload) continue; // Listener not valid for reloading.
					if(conf__parse_string(&token, "default listener bind_address", &config->default_listener.host, saveptr)) return MOSQ_ERR_INVAL;
					if(conf__attempt_resolve(config->default_listener.host, "bind_address", MOSQ_LOG_ERR, "Error")){
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "bridge_attempt_unsubscribe")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_bool(&token, "bridge_attempt_unsubscribe", &cur_bridge->attempt_unsubscribe, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "bridge_cafile")){
#if defined(WITH_BRIDGE) && defined(WITH_TLS)
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
#ifdef REAL_WITH_TLS_PSK
					if(cur_bridge->tls_psk_identity || cur_bridge->tls_psk){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Cannot use both certificate and psk encryption in a single bridge.");
						return MOSQ_ERR_INVAL;
					}
#endif
					if(conf__parse_string(&token, "bridge_cafile", &cur_bridge->tls_cafile, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge and/or TLS support not available.");
#endif
				}else if(!strcmp(token, "bridge_capath")){
#if defined(WITH_BRIDGE) && defined(WITH_TLS)
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
#ifdef REAL_WITH_TLS_PSK
					if(cur_bridge->tls_psk_identity || cur_bridge->tls_psk){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Cannot use both certificate and psk encryption in a single bridge.");
						return MOSQ_ERR_INVAL;
					}
#endif
					if(conf__parse_string(&token, "bridge_capath", &cur_bridge->tls_capath, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge and/or TLS support not available.");
#endif
				}else if(!strcmp(token, "bridge_certfile")){
#if defined(WITH_BRIDGE) && defined(WITH_TLS)
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
#ifdef REAL_WITH_TLS_PSK
					if(cur_bridge->tls_psk_identity || cur_bridge->tls_psk){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Cannot use both certificate and psk encryption in a single bridge.");
						return MOSQ_ERR_INVAL;
					}
#endif
					if(conf__parse_string(&token, "bridge_certfile", &cur_bridge->tls_certfile, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge and/or TLS support not available.");
#endif
				}else if(!strcmp(token, "bridge_identity")){
#if defined(WITH_BRIDGE) && defined(REAL_WITH_TLS_PSK)
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(cur_bridge->tls_cafile || cur_bridge->tls_capath || cur_bridge->tls_certfile || cur_bridge->tls_keyfile){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Cannot use both certificate and identity encryption in a single bridge.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_string(&token, "bridge_identity", &cur_bridge->tls_psk_identity, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge and/or TLS-PSK support not available.");
#endif
				}else if(!strcmp(token, "bridge_insecure")){
#if defined(WITH_BRIDGE) && defined(WITH_TLS)
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_bool(&token, "bridge_insecure", &cur_bridge->tls_insecure, saveptr)) return MOSQ_ERR_INVAL;
					if(cur_bridge->tls_insecure){
						log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge %s using insecure mode.", cur_bridge->name);
					}
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge and/or TLS-PSK support not available.");
#endif
				}else if(!strcmp(token, "bridge_keyfile")){
#if defined(WITH_BRIDGE) && defined(WITH_TLS)
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
#ifdef REAL_WITH_TLS_PSK
					if(cur_bridge->tls_psk_identity || cur_bridge->tls_psk){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Cannot use both certificate and psk encryption in a single bridge.");
						return MOSQ_ERR_INVAL;
					}
#endif
					if(conf__parse_string(&token, "bridge_keyfile", &cur_bridge->tls_keyfile, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge and/or TLS support not available.");
#endif
				}else if(!strcmp(token, "bridge_protocol_version")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					token = strtok_r(NULL, "", &saveptr);
					if(token){
						if(!strcmp(token, "mqttv31")){
							cur_bridge->protocol_version = mosq_p_mqtt31;
						}else if(!strcmp(token, "mqttv311")){
							cur_bridge->protocol_version = mosq_p_mqtt311;
						}else{
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge_protocol_version value (%s).", token);
							return MOSQ_ERR_INVAL;
						}
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty bridge_protocol_version value in configuration.");
						return MOSQ_ERR_INVAL;
					}
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "bridge_psk")){
#if defined(WITH_BRIDGE) && defined(REAL_WITH_TLS_PSK)
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(cur_bridge->tls_cafile || cur_bridge->tls_capath || cur_bridge->tls_certfile || cur_bridge->tls_keyfile){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Cannot use both certificate and psk encryption in a single bridge.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_string(&token, "bridge_psk", &cur_bridge->tls_psk, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge and/or TLS-PSK support not available.");
#endif
				}else if(!strcmp(token, "bridge_tls_version")){
#if defined(WITH_BRIDGE) && defined(WITH_TLS)
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_string(&token, "bridge_tls_version", &cur_bridge->tls_version, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge and/or TLS support not available.");
#endif
				}else if(!strcmp(token, "cafile")){
#if defined(WITH_TLS)
					if(reload) continue; // Listeners not valid for reloading.
					if(cur_listener->psk_hint){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Cannot use both certificate and psk encryption in a single listener.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_string(&token, "cafile", &cur_listener->cafile, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "capath")){
#ifdef WITH_TLS
					if(reload) continue; // Listeners not valid for reloading.
					if(conf__parse_string(&token, "capath", &cur_listener->capath, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "certfile")){
#ifdef WITH_TLS
					if(reload) continue; // Listeners not valid for reloading.
					if(cur_listener->psk_hint){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Cannot use both certificate and psk encryption in a single listener.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_string(&token, "certfile", &cur_listener->certfile, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "ciphers")){
#ifdef WITH_TLS
					if(reload) continue; // Listeners not valid for reloading.
					if(conf__parse_string(&token, "ciphers", &cur_listener->ciphers, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "clientid") || !strcmp(token, "remote_clientid")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_string(&token, "bridge remote clientid", &cur_bridge->remote_clientid, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "cleansession")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_bool(&token, "cleansession", &cur_bridge->clean_session, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "clientid_prefixes")){
					if(reload){
						mosquitto__free(config->clientid_prefixes);
						config->clientid_prefixes = NULL;
					}
					if(conf__parse_string(&token, "clientid_prefixes", &config->clientid_prefixes, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "connection")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						config->bridge_count++;
						config->bridges = mosquitto__realloc(config->bridges, config->bridge_count*sizeof(struct mosquitto__bridge));
						if(!config->bridges){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
						cur_bridge = &(config->bridges[config->bridge_count-1]);
						memset(cur_bridge, 0, sizeof(struct mosquitto__bridge));
						cur_bridge->name = mosquitto__strdup(token);
						if(!cur_bridge->name){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
						cur_bridge->keepalive = 60;
						cur_bridge->notifications = true;
						cur_bridge->start_type = bst_automatic;
						cur_bridge->idle_timeout = 60;
						cur_bridge->restart_timeout = 30;
						cur_bridge->threshold = 10;
						cur_bridge->try_private = true;
						cur_bridge->attempt_unsubscribe = true;
						cur_bridge->protocol_version = mosq_p_mqtt311;
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty connection value in configuration.");
						return MOSQ_ERR_INVAL;
					}
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "connection_messages")){
					if(conf__parse_bool(&token, token, &config->connection_messages, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "crlfile")){
#ifdef WITH_TLS
					if(reload) continue; // Listeners not valid for reloading.
					if(conf__parse_string(&token, "crlfile", &cur_listener->crlfile, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "http_dir")){
#ifdef WITH_WEBSOCKETS
					if(reload) continue; // Listeners not valid for reloading.
					if(conf__parse_string(&token, "http_dir", &cur_listener->http_dir, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Websockets support not available.");
#endif
				}else if(!strcmp(token, "idle_timeout")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_int(&token, "idle_timeout", &cur_bridge->idle_timeout, saveptr)) return MOSQ_ERR_INVAL;
					if(cur_bridge->idle_timeout < 1){
						log__printf(NULL, MOSQ_LOG_NOTICE, "idle_timeout interval too low, using 1 second.");
						cur_bridge->idle_timeout = 1;
					}
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "include_dir")){
					if(level == 0){
						/* Only process include_dir from the main config file. */
						token = strtok_r(NULL, "", &saveptr);
						if(!token){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty include_dir value in configuration.");
							return 1;
						}
#ifdef WIN32
						snprintf(dirpath, MAX_PATH, "%s\\*.conf", token);
						fh = FindFirstFile(dirpath, &find_data);
						if(fh == INVALID_HANDLE_VALUE){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open include_dir '%s'.", token);
							return 1;
						}

						do{
							len = strlen(token)+1+strlen(find_data.cFileName)+1;
							conf_file = mosquitto__malloc(len+1);
							if(!conf_file){
								FindClose(fh);
								return MOSQ_ERR_NOMEM;
							}
							snprintf(conf_file, len, "%s\\%s", token, find_data.cFileName);
							conf_file[len] = '\0';
								
							rc = config__read_file(config, reload, conf_file, cr, level+1, &lineno_ext);
							if(rc){
								FindClose(fh);
								log__printf(NULL, MOSQ_LOG_ERR, "Error found at %s:%d.", conf_file, lineno_ext);
								mosquitto__free(conf_file);
								return rc;
							}
							mosquitto__free(conf_file);
						}while(FindNextFile(fh, &find_data));

						FindClose(fh);
#else
						dh = opendir(token);
						if(!dh){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open include_dir '%s'.", token);
							return 1;
						}
						while((de = readdir(dh)) != NULL){
							if(strlen(de->d_name) > 5){
								if(!strcmp(&de->d_name[strlen(de->d_name)-5], ".conf")){
									len = strlen(token)+1+strlen(de->d_name)+1;
									conf_file = mosquitto__malloc(len+1);
									if(!conf_file){
										closedir(dh);
										return MOSQ_ERR_NOMEM;
									}
									snprintf(conf_file, len, "%s/%s", token, de->d_name);
									conf_file[len] = '\0';
									
									rc = config__read_file(config, reload, conf_file, cr, level+1, &lineno_ext);
									if(rc){
										closedir(dh);
										log__printf(NULL, MOSQ_LOG_ERR, "Error found at %s:%d.", conf_file, lineno_ext);
										mosquitto__free(conf_file);
										return rc;
									}
									mosquitto__free(conf_file);
								}
							}
						}
						closedir(dh);
#endif
					}
				}else if(!strcmp(token, "keepalive_interval")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_int(&token, "keepalive_interval", &cur_bridge->keepalive, saveptr)) return MOSQ_ERR_INVAL;
					if(cur_bridge->keepalive < 5){
						log__printf(NULL, MOSQ_LOG_NOTICE, "keepalive interval too low, using 5 seconds.");
						cur_bridge->keepalive = 5;
					}
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "keyfile")){
#ifdef WITH_TLS
					if(reload) continue; // Listeners not valid for reloading.
					if(conf__parse_string(&token, "keyfile", &cur_listener->keyfile, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "listener")){
					if(reload) continue; // Listeners not valid for reloading.
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						config->listener_count++;
						config->listeners = mosquitto__realloc(config->listeners, sizeof(struct mosquitto__listener)*config->listener_count);
						if(!config->listeners){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
						tmp_int = atoi(token);
						if(tmp_int < 1 || tmp_int > 65535){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid port value (%d).", tmp_int);
							return MOSQ_ERR_INVAL;
						}
						cur_listener = &config->listeners[config->listener_count-1];
						memset(cur_listener, 0, sizeof(struct mosquitto__listener));
						cur_listener->protocol = mp_mqtt;
						cur_listener->port = tmp_int;
						token = strtok_r(NULL, "", &saveptr);
						if(token){
							cur_listener->host = mosquitto__strdup(token);
						}else{
							cur_listener->host = NULL;
						}
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty listener value in configuration.");
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "local_clientid")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_string(&token, "bridge local clientd", &cur_bridge->local_clientid, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "local_password")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_string(&token, "bridge local_password", &cur_bridge->local_password, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "local_username")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_string(&token, "bridge local_username", &cur_bridge->local_username, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "log_dest")){
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						cr->log_dest_set = 1;
						if(!strcmp(token, "none")){
							cr->log_dest = MQTT3_LOG_NONE;
						}else if(!strcmp(token, "syslog")){
							cr->log_dest |= MQTT3_LOG_SYSLOG;
						}else if(!strcmp(token, "stdout")){
							cr->log_dest |= MQTT3_LOG_STDOUT;
						}else if(!strcmp(token, "stderr")){
							cr->log_dest |= MQTT3_LOG_STDERR;
						}else if(!strcmp(token, "topic")){
							cr->log_dest |= MQTT3_LOG_TOPIC;
						}else if(!strcmp(token, "file")){
							cr->log_dest |= MQTT3_LOG_FILE;
							if(config->log_fptr || config->log_file){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Duplicate \"log_dest file\" value.");
								return MOSQ_ERR_INVAL;
							}
							/* Get remaining string. */
							token = &token[strlen(token)+1];
							while(token[0] == ' ' || token[0] == '\t'){
								token++;
							}
							if(token[0]){
								config->log_file = mosquitto__strdup(token);
								if(!config->log_file){
									log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
									return MOSQ_ERR_NOMEM;
								}
							}else{
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty \"log_dest file\" value in configuration.");
								return MOSQ_ERR_INVAL;
							}
						}else{
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid log_dest value (%s).", token);
							return MOSQ_ERR_INVAL;
						}
#if defined(WIN32) || defined(__CYGWIN__)
						if(service_handle){
							if(cr->log_dest == MQTT3_LOG_STDOUT || cr->log_dest == MQTT3_LOG_STDERR){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Cannot log to stdout/stderr when running as a Windows service.");
								return MOSQ_ERR_INVAL;
							}
						}
#endif
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty log_dest value in configuration.");
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "log_facility")){
#if defined(WIN32) || defined(__CYGWIN__)
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: log_facility not supported on Windows.");
#else
					if(conf__parse_int(&token, "log_facility", &tmp_int, saveptr)) return MOSQ_ERR_INVAL;
					switch(tmp_int){
						case 0:
							config->log_facility = LOG_LOCAL0;
							break;
						case 1:
							config->log_facility = LOG_LOCAL1;
							break;
						case 2:
							config->log_facility = LOG_LOCAL2;
							break;
						case 3:
							config->log_facility = LOG_LOCAL3;
							break;
						case 4:
							config->log_facility = LOG_LOCAL4;
							break;
						case 5:
							config->log_facility = LOG_LOCAL5;
							break;
						case 6:
							config->log_facility = LOG_LOCAL6;
							break;
						case 7:
							config->log_facility = LOG_LOCAL7;
							break;
						default:
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid log_facility value (%d).", tmp_int);
							return MOSQ_ERR_INVAL;
					}
#endif
				}else if(!strcmp(token, "log_timestamp")){
					if(conf__parse_bool(&token, token, &config->log_timestamp, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "log_type")){
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						cr->log_type_set = 1;
						if(!strcmp(token, "none")){
							cr->log_type = MOSQ_LOG_NONE;
						}else if(!strcmp(token, "information")){
							cr->log_type |= MOSQ_LOG_INFO;
						}else if(!strcmp(token, "notice")){
							cr->log_type |= MOSQ_LOG_NOTICE;
						}else if(!strcmp(token, "warning")){
							cr->log_type |= MOSQ_LOG_WARNING;
						}else if(!strcmp(token, "error")){
							cr->log_type |= MOSQ_LOG_ERR;
						}else if(!strcmp(token, "debug")){
							cr->log_type |= MOSQ_LOG_DEBUG;
						}else if(!strcmp(token, "subscribe")){
							cr->log_type |= MOSQ_LOG_SUBSCRIBE;
						}else if(!strcmp(token, "unsubscribe")){
							cr->log_type |= MOSQ_LOG_UNSUBSCRIBE;
#ifdef WITH_WEBSOCKETS
						}else if(!strcmp(token, "websockets")){
							cr->log_type |= MOSQ_LOG_WEBSOCKETS;
#endif
						}else if(!strcmp(token, "all")){
							cr->log_type = INT_MAX;
						}else{
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid log_type value (%s).", token);
							return MOSQ_ERR_INVAL;
						}
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty log_type value in configuration.");
					}
				}else if(!strcmp(token, "max_connections")){
					if(reload) continue; // Listeners not valid for reloading.
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						cur_listener->max_connections = atoi(token);
						if(cur_listener->max_connections < 0) cur_listener->max_connections = -1;
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty max_connections value in configuration.");
					}
				}else if(!strcmp(token, "max_inflight_messages")){
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						cr->max_inflight_messages = atoi(token);
						if(cr->max_inflight_messages < 0) cr->max_inflight_messages = 0;
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty max_inflight_messages value in configuration.");
					}
				}else if(!strcmp(token, "max_queued_messages")){
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						cr->max_queued_messages = atoi(token);
						if(cr->max_queued_messages < 0) cr->max_queued_messages = 0;
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty max_queued_messages value in configuration.");
					}
				}else if(!strcmp(token, "message_size_limit")){
					if(conf__parse_int(&token, "message_size_limit", (int *)&config->message_size_limit, saveptr)) return MOSQ_ERR_INVAL;
					if(config->message_size_limit > MQTT_MAX_PAYLOAD){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid message_size_limit value (%d).", config->message_size_limit);
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "mount_point")){
					if(reload) continue; // Listeners not valid for reloading.
					if(config->listener_count == 0){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: You must use create a listener before using the mount_point option in the configuration file.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_string(&token, "mount_point", &cur_listener->mount_point, saveptr)) return MOSQ_ERR_INVAL;
					if(mosquitto_pub_topic_check(cur_listener->mount_point) != MOSQ_ERR_SUCCESS){
						log__printf(NULL, MOSQ_LOG_ERR,
								"Error: Invalid mount_point '%s'. Does it contain a wildcard character?",
								cur_listener->mount_point);
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "notifications")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_bool(&token, "notifications", &cur_bridge->notifications, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "notification_topic")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_string(&token, "notification_topic", &cur_bridge->notification_topic, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "password") || !strcmp(token, "remote_password")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_string(&token, "bridge remote_password", &cur_bridge->remote_password, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "password_file")){
					if(reload){
						mosquitto__free(config->password_file);
						config->password_file = NULL;
					}
					if(conf__parse_string(&token, "password_file", &config->password_file, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "persistence") || !strcmp(token, "retained_persistence")){
					if(conf__parse_bool(&token, token, &config->persistence, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "persistence_file")){
					if(conf__parse_string(&token, "persistence_file", &config->persistence_file, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "persistence_location")){
					if(conf__parse_string(&token, "persistence_location", &config->persistence_location, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "persistent_client_expiration")){
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						switch(token[strlen(token)-1]){
							case 'h':
								expiration_mult = 3600;
								break;
							case 'd':
								expiration_mult = 86400;
								break;
							case 'w':
								expiration_mult = 86400*7;
								break;
							case 'm':
								expiration_mult = 86400*30;
								break;
							case 'y':
								expiration_mult = 86400*365;
								break;
							default:
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid persistent_client_expiration duration in configuration.");
								return MOSQ_ERR_INVAL;
						}
						token[strlen(token)-1] = '\0';
						config->persistent_client_expiration = atoi(token)*expiration_mult;
						if(config->persistent_client_expiration <= 0){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid persistent_client_expiration duration in configuration.");
							return MOSQ_ERR_INVAL;
						}
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty persistent_client_expiration value in configuration.");
					}
				}else if(!strcmp(token, "pid_file")){
					if(reload) continue; // pid file not valid for reloading.
					if(conf__parse_string(&token, "pid_file", &config->pid_file, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "port")){
					if(reload) continue; // Listener not valid for reloading.
					if(config->default_listener.port){
						log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Default listener port specified multiple times. Only the latest will be used.");
					}
					if(conf__parse_int(&token, "port", &tmp_int, saveptr)) return MOSQ_ERR_INVAL;
					if(tmp_int < 1 || tmp_int > 65535){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid port value (%d).", tmp_int);
						return MOSQ_ERR_INVAL;
					}
					config->default_listener.port = tmp_int;
				}else if(!strcmp(token, "protocol")){
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						if(!strcmp(token, "mqtt")){
							cur_listener->protocol = mp_mqtt;
						/*
						}else if(!strcmp(token, "mqttsn")){
							cur_listener->protocol = mp_mqttsn;
						*/
						}else if(!strcmp(token, "websockets")){
#ifdef WITH_WEBSOCKETS
							cur_listener->protocol = mp_websockets;
							config->have_websockets_listener = true;
#else
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Websockets support not available.");
							return MOSQ_ERR_INVAL;
#endif
						}else{
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid protocol value (%s).", token);
							return MOSQ_ERR_INVAL;
						}
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty protocol value in configuration.");
					}
				}else if(!strcmp(token, "psk_file")){
#ifdef REAL_WITH_TLS_PSK
					if(reload){
						mosquitto__free(config->psk_file);
						config->psk_file = NULL;
					}
					if(conf__parse_string(&token, "psk_file", &config->psk_file, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS/TLS-PSK support not available.");
#endif
				}else if(!strcmp(token, "psk_hint")){
#ifdef REAL_WITH_TLS_PSK
					if(reload) continue; // Listeners not valid for reloading.
					if(conf__parse_string(&token, "psk_hint", &cur_listener->psk_hint, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS/TLS-PSK support not available.");
#endif
				}else if(!strcmp(token, "queue_qos0_messages")){
					if(conf__parse_bool(&token, token, &config->queue_qos0_messages, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "require_certificate")){
#ifdef WITH_TLS
					if(reload) continue; // Listeners not valid for reloading.
					if(conf__parse_bool(&token, "require_certificate", &cur_listener->require_certificate, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "restart_timeout")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_int(&token, "restart_timeout", &cur_bridge->restart_timeout, saveptr)) return MOSQ_ERR_INVAL;
					if(cur_bridge->restart_timeout < 1){
						log__printf(NULL, MOSQ_LOG_NOTICE, "restart_timeout interval too low, using 1 second.");
						cur_bridge->restart_timeout = 1;
					}
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "retry_interval")){
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: The retry_interval option is no longer available.");
				}else if(!strcmp(token, "round_robin")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_bool(&token, "round_robin", &cur_bridge->round_robin, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "start_type")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						if(!strcmp(token, "automatic")){
							cur_bridge->start_type = bst_automatic;
						}else if(!strcmp(token, "lazy")){
							cur_bridge->start_type = bst_lazy;
						}else if(!strcmp(token, "manual")){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Manual start_type not supported.");
							return MOSQ_ERR_INVAL;
						}else if(!strcmp(token, "once")){
							cur_bridge->start_type = bst_once;
						}else{
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid start_type value in configuration (%s).", token);
							return MOSQ_ERR_INVAL;
						}
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty start_type value in configuration.");
						return MOSQ_ERR_INVAL;
					}
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "store_clean_interval")){
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: store_clean_interval is no longer needed.");
				}else if(!strcmp(token, "sys_interval")){
					if(conf__parse_int(&token, "sys_interval", &config->sys_interval, saveptr)) return MOSQ_ERR_INVAL;
					if(config->sys_interval < 0 || config->sys_interval > 65535){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid sys_interval value (%d).", config->sys_interval);
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "threshold")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_int(&token, "threshold", &cur_bridge->threshold, saveptr)) return MOSQ_ERR_INVAL;
					if(cur_bridge->threshold < 1){
						log__printf(NULL, MOSQ_LOG_NOTICE, "threshold too low, using 1 message.");
						cur_bridge->threshold = 1;
					}
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "tls_version")){
#if defined(WITH_TLS)
					if(reload) continue; // Listeners not valid for reloading.
					if(conf__parse_string(&token, "tls_version", &cur_listener->tls_version, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "topic")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						cur_bridge->topic_count++;
						cur_bridge->topics = mosquitto__realloc(cur_bridge->topics, 
								sizeof(struct mosquitto__bridge_topic)*cur_bridge->topic_count);
						if(!cur_bridge->topics){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
						cur_topic = &cur_bridge->topics[cur_bridge->topic_count-1];
						if(!strcmp(token, "\"\"")){
							cur_topic->topic = NULL;
						}else{
							cur_topic->topic = mosquitto__strdup(token);
							if(!cur_topic->topic){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
								return MOSQ_ERR_NOMEM;
							}
						}
						cur_topic->direction = bd_out;
						cur_topic->qos = 0;
						cur_topic->local_prefix = NULL;
						cur_topic->remote_prefix = NULL;
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty topic value in configuration.");
						return MOSQ_ERR_INVAL;
					}
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						if(!strcasecmp(token, "out")){
							cur_topic->direction = bd_out;
						}else if(!strcasecmp(token, "in")){
							cur_topic->direction = bd_in;
						}else if(!strcasecmp(token, "both")){
							cur_topic->direction = bd_both;
						}else{
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge topic direction '%s'.", token);
							return MOSQ_ERR_INVAL;
						}
						token = strtok_r(NULL, " ", &saveptr);
						if(token){
							cur_topic->qos = atoi(token);
							if(cur_topic->qos < 0 || cur_topic->qos > 2){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge QoS level '%s'.", token);
								return MOSQ_ERR_INVAL;
							}

							token = strtok_r(NULL, " ", &saveptr);
							if(token){
								cur_bridge->topic_remapping = true;
								if(!strcmp(token, "\"\"")){
									cur_topic->local_prefix = NULL;
								}else{
									if(mosquitto_pub_topic_check(token) != MOSQ_ERR_SUCCESS){
										log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge topic local prefix '%s'.", token);
										return MOSQ_ERR_INVAL;
									}
									cur_topic->local_prefix = mosquitto__strdup(token);
									if(!cur_topic->local_prefix){
										log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
										return MOSQ_ERR_NOMEM;
									}
								}

								token = strtok_r(NULL, " ", &saveptr);
								if(token){
									if(!strcmp(token, "\"\"")){
										cur_topic->remote_prefix = NULL;
									}else{
										if(mosquitto_pub_topic_check(token) != MOSQ_ERR_SUCCESS){
											log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge topic remote prefix '%s'.", token);
											return MOSQ_ERR_INVAL;
										}
										cur_topic->remote_prefix = mosquitto__strdup(token);
										if(!cur_topic->remote_prefix){
											log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
											return MOSQ_ERR_NOMEM;
										}
									}
								}
							}
						}
					}
					if(cur_topic->topic == NULL && 
							(cur_topic->local_prefix == NULL || cur_topic->remote_prefix == NULL)){

						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge remapping.");
						return MOSQ_ERR_INVAL;
					}
					if(cur_topic->local_prefix){
						if(cur_topic->topic){
							len = strlen(cur_topic->topic) + strlen(cur_topic->local_prefix)+1;
							cur_topic->local_topic = mosquitto__malloc(len+1);
							if(!cur_topic->local_topic){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
								return MOSQ_ERR_NOMEM;
							}
							snprintf(cur_topic->local_topic, len+1, "%s%s", cur_topic->local_prefix, cur_topic->topic);
							cur_topic->local_topic[len] = '\0';
						}else{
							cur_topic->local_topic = mosquitto__strdup(cur_topic->local_prefix);
							if(!cur_topic->local_topic){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
								return MOSQ_ERR_NOMEM;
							}
						}
					}else{
						cur_topic->local_topic = mosquitto__strdup(cur_topic->topic);
						if(!cur_topic->local_topic){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
					}

					if(cur_topic->remote_prefix){
						if(cur_topic->topic){
							len = strlen(cur_topic->topic) + strlen(cur_topic->remote_prefix)+1;
							cur_topic->remote_topic = mosquitto__malloc(len+1);
							if(!cur_topic->remote_topic){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
								return MOSQ_ERR_NOMEM;
							}
							snprintf(cur_topic->remote_topic, len, "%s%s", cur_topic->remote_prefix, cur_topic->topic);
							cur_topic->remote_topic[len] = '\0';
						}else{
							cur_topic->remote_topic = mosquitto__strdup(cur_topic->remote_prefix);
							if(!cur_topic->remote_topic){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
								return MOSQ_ERR_NOMEM;
							}
						}
					}else{
						cur_topic->remote_topic = mosquitto__strdup(cur_topic->topic);
						if(!cur_topic->remote_topic){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
					}
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "try_private")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_bool(&token, "try_private", &cur_bridge->try_private, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "upgrade_outgoing_qos")){
					if(conf__parse_bool(&token, token, &config->upgrade_outgoing_qos, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "use_identity_as_username")){
#ifdef WITH_TLS
					if(reload) continue; // Listeners not valid for reloading.
					if(conf__parse_bool(&token, "use_identity_as_username", &cur_listener->use_identity_as_username, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "use_subject_as_username")){
#ifdef WITH_TLS
					if(reload) continue; // Listeners not valid for reloading.
					if(conf__parse_bool(&token, "use_subject_as_username", &cur_listener->use_subject_as_username, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "user")){
					if(reload) continue; // Drop privileges user not valid for reloading.
					if(conf__parse_string(&token, "user", &config->user, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "use_username_as_clientid")){
					if(reload) continue; // Listeners not valid for reloading.
					if(conf__parse_bool(&token, "use_username_as_clientid", &cur_listener->use_username_as_clientid, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "username") || !strcmp(token, "remote_username")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						if(cur_bridge->remote_username){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Duplicate username value in bridge configuration.");
							return MOSQ_ERR_INVAL;
						}
						cur_bridge->remote_username = mosquitto__strdup(token);
						if(!cur_bridge->remote_username){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty username value in configuration.");
						return MOSQ_ERR_INVAL;
					}
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "websockets_log_level")){
#ifdef WITH_WEBSOCKETS
					if(conf__parse_int(&token, "websockets_log_level", &config->websockets_log_level, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Websockets support not available.");
#endif
				}else if(!strcmp(token, "trace_level")
						|| !strcmp(token, "ffdc_output")
						|| !strcmp(token, "max_log_entries")
						|| !strcmp(token, "trace_output")){
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Unsupported rsmb configuration option \"%s\".", token);
				}else{
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Unknown configuration variable \"%s\".", token);
					return MOSQ_ERR_INVAL;
				}
			}
		}
	}
	return MOSQ_ERR_SUCCESS;
}

int config__read_file(struct mosquitto__config *config, bool reload, const char *file, struct config_recurse *cr, int level, int *lineno)
{
	int rc;
	FILE *fptr = NULL;

	fptr = mosquitto__fopen(file, "rt");
	if(!fptr){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open config file %s\n", file);
		return 1;
	}

	rc = config__read_file_core(config, reload, file, cr, level, lineno, fptr);
	fclose(fptr);

	return rc;
}


static int config__check(struct mosquitto__config *config)
{
	/* Checks that are easy to make after the config has been loaded. */

#ifdef WITH_BRIDGE
	int i, j;
	struct mosquitto__bridge *bridge1, *bridge2;
	char hostname[256];
	int len;

	/* Check for bridge duplicate local_clientid, need to generate missing IDs
	 * first. */
	for(i=0; i<config->bridge_count; i++){
		bridge1 = &config->bridges[i];

		if(!bridge1->remote_clientid){
			if(!gethostname(hostname, 256)){
				len = strlen(hostname) + strlen(bridge1->name) + 2;
				bridge1->remote_clientid = mosquitto__malloc(len);
				if(!bridge1->remote_clientid){
					return MOSQ_ERR_NOMEM;
				}
				snprintf(bridge1->remote_clientid, len, "%s.%s", hostname, bridge1->name);
			}else{
				return 1;
			}
		}

		if(!bridge1->local_clientid){
			len = strlen(bridge1->remote_clientid) + strlen("local.") + 2;
			bridge1->local_clientid = mosquitto__malloc(len);
			if(!bridge1->local_clientid){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				return MOSQ_ERR_NOMEM;
			}
			snprintf(bridge1->local_clientid, len, "local.%s", bridge1->remote_clientid);
		}
	}

	for(i=0; i<config->bridge_count; i++){
		bridge1 = &config->bridges[i];
		for(j=i+1; j<config->bridge_count; j++){
			bridge2 = &config->bridges[j];
			if(!strcmp(bridge1->local_clientid, bridge2->local_clientid)){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Bridge local_clientid "
						"'%s' is not unique. Try changing or setting the "
						"local_clientid value for one of the bridges.",
						bridge1->local_clientid);
				return MOSQ_ERR_INVAL;
			}
		}
	}
#endif
	return MOSQ_ERR_SUCCESS;
}


static int conf__parse_bool(char **token, const char *name, bool *value, char *saveptr)
{
	*token = strtok_r(NULL, " ", &saveptr);
	if(*token){
		if(!strcmp(*token, "false") || !strcmp(*token, "0")){
			*value = false;
		}else if(!strcmp(*token, "true") || !strcmp(*token, "1")){
			*value = true;
		}else{
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid %s value (%s).", name, *token);
		}
	}else{
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty %s value in configuration.", name);
		return MOSQ_ERR_INVAL;
	}
	
	return MOSQ_ERR_SUCCESS;
}

static int conf__parse_int(char **token, const char *name, int *value, char *saveptr)
{
	*token = strtok_r(NULL, " ", &saveptr);
	if(*token){
		*value = atoi(*token);
	}else{
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty %s value in configuration.", name);
		return MOSQ_ERR_INVAL;
	}

	return MOSQ_ERR_SUCCESS;
}

static int conf__parse_string(char **token, const char *name, char **value, char *saveptr)
{
	*token = strtok_r(NULL, "", &saveptr);
	if(*token){
		if(*value){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Duplicate %s value in configuration.", name);
			return MOSQ_ERR_INVAL;
		}
		/* Deal with multiple spaces at the beginning of the string. */
		while((*token)[0] == ' ' || (*token)[0] == '\t'){
			(*token)++;
		}
		*value = mosquitto__strdup(*token);
		if(!*value){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
	}else{
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty %s value in configuration.", name);
		return MOSQ_ERR_INVAL;
	}
	return MOSQ_ERR_SUCCESS;
}
