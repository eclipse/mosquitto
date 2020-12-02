/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef WIN32
#else
#  include <dirent.h>
#  include <strings.h>
#endif

#ifndef WIN32
#  include <netdb.h>
#  include <sys/socket.h>
#else
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif

#if !defined(WIN32) && !defined(__CYGWIN__)
#  include <syslog.h>
#endif

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "misc_mosq.h"
#include "tls_mosq.h"
#include "util_mosq.h"
#include "mqtt_protocol.h"

struct config_recurse {
	unsigned int log_dest;
	int log_dest_set;
	unsigned int log_type;
	int log_type_set;
};

#if defined(WIN32) || defined(__CYGWIN__)
#include <windows.h>
extern SERVICE_STATUS_HANDLE service_handle;
#endif

static struct mosquitto__security_options *cur_security_options = NULL;

static int conf__parse_bool(char **token, const char *name, bool *value, char *saveptr);
static int conf__parse_int(char **token, const char *name, int *value, char *saveptr);
static int conf__parse_ssize_t(char **token, const char *name, ssize_t *value, char *saveptr);
static int conf__parse_string(char **token, const char *name, char **value, char *saveptr);
static int config__read_file(struct mosquitto__config *config, bool reload, const char *file, struct config_recurse *config_tmp, int level, int *lineno);
static int config__check(struct mosquitto__config *config);
static void config__cleanup_plugins(struct mosquitto__config *config);

static void conf__set_cur_security_options(struct mosquitto__config *config, struct mosquitto__listener *cur_listener, struct mosquitto__security_options **security_options)
{
	if(config->per_listener_settings){
		(*security_options) = &cur_listener->security_options;
	}else{
		(*security_options) = &config->security_options;
	}
}

static int conf__attempt_resolve(const char *host, const char *text, unsigned int log, const char *msg)
{
	struct addrinfo gai_hints;
	struct addrinfo *gai_res;
	int rc;

	memset(&gai_hints, 0, sizeof(struct addrinfo));
	gai_hints.ai_family = AF_UNSPEC;
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
	/* Set defaults */
	for(i=0; i<config->listener_count; i++){
		mosquitto__free(config->listeners[i].security_options.acl_file);
		config->listeners[i].security_options.acl_file = NULL;

		mosquitto__free(config->listeners[i].security_options.password_file);
		config->listeners[i].security_options.password_file = NULL;

		mosquitto__free(config->listeners[i].security_options.psk_file);
		config->listeners[i].security_options.psk_file = NULL;

		config->listeners[i].security_options.allow_anonymous = -1;
		config->listeners[i].security_options.allow_zero_length_clientid = true;
		config->listeners[i].security_options.auto_id_prefix = NULL;
		config->listeners[i].security_options.auto_id_prefix_len = 0;
	}

	config->local_only = true;
	config->allow_duplicate_messages = false;

	mosquitto__free(config->security_options.acl_file);
	config->security_options.acl_file = NULL;

	config->security_options.allow_anonymous = -1;
	config->security_options.allow_zero_length_clientid = true;
	config->security_options.auto_id_prefix = NULL;
	config->security_options.auto_id_prefix_len = 0;

	mosquitto__free(config->security_options.password_file);
	config->security_options.password_file = NULL;

	mosquitto__free(config->security_options.psk_file);
	config->security_options.psk_file = NULL;

	config->autosave_interval = 1800;
	config->autosave_on_changes = false;
	mosquitto__free(config->clientid_prefixes);
	config->connection_messages = true;
	config->clientid_prefixes = NULL;
	config->per_listener_settings = false;
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
	config->log_dest = MQTT3_LOG_STDERR | MQTT3_LOG_DLT;
	if(db.verbose){
		config->log_type = UINT_MAX;
	}else{
		config->log_type = MOSQ_LOG_ERR | MOSQ_LOG_WARNING | MOSQ_LOG_NOTICE | MOSQ_LOG_INFO;
	}
#endif
	config->log_timestamp = true;
	mosquitto__free(config->log_timestamp_format);
	config->log_timestamp_format = NULL;
	config->max_keepalive = 65535;
	config->max_packet_size = 0;
	config->max_inflight_messages = 20;
	config->max_queued_messages = 1000;
	config->max_inflight_bytes = 0;
	config->max_queued_bytes = 0;
	config->persistence = false;
	mosquitto__free(config->persistence_location);
	config->persistence_location = NULL;
	mosquitto__free(config->persistence_file);
	config->persistence_file = NULL;
	config->persistent_client_expiration = 0;
	config->queue_qos0_messages = false;
	config->retain_available = true;
	config->set_tcp_nodelay = false;
	config->sys_interval = 10;
	config->upgrade_outgoing_qos = false;

	config__cleanup_plugins(config);
}


static void config__cleanup_plugins(struct mosquitto__config *config)
{
	int i, j;
	struct mosquitto__auth_plugin_config *plug;

	if(config->security_options.auth_plugin_configs){
		for(i=0; i<config->security_options.auth_plugin_config_count; i++){
			plug = &config->security_options.auth_plugin_configs[i];
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
		mosquitto__free(config->security_options.auth_plugin_configs);
		config->security_options.auth_plugin_configs = NULL;
	}
}


void config__init(struct mosquitto__config *config)
{
	memset(config, 0, sizeof(struct mosquitto__config));
	config__init_reload(config);

	config->daemon = false;
	memset(&config->default_listener, 0, sizeof(struct mosquitto__listener));
	listener__set_defaults(&config->default_listener);
}

void config__cleanup(struct mosquitto__config *config)
{
	int i;
#ifdef WITH_BRIDGE
	int j;
#endif

	mosquitto__free(config->clientid_prefixes);
	mosquitto__free(config->persistence_location);
	mosquitto__free(config->persistence_file);
	mosquitto__free(config->persistence_filepath);
	mosquitto__free(config->security_options.auto_id_prefix);
	mosquitto__free(config->security_options.acl_file);
	mosquitto__free(config->security_options.password_file);
	mosquitto__free(config->security_options.psk_file);
	mosquitto__free(config->pid_file);
	mosquitto__free(config->user);
	mosquitto__free(config->log_timestamp_format);
	if(config->listeners){
		for(i=0; i<config->listener_count; i++){
			mosquitto__free(config->listeners[i].host);
			mosquitto__free(config->listeners[i].bind_interface);
			mosquitto__free(config->listeners[i].mount_point);
			mosquitto__free(config->listeners[i].socks);
			mosquitto__free(config->listeners[i].security_options.auto_id_prefix);
			mosquitto__free(config->listeners[i].security_options.acl_file);
			mosquitto__free(config->listeners[i].security_options.password_file);
			mosquitto__free(config->listeners[i].security_options.psk_file);
#ifdef WITH_TLS
			mosquitto__free(config->listeners[i].cafile);
			mosquitto__free(config->listeners[i].capath);
			mosquitto__free(config->listeners[i].certfile);
			mosquitto__free(config->listeners[i].keyfile);
			mosquitto__free(config->listeners[i].ciphers);
			mosquitto__free(config->listeners[i].ciphers_tls13);
			mosquitto__free(config->listeners[i].psk_hint);
			mosquitto__free(config->listeners[i].crlfile);
			mosquitto__free(config->listeners[i].dhparamfile);
			mosquitto__free(config->listeners[i].tls_version);
			mosquitto__free(config->listeners[i].tls_engine);
			mosquitto__free(config->listeners[i].tls_engine_kpass_sha1);
#ifdef WITH_WEBSOCKETS
			if(!config->listeners[i].ws_context) /* libwebsockets frees its own SSL_CTX */
#endif
			{
				SSL_CTX_free(config->listeners[i].ssl_ctx);
			}
#endif
#ifdef WITH_WEBSOCKETS
			mosquitto__free(config->listeners[i].http_dir);
#endif
#ifdef WITH_UNIX_SOCKETS
			mosquitto__free(config->listeners[i].unix_socket_path);
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
			mosquitto__free(config->bridges[i].tls_alpn);
#ifdef FINAL_WITH_TLS_PSK
			mosquitto__free(config->bridges[i].tls_psk_identity);
			mosquitto__free(config->bridges[i].tls_psk);
#endif
#endif
		}
		mosquitto__free(config->bridges);
	}
#endif
	config__cleanup_plugins(config);

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
	printf("mosquitto version %s\n\n", VERSION);
	printf("mosquitto is an MQTT v5.0/v3.1.1/v3.1 broker.\n\n");
	printf("Usage: mosquitto [-c config_file] [-d] [-h] [-p port]\n\n");
	printf(" -c : specify the broker config file.\n");
	printf(" -d : put the broker into the background after starting.\n");
	printf(" -h : display this help.\n");
	printf(" -p : start the broker listening on the specified port.\n");
	printf("      Not recommended in conjunction with the -c option.\n");
	printf(" -v : verbose mode - enable all logging types. This overrides\n");
	printf("      any logging options given in the config file.\n");
	printf("\nSee https://mosquitto.org/ for more information.\n\n");
}

int config__parse_args(struct mosquitto__config *config, int argc, char *argv[])
{
	int i;
	int port_tmp;

	for(i=1; i<argc; i++){
		if(!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config-file")){
			if(i<argc-1){
				db.config_file = argv[i+1];

				if(config__read(config, false)){
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
				if(port_tmp<1 || port_tmp>UINT16_MAX){
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid port specified (%d).", port_tmp);
					return MOSQ_ERR_INVAL;
				}else{
					if(config->cmd_port_count == CMD_PORT_LIMIT){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Only %d ports can be specified on the command line.", CMD_PORT_LIMIT);
						return MOSQ_ERR_INVAL;
					}
					config->cmd_port[config->cmd_port_count] = (uint16_t)port_tmp;
					config->cmd_port_count++;
				}
			}else{
				log__printf(NULL, MOSQ_LOG_ERR, "Error: -p argument given, but no port specified.");
				return MOSQ_ERR_INVAL;
			}
			i++;
		}else if(!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")){
			db.verbose = true;
		}else{
			fprintf(stderr, "Error: Unknown option '%s'.\n",argv[i]);
			print_usage();
			return MOSQ_ERR_INVAL;
		}
	}

	if(config->default_listener.bind_interface
#ifdef WITH_TLS
			|| config->default_listener.cafile
			|| config->default_listener.capath
			|| config->default_listener.certfile
			|| config->default_listener.keyfile
			|| config->default_listener.tls_engine
			|| config->default_listener.tls_keyform != mosq_k_pem
			|| config->default_listener.tls_engine_kpass_sha1
			|| config->default_listener.ciphers
			|| config->default_listener.ciphers_tls13
			|| config->default_listener.dhparamfile
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
			|| config->default_listener.max_qos != 2
			|| config->default_listener.mount_point
			|| config->default_listener.protocol != mp_mqtt
			|| config->default_listener.socket_domain
			|| config->default_listener.security_options.password_file
			|| config->default_listener.security_options.psk_file
			|| config->default_listener.security_options.auth_plugin_config_count
			|| config->default_listener.security_options.allow_zero_length_clientid != true
			){

		config->listener_count++;
		config->listeners = mosquitto__realloc(config->listeners, sizeof(struct mosquitto__listener)*(size_t)config->listener_count);
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
		config->listeners[config->listener_count-1].bind_interface = config->default_listener.bind_interface;
		config->listeners[config->listener_count-1].max_connections = config->default_listener.max_connections;
		config->listeners[config->listener_count-1].protocol = config->default_listener.protocol;
		config->listeners[config->listener_count-1].socket_domain = config->default_listener.socket_domain;
		config->listeners[config->listener_count-1].client_count = 0;
		config->listeners[config->listener_count-1].socks = NULL;
		config->listeners[config->listener_count-1].sock_count = 0;
		config->listeners[config->listener_count-1].client_count = 0;
		config->listeners[config->listener_count-1].use_username_as_clientid = config->default_listener.use_username_as_clientid;
		config->listeners[config->listener_count-1].max_qos = config->default_listener.max_qos;
		config->listeners[config->listener_count-1].max_topic_alias = config->default_listener.max_topic_alias;
#ifdef WITH_TLS
		config->listeners[config->listener_count-1].tls_version = config->default_listener.tls_version;
		config->listeners[config->listener_count-1].tls_engine = config->default_listener.tls_engine;
		config->listeners[config->listener_count-1].tls_keyform = config->default_listener.tls_keyform;
		config->listeners[config->listener_count-1].tls_engine_kpass_sha1 = config->default_listener.tls_engine_kpass_sha1;
		config->listeners[config->listener_count-1].cafile = config->default_listener.cafile;
		config->listeners[config->listener_count-1].capath = config->default_listener.capath;
		config->listeners[config->listener_count-1].certfile = config->default_listener.certfile;
		config->listeners[config->listener_count-1].keyfile = config->default_listener.keyfile;
		config->listeners[config->listener_count-1].ciphers = config->default_listener.ciphers;
		config->listeners[config->listener_count-1].ciphers_tls13 = config->default_listener.ciphers_tls13;
		config->listeners[config->listener_count-1].dhparamfile = config->default_listener.dhparamfile;
		config->listeners[config->listener_count-1].psk_hint = config->default_listener.psk_hint;
		config->listeners[config->listener_count-1].require_certificate = config->default_listener.require_certificate;
		config->listeners[config->listener_count-1].ssl_ctx = NULL;
		config->listeners[config->listener_count-1].crlfile = config->default_listener.crlfile;
		config->listeners[config->listener_count-1].use_identity_as_username = config->default_listener.use_identity_as_username;
		config->listeners[config->listener_count-1].use_subject_as_username = config->default_listener.use_subject_as_username;
#endif
		config->listeners[config->listener_count-1].security_options.acl_file = config->default_listener.security_options.acl_file;
		config->listeners[config->listener_count-1].security_options.password_file = config->default_listener.security_options.password_file;
		config->listeners[config->listener_count-1].security_options.psk_file = config->default_listener.security_options.psk_file;
		config->listeners[config->listener_count-1].security_options.auth_plugin_configs = config->default_listener.security_options.auth_plugin_configs;
		config->listeners[config->listener_count-1].security_options.auth_plugin_config_count = config->default_listener.security_options.auth_plugin_config_count;
		config->listeners[config->listener_count-1].security_options.allow_anonymous = config->default_listener.security_options.allow_anonymous;
		config->listeners[config->listener_count-1].security_options.allow_zero_length_clientid = config->default_listener.security_options.allow_zero_length_clientid;
	}

	/* Default to drop to mosquitto user if we are privileged and no user specified. */
	if(!config->user){
		config->user = mosquitto__strdup("mosquitto");
		if(config->user == NULL){
			return MOSQ_ERR_NOMEM;
		}
	}
	if(db.verbose){
		config->log_type = UINT_MAX;
	}
	return config__check(config);
}

void config__copy(struct mosquitto__config *src, struct mosquitto__config *dest)
{
	mosquitto__free(dest->security_options.acl_file);
	dest->security_options.acl_file = src->security_options.acl_file;

	dest->security_options.allow_anonymous = src->security_options.allow_anonymous;
	dest->security_options.allow_zero_length_clientid = src->security_options.allow_zero_length_clientid;

	mosquitto__free(dest->security_options.auto_id_prefix);
	dest->security_options.auto_id_prefix = src->security_options.auto_id_prefix;
	dest->security_options.auto_id_prefix_len = src->security_options.auto_id_prefix_len;

	mosquitto__free(dest->security_options.password_file);
	dest->security_options.password_file = src->security_options.password_file;

	mosquitto__free(dest->security_options.psk_file);
	dest->security_options.psk_file = src->security_options.psk_file;


	dest->allow_duplicate_messages = src->allow_duplicate_messages;


	dest->autosave_interval = src->autosave_interval;
	dest->autosave_on_changes = src->autosave_on_changes;

	mosquitto__free(dest->clientid_prefixes);
	dest->clientid_prefixes = src->clientid_prefixes;

	dest->connection_messages = src->connection_messages;
	dest->log_dest = src->log_dest;
	dest->log_facility = src->log_facility;
	dest->log_type = src->log_type;
	dest->log_timestamp = src->log_timestamp;

	mosquitto__free(dest->log_timestamp_format);
	dest->log_timestamp_format = src->log_timestamp_format;

	mosquitto__free(dest->log_file);
	dest->log_file = src->log_file;

	dest->message_size_limit = src->message_size_limit;

	dest->persistence = src->persistence;

	mosquitto__free(dest->persistence_location);
	dest->persistence_location = src->persistence_location;

	mosquitto__free(dest->persistence_file);
	dest->persistence_file = src->persistence_file;

	mosquitto__free(dest->persistence_filepath);
	dest->persistence_filepath = src->persistence_filepath;

	dest->persistent_client_expiration = src->persistent_client_expiration;


	dest->queue_qos0_messages = src->queue_qos0_messages;
	dest->sys_interval = src->sys_interval;
	dest->upgrade_outgoing_qos = src->upgrade_outgoing_qos;

#ifdef WITH_WEBSOCKETS
	dest->websockets_log_level = src->websockets_log_level;
#endif
}


int config__read(struct mosquitto__config *config, bool reload)
{
	int rc = MOSQ_ERR_SUCCESS;
	struct config_recurse cr;
	int lineno = 0;
#ifdef WITH_PERSISTENCE
	size_t len;
#endif
	struct mosquitto__config config_reload;
	int i;

	if(reload){
		memset(&config_reload, 0, sizeof(struct mosquitto__config));
	}

	cr.log_dest = MQTT3_LOG_NONE;
	cr.log_dest_set = 0;
	cr.log_type = MOSQ_LOG_NONE;
	cr.log_type_set = 0;

	if(!db.config_file) return 0;

	if(reload){
		/* Re-initialise appropriate config vars to default for reload. */
		config__init_reload(&config_reload);
		config_reload.listeners = config->listeners;
		config_reload.listener_count = config->listener_count;
		cur_security_options = NULL;
		rc = config__read_file(&config_reload, reload, db.config_file, &cr, 0, &lineno);
	}else{
		rc = config__read_file(config, reload, db.config_file, &cr, 0, &lineno);
	}
	if(rc){
		if(lineno > 0){
			log__printf(NULL, MOSQ_LOG_ERR, "Error found at %s:%d.", db.config_file, lineno);
		}
		return rc;
	}

	if(reload){
		config__copy(&config_reload, config);
	}

	/* If auth/access options are set and allow_anonymous not explicitly set, disallow anon. */
	if(config->local_only == true){
		config->security_options.allow_anonymous = true;
	}else{
		if(config->per_listener_settings){
			for(i=0; i<config->listener_count; i++){
				/* Default option if no security options set */
				if(config->listeners[i].security_options.allow_anonymous == -1){
					config->listeners[i].security_options.allow_anonymous = false;
				}
			}
		}else{
			if(config->security_options.allow_anonymous == -1){
				config->security_options.allow_anonymous = false;
			}
		}
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
		config->user = mosquitto__strdup("mosquitto");
	}

#ifdef WITH_BRIDGE
	for(i=0; i<config->bridge_count; i++){
		if(!config->bridges[i].name){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration: bridge name not defined.");
			return MOSQ_ERR_INVAL;
		}
		if(config->bridges[i].addresses  == 0){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration: no remote addresses defined.");
			return MOSQ_ERR_INVAL;
		}
		if(config->bridges[i].topic_count == 0){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration: no topics defined.");
			return MOSQ_ERR_INVAL;
		}
#ifdef FINAL_WITH_TLS_PSK
		if(config->bridges[i].tls_psk && !config->bridges[i].tls_psk_identity){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration: missing bridge_identity.");
			return MOSQ_ERR_INVAL;
		}
		if(config->bridges[i].tls_psk_identity && !config->bridges[i].tls_psk){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration: missing bridge_psk.");
			return MOSQ_ERR_INVAL;
		}
#endif
	}
#endif

	if(cr.log_dest_set){
		config->log_dest = cr.log_dest;
	}
	if(db.verbose){
		config->log_type = UINT_MAX;
	}else if(cr.log_type_set){
		config->log_type = cr.log_type;
	}
	return MOSQ_ERR_SUCCESS;
}


int config__read_file_core(struct mosquitto__config *config, bool reload, struct config_recurse *cr, int level, int *lineno, FILE *fptr, char **buf, int *buflen)
{
	int rc;
	char *token;
	int tmp_int;
	char *saveptr = NULL;
#ifdef WITH_BRIDGE
	char *tmp_char;
	struct mosquitto__bridge *cur_bridge = NULL;
#endif
	struct mosquitto__auth_plugin_config *cur_auth_plugin_config = NULL;

	time_t expiration_mult;
	char *key;
	struct mosquitto__listener *cur_listener = &config->default_listener;
	int i;
	int lineno_ext = 0;
	size_t prefix_len;
	char **files;
	int file_count;
#ifdef WITH_TLS
	char *kpass_sha = NULL, *kpass_sha_bin = NULL;
	char *keyform ;
#endif

	*lineno = 0;

	while(fgets_extending(buf, buflen, fptr)){
		(*lineno)++;
		if((*buf)[0] != '#' && (*buf)[0] != 10 && (*buf)[0] != 13){
			while((*buf)[strlen((*buf))-1] == 10 || (*buf)[strlen((*buf))-1] == 13){
				(*buf)[strlen((*buf))-1] = 0;
			}
			token = strtok_r((*buf), " ", &saveptr);
			if(token){
				if(!strcmp(token, "acl_file")){
					conf__set_cur_security_options(config, cur_listener, &cur_security_options);
					if(reload){
						mosquitto__free(cur_security_options->acl_file);
						cur_security_options->acl_file = NULL;
					}
					if(conf__parse_string(&token, "acl_file", &cur_security_options->acl_file, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "address") || !strcmp(token, "addresses")){
#ifdef WITH_BRIDGE
					if(reload) continue; /* FIXME */
					if(!cur_bridge || cur_bridge->addresses){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					while((token = strtok_r(NULL, " ", &saveptr))){
						if (token[0] == '#'){
							break;
						}
						cur_bridge->address_count++;
						cur_bridge->addresses = mosquitto__realloc(cur_bridge->addresses, sizeof(struct bridge_address)*(size_t)cur_bridge->address_count);
						if(!cur_bridge->addresses){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
						cur_bridge->addresses[cur_bridge->address_count-1].address = token;
					}
					for(i=0; i<cur_bridge->address_count; i++){
						/* cur_bridge->addresses[i].address is now
						 * "address[:port]". If address is an IPv6 address,
						 * then port is required. We must check for the :
						 * backwards. */
						tmp_char = strrchr(cur_bridge->addresses[i].address, ':');
						if(tmp_char){
							/* Remove ':', so cur_bridge->addresses[i].address
							 * now just looks like the address. */
							tmp_char[0] = '\0';

							/* The remainder of the string */
							tmp_int = atoi(&tmp_char[1]);
							if(tmp_int < 1 || tmp_int > UINT16_MAX){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid port value (%d).", tmp_int);
								return MOSQ_ERR_INVAL;
							}
							cur_bridge->addresses[i].port = (uint16_t)tmp_int;
						}else{
							cur_bridge->addresses[i].port = 1883;
						}
						/* This looks a bit weird, but isn't. Before this
						 * call, cur_bridge->addresses[i].address points
						 * to the tokenised part of the line, it will be
						 * reused in a future parse of a config line so we
						 * must duplicate it. */
						cur_bridge->addresses[i].address = mosquitto__strdup(cur_bridge->addresses[i].address);
						conf__attempt_resolve(cur_bridge->addresses[i].address, "bridge address", MOSQ_LOG_WARNING, "Warning");
					}
					if(cur_bridge->address_count == 0){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty address value in configuration.");
						return MOSQ_ERR_INVAL;
					}
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "allow_anonymous")){
					conf__set_cur_security_options(config, cur_listener, &cur_security_options);
					if(conf__parse_bool(&token, "allow_anonymous", (bool *)&cur_security_options->allow_anonymous, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "allow_duplicate_messages")){
					log__printf(NULL, MOSQ_LOG_NOTICE, "The 'allow_duplicate_messages' option is now deprecated and will be removed in a future version. The behaviour will default to true.");
					if(conf__parse_bool(&token, "allow_duplicate_messages", &config->allow_duplicate_messages, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "allow_zero_length_clientid")){
					conf__set_cur_security_options(config, cur_listener, &cur_security_options);
					if(conf__parse_bool(&token, "allow_zero_length_clientid", &cur_security_options->allow_zero_length_clientid, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strncmp(token, "auth_opt_", strlen("auth_opt_")) || !strncmp(token, "plugin_opt_", strlen("plugin_opt_"))){
					if(reload) continue; /* Auth plugin not currently valid for reloading. */
					if(!cur_auth_plugin_config){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: An auth_opt_ option exists in the config file without an auth_plugin.");
						return MOSQ_ERR_INVAL;
					}
					if(!strncmp(token, "auth_opt_", strlen("auth_opt_"))){
						prefix_len = strlen("auth_opt_");
					}else{
						prefix_len = strlen("plugin_opt_");
					}
					if(strlen(token) < prefix_len + 3){
						/* auth_opt_ == 9, + one digit key == 10, + one space == 11, + one value == 12 */
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid auth_opt_ config option.");
						return MOSQ_ERR_INVAL;
					}
					key = mosquitto__strdup(&token[prefix_len]);
					if(!key){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
						return MOSQ_ERR_NOMEM;
					}else if(STREMPTY(key)){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid auth_opt_ config option.");
						mosquitto__free(key);
						return MOSQ_ERR_INVAL;
					}
					token += prefix_len+strlen(key)+1;
					while(token[0] == ' ' || token[0] == '\t'){
						token++;
					}
					if(token[0]){
						cur_auth_plugin_config->option_count++;
						cur_auth_plugin_config->options = mosquitto__realloc(cur_auth_plugin_config->options, (size_t)cur_auth_plugin_config->option_count*sizeof(struct mosquitto_auth_opt));
						if(!cur_auth_plugin_config->options){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							mosquitto__free(key);
							return MOSQ_ERR_NOMEM;
						}
						cur_auth_plugin_config->options[cur_auth_plugin_config->option_count-1].key = key;
						cur_auth_plugin_config->options[cur_auth_plugin_config->option_count-1].value = mosquitto__strdup(token);
						if(!cur_auth_plugin_config->options[cur_auth_plugin_config->option_count-1].value){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty %s value in configuration.", key);
						mosquitto__free(key);
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "auth_plugin") || !strcmp(token, "plugin")){
					if(reload) continue; // Auth plugin not currently valid for reloading.
					conf__set_cur_security_options(config, cur_listener, &cur_security_options);
					cur_security_options->auth_plugin_configs = mosquitto__realloc(cur_security_options->auth_plugin_configs, (size_t)(cur_security_options->auth_plugin_config_count+1)*sizeof(struct mosquitto__auth_plugin_config));
					if(!cur_security_options->auth_plugin_configs){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
						return MOSQ_ERR_NOMEM;
					}
					cur_auth_plugin_config = &cur_security_options->auth_plugin_configs[cur_security_options->auth_plugin_config_count];
					memset(cur_auth_plugin_config, 0, sizeof(struct mosquitto__auth_plugin_config));
					cur_auth_plugin_config->path = NULL;
					cur_auth_plugin_config->options = NULL;
					cur_auth_plugin_config->option_count = 0;
					cur_auth_plugin_config->deny_special_chars = true;
					cur_security_options->auth_plugin_config_count++;
					if(conf__parse_string(&token, "auth_plugin", &cur_auth_plugin_config->path, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "auth_plugin_deny_special_chars")){
					if(reload) continue; /* Auth plugin not currently valid for reloading. */
					if(!cur_auth_plugin_config){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: An auth_plugin_deny_special_chars option exists in the config file without an auth_plugin.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_bool(&token, "auth_plugin_deny_special_chars", &cur_auth_plugin_config->deny_special_chars, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "auto_id_prefix")){
					conf__set_cur_security_options(config, cur_listener, &cur_security_options);
					if(conf__parse_string(&token, "auto_id_prefix", &cur_security_options->auto_id_prefix, saveptr)) return MOSQ_ERR_INVAL;
					if(cur_security_options->auto_id_prefix){
						cur_security_options->auto_id_prefix_len = (uint16_t)strlen(cur_security_options->auto_id_prefix);
					}else{
						cur_security_options->auto_id_prefix_len = 0;
					}
				}else if(!strcmp(token, "autosave_interval")){
					if(conf__parse_int(&token, "autosave_interval", &config->autosave_interval, saveptr)) return MOSQ_ERR_INVAL;
					if(config->autosave_interval < 0) config->autosave_interval = 0;
				}else if(!strcmp(token, "autosave_on_changes")){
					if(conf__parse_bool(&token, "autosave_on_changes", &config->autosave_on_changes, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "bind_address")){
					log__printf(NULL, MOSQ_LOG_NOTICE, "The 'bind_address' option is now deprecated and will be removed in a future version. The behaviour will default to true.");
					config->local_only = false;
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_string(&token, "default listener bind_address", &config->default_listener.host, saveptr)) return MOSQ_ERR_INVAL;
					if(conf__attempt_resolve(config->default_listener.host, "bind_address", MOSQ_LOG_ERR, "Error")){
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "bind_interface")){
#ifdef SO_BINDTODEVICE
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_string(&token, "bind_interface", &cur_listener->bind_interface, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_ERR, "Error: bind_interface specified but socket option not available.");
					return MOSQ_ERR_INVAL;
#endif
				}else if(!strcmp(token, "bridge_attempt_unsubscribe")){
#ifdef WITH_BRIDGE
					if(reload) continue; /* FIXME */
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
					if(reload) continue; /* FIXME */
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
#ifdef FINAL_WITH_TLS_PSK
					if(cur_bridge->tls_psk_identity || cur_bridge->tls_psk){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Cannot use both certificate and psk encryption in a single bridge.");
						return MOSQ_ERR_INVAL;
					}
#endif
					if(conf__parse_string(&token, "bridge_cafile", &cur_bridge->tls_cafile, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge and/or TLS support not available.");
#endif
				}else if(!strcmp(token, "bridge_alpn")){
#if defined(WITH_BRIDGE) && defined(WITH_TLS)
					if(reload) continue; /* FIXME */
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_string(&token, "bridge_alpn", &cur_bridge->tls_alpn, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge and/or TLS support not available.");
#endif
				}else if(!strcmp(token, "bridge_bind_address")){
#if defined(WITH_BRIDGE) && defined(WITH_TLS)
					if(reload) continue; /* FIXME */
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_string(&token, "bridge_bind_address", &cur_bridge->bind_address, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "bridge_capath")){
#if defined(WITH_BRIDGE) && defined(WITH_TLS)
					if(reload) continue; /* FIXME */
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
#ifdef FINAL_WITH_TLS_PSK
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
					if(reload) continue; /* FIXME */
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
#ifdef FINAL_WITH_TLS_PSK
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
#if defined(WITH_BRIDGE) && defined(FINAL_WITH_TLS_PSK)
					if(reload) continue; /* FIXME */
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
					if(reload) continue; /* FIXME */
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
				}else if(!strcmp(token, "bridge_require_ocsp")){
#if defined(WITH_BRIDGE) && defined(WITH_TLS)
					if(reload) continue; /* Listeners not valid for reloading. */
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_bool(&token, "bridge_require_ocsp", &cur_bridge->tls_ocsp_required, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "bridge_max_packet_size")){
#if defined(WITH_BRIDGE)
					if(reload) continue; // Bridges not valid for reloading.
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_int(&token, "bridge_max_packet_size", &tmp_int, saveptr)) return MOSQ_ERR_INVAL;
					if(tmp_int < 0) tmp_int = 0;
					cur_bridge->maximum_packet_size = (uint32_t)tmp_int;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "bridge_outgoing_retain")){
#if defined(WITH_BRIDGE)
					if(reload) continue; // Listeners not valid for reloading.
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_bool(&token, "bridge_outgoing_retain", &cur_bridge->outgoing_retain, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "bridge_keyfile")){
#if defined(WITH_BRIDGE) && defined(WITH_TLS)
					if(reload) continue; /* FIXME */
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
#ifdef FINAL_WITH_TLS_PSK
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
					if(reload) continue; /* FIXME */
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
						}else if(!strcmp(token, "mqttv50")){
							cur_bridge->protocol_version = mosq_p_mqtt5;
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
#if defined(WITH_BRIDGE) && defined(FINAL_WITH_TLS_PSK)
					if(reload) continue; /* FIXME */
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
					if(reload) continue; /* FIXME */
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
					if(reload) continue; /* Listeners not valid for reloading. */
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
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_string(&token, "capath", &cur_listener->capath, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "certfile")){
#ifdef WITH_TLS
					if(reload) continue; /* Listeners not valid for reloading. */
					if(cur_listener->psk_hint){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Cannot use both certificate and psk encryption in a single listener.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_string(&token, "certfile", &cur_listener->certfile, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "check_retain_source")){
					conf__set_cur_security_options(config, cur_listener, &cur_security_options);
					if(conf__parse_bool(&token, "check_retain_source", &config->check_retain_source, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "ciphers")){
#ifdef WITH_TLS
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_string(&token, "ciphers", &cur_listener->ciphers, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "ciphers_tls1.3")){
#if defined(WITH_TLS) && !defined(LIBRESSL_VERSION_NUMBER)
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_string(&token, "ciphers_tls1.3", &cur_listener->ciphers_tls13, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: ciphers_tls1.3 support not available.");
#endif
				}else if(!strcmp(token, "clientid") || !strcmp(token, "remote_clientid")){
#ifdef WITH_BRIDGE
					if(reload) continue; /* FIXME */
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
					if(reload) continue; /* FIXME */
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_bool(&token, "cleansession", &cur_bridge->clean_start, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "local_cleansession")){
#ifdef WITH_BRIDGE
					if(reload) continue; // FIXME
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_bool(&token, "local_cleansession", (bool *) &cur_bridge->clean_start_local, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "clientid_prefixes")){
					log__printf(NULL, MOSQ_LOG_NOTICE, "The 'clientid_prefixes' option is now deprecated and will be removed in a future version.");
					if(reload){
						mosquitto__free(config->clientid_prefixes);
						config->clientid_prefixes = NULL;
					}
					if(conf__parse_string(&token, "clientid_prefixes", &config->clientid_prefixes, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "connection")){
#ifdef WITH_BRIDGE
					if(reload) continue; /* FIXME */
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						/* Check for existing bridge name. */
						for(i=0; i<config->bridge_count; i++){
							if(!strcmp(config->bridges[i].name, token)){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Duplicate bridge name \"%s\".", token);
								return MOSQ_ERR_INVAL;
							}
						}

						config->bridge_count++;
						config->bridges = mosquitto__realloc(config->bridges, (size_t)config->bridge_count*sizeof(struct mosquitto__bridge));
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
						cur_bridge->notifications_local_only = false;
						cur_bridge->start_type = bst_automatic;
						cur_bridge->idle_timeout = 60;
						cur_bridge->restart_timeout = 0;
						cur_bridge->backoff_base = 5;
						cur_bridge->backoff_cap = 30;
						cur_bridge->threshold = 10;
						cur_bridge->try_private = true;
						cur_bridge->attempt_unsubscribe = true;
						cur_bridge->protocol_version = mosq_p_mqtt311;
						cur_bridge->primary_retry_sock = INVALID_SOCKET;
						cur_bridge->outgoing_retain = true;
						cur_bridge->clean_start_local = -1;
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
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_string(&token, "crlfile", &cur_listener->crlfile, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "dhparamfile")){
#ifdef WITH_TLS
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_string(&token, "dhparamfile", &cur_listener->dhparamfile, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "http_dir")){
#ifdef WITH_WEBSOCKETS
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_string(&token, "http_dir", &cur_listener->http_dir, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Websockets support not available.");
#endif
				}else if(!strcmp(token, "idle_timeout")){
#ifdef WITH_BRIDGE
					if(reload) continue; /* FIXME */
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

						rc = config__get_dir_files(token, &files, &file_count);
						if(rc) return rc;

						for(i=0; i<file_count; i++){
							log__printf(NULL, MOSQ_LOG_INFO, "Loading config file %s", files[i]);

							rc = config__read_file(config, reload, files[i], cr, level+1, &lineno_ext);
							if(rc){
								if(lineno_ext > 0){
									log__printf(NULL, MOSQ_LOG_ERR, "Error found at %s:%d.", files[i], lineno_ext);
								}
								/* Free happens below */
								break;
							}
						}
						for(i=0; i<file_count; i++){
							mosquitto__free(files[i]);
						}
						mosquitto__free(files);
						if(rc) return rc; /* This returns if config__read_file() fails above */
					}
				}else if(!strcmp(token, "keepalive_interval")){
#ifdef WITH_BRIDGE
					if(reload) continue; /* FIXME */
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_int(&token, "keepalive_interval", &tmp_int, saveptr)) return MOSQ_ERR_INVAL;
					if(tmp_int > UINT16_MAX){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Bridge keepalive value too high.");
						return MOSQ_ERR_INVAL;
					}
					if(tmp_int < 5){
						log__printf(NULL, MOSQ_LOG_NOTICE, "keepalive interval too low, using 5 seconds.");
						tmp_int = 5;
					}
					cur_bridge->keepalive = (uint16_t)tmp_int;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "keyfile")){
#ifdef WITH_TLS
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_string(&token, "keyfile", &cur_listener->keyfile, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "listener")){
					config->local_only = false;
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						tmp_int = atoi(token);
#ifdef WITH_UNIX_SOCKETS
						if(tmp_int < 0 || tmp_int > UINT16_MAX){
#else
						if(tmp_int < 1 || tmp_int > UINT16_MAX){
#endif
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid port value (%d).", tmp_int);
							return MOSQ_ERR_INVAL;
						}

						/* Look for bind address / unix socket path */
						token = strtok_r(NULL, " ", &saveptr);
						if (token != NULL && token[0] == '#'){
							token = NULL;
						}

						if(tmp_int == 0 && token == NULL){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: A listener with port 0 must provide a Unix socket path.");
							return MOSQ_ERR_INVAL;
						}

						if(reload){
							/* We reload listeners settings based on port number/unix socket path.
							 * If the port number/unix path doesn't already exist, exit with a complaint. */
							cur_listener = NULL;
#ifdef WITH_UNIX_SOCKETS
							if(tmp_int == 0){
								for(i=0; i<config->listener_count; i++){
									if(config->listeners[i].unix_socket_path != NULL
											&& strcmp(config->listeners[i].unix_socket_path, token) == 0){

										cur_listener = &config->listeners[i];
										break;
									}
								}
							}else
#endif
							{
								for(i=0; i<config->listener_count; i++){
									if(config->listeners[i].port == tmp_int){
										cur_listener = &config->listeners[i];
										break;
									}
								}
							}
							if(!cur_listener){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: It is not currently possible to add/remove listeners when reloading the config file.");
								return MOSQ_ERR_INVAL;
							}
						}else{
							config->listener_count++;
							config->listeners = mosquitto__realloc(config->listeners, sizeof(struct mosquitto__listener)*(size_t)config->listener_count);
							if(!config->listeners){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
								return MOSQ_ERR_NOMEM;
							}
							cur_listener = &config->listeners[config->listener_count-1];
							memset(cur_listener, 0, sizeof(struct mosquitto__listener));
						}

						listener__set_defaults(cur_listener);
						cur_listener->port = (uint16_t)tmp_int;

						mosquitto__free(cur_listener->host);
						cur_listener->host = NULL;

#ifdef WITH_UNIX_SOCKETS
						mosquitto__free(cur_listener->unix_socket_path);
						cur_listener->unix_socket_path = NULL;
#endif

						if(token){
#ifdef WITH_UNIX_SOCKETS
							if(cur_listener->port == 0){
								cur_listener->unix_socket_path = mosquitto__strdup(token);
							}else
#endif
							{
								cur_listener->host = mosquitto__strdup(token);
							}
						}
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty listener value in configuration.");
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "local_clientid")){
#ifdef WITH_BRIDGE
					if(reload) continue; /* FIXME */
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
					if(reload) continue; /* FIXME */
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
					if(reload) continue; /* FIXME */
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
						}else if(!strcmp(token, "dlt")){
							cr->log_dest |= MQTT3_LOG_DLT;
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
				}else if(!strcmp(token, "log_timestamp_format")){
					if(conf__parse_string(&token, token, &config->log_timestamp_format, saveptr)) return MOSQ_ERR_INVAL;
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
						}else if(!strcmp(token, "internal")){
							cr->log_type |= MOSQ_LOG_INTERNAL;
#ifdef WITH_WEBSOCKETS
						}else if(!strcmp(token, "websockets")){
							cr->log_type |= MOSQ_LOG_WEBSOCKETS;
#endif
						}else if(!strcmp(token, "all")){
							cr->log_type = MOSQ_LOG_ALL;
						}else{
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid log_type value (%s).", token);
							return MOSQ_ERR_INVAL;
						}
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty log_type value in configuration.");
					}
				}else if(!strcmp(token, "max_connections")){
					if(reload) continue; /* Listeners not valid for reloading. */
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						cur_listener->max_connections = atoi(token);
						if(cur_listener->max_connections < 0) cur_listener->max_connections = -1;
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty max_connections value in configuration.");
					}
				}else if(!strcmp(token, "maximum_qos") || !strcmp(token, "max_qos")){
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_int(&token, token, &tmp_int, saveptr)) return MOSQ_ERR_INVAL;
					if(tmp_int < 0 || tmp_int > 2){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: max_qos must be between 0 and 2 inclusive.");
						return MOSQ_ERR_INVAL;
					}
					cur_listener->max_qos = (uint8_t)tmp_int;
				}else if(!strcmp(token, "max_inflight_bytes")){
					if(conf__parse_int(&token, "max_inflight_bytes", &tmp_int, saveptr)) return MOSQ_ERR_INVAL;
					if(tmp_int < 0) tmp_int = 0;
					config->max_inflight_bytes = (size_t)tmp_int;
				}else if(!strcmp(token, "max_inflight_messages")){
					if(conf__parse_int(&token, "max_inflight_messages", &tmp_int, saveptr)) return MOSQ_ERR_INVAL;
					if(tmp_int < 0 || tmp_int == UINT16_MAX){
						tmp_int = 0;
					}else if(tmp_int > UINT16_MAX){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: max_inflight_messages must be <= 65535.");
						return MOSQ_ERR_INVAL;
					}
					config->max_inflight_messages = (uint16_t)tmp_int;
				}else if(!strcmp(token, "max_keepalive")){
					if(conf__parse_int(&token, "max_keepalive", &tmp_int, saveptr)) return MOSQ_ERR_INVAL;
					if(tmp_int < 10 || tmp_int > UINT16_MAX){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid max_keepalive value (%d).", tmp_int);
						return MOSQ_ERR_INVAL;
					}
					config->max_keepalive = (uint16_t)tmp_int;
				}else if(!strcmp(token, "max_packet_size")){
					if(conf__parse_int(&token, "max_packet_size", &tmp_int, saveptr)) return MOSQ_ERR_INVAL;
					if(tmp_int < 20){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid max_packet_size value (%d).", tmp_int);
						return MOSQ_ERR_INVAL;
					}
					config->max_packet_size = (uint32_t)tmp_int;
				}else if(!strcmp(token, "max_queued_bytes")){
					if(conf__parse_int(&token, "max_queued_bytes", &tmp_int, saveptr)) return MOSQ_ERR_INVAL;
					if(tmp_int < 0) tmp_int = 0;
					config->max_queued_bytes = (size_t)tmp_int;
				}else if(!strcmp(token, "max_queued_messages")){
					if(conf__parse_int(&token, "max_queued_messages", &tmp_int, saveptr)) return MOSQ_ERR_INVAL;
					if(tmp_int < 0) tmp_int = 0;
					config->max_queued_messages = tmp_int;
				}else if(!strcmp(token, "memory_limit")){
					ssize_t lim;
					if(conf__parse_ssize_t(&token, "memory_limit", &lim, saveptr)) return MOSQ_ERR_INVAL;
					if(lim < 0){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid memory_limit value (%ld).", lim);
						return MOSQ_ERR_INVAL;
					}
					memory__set_limit((size_t)lim);
				}else if(!strcmp(token, "message_size_limit")){
					if(conf__parse_int(&token, "message_size_limit", (int *)&config->message_size_limit, saveptr)) return MOSQ_ERR_INVAL;
					if(config->message_size_limit > MQTT_MAX_PAYLOAD){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid message_size_limit value (%u).", config->message_size_limit);
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "mount_point")){
					if(reload) continue; /* Listeners not valid for reloading. */
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
					if(reload) continue; /* FIXME */
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_bool(&token, "notifications", &cur_bridge->notifications, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "notifications_local_only")){
#ifdef WITH_BRIDGE
					if(reload) continue; /* FIXME */
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_bool(&token, "notifications_local_only", &cur_bridge->notifications_local_only, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "notification_topic")){
#ifdef WITH_BRIDGE
					if(reload) continue; /* FIXME */
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
					if(reload) continue; /* FIXME */
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_string(&token, "bridge remote_password", &cur_bridge->remote_password, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "password_file")){
					conf__set_cur_security_options(config, cur_listener, &cur_security_options);
					if(reload){
						mosquitto__free(cur_security_options->password_file);
						cur_security_options->password_file = NULL;
					}
					if(conf__parse_string(&token, "password_file", &cur_security_options->password_file, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "per_listener_settings")){
					if(conf__parse_bool(&token, "per_listener_settings", &config->per_listener_settings, saveptr)) return MOSQ_ERR_INVAL;
					if(cur_security_options && config->per_listener_settings){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: per_listener_settings must be set before any other security settings.");
						return MOSQ_ERR_INVAL;
					}
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
					if(reload) continue; /* pid file not valid for reloading. */
					if(conf__parse_string(&token, "pid_file", &config->pid_file, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "port")){
					log__printf(NULL, MOSQ_LOG_NOTICE, "The 'port' option is now deprecated and will be removed in a future version. Please use 'listener' instead.");
					config->local_only = false;
					if(reload) continue; /* Listeners not valid for reloading. */
					if(config->default_listener.port){
						log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Default listener port specified multiple times. Only the latest will be used.");
					}
					if(conf__parse_int(&token, "port", &tmp_int, saveptr)) return MOSQ_ERR_INVAL;
					if(tmp_int < 1 || tmp_int > UINT16_MAX){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid port value (%d).", tmp_int);
						return MOSQ_ERR_INVAL;
					}
					config->default_listener.port = (uint16_t)tmp_int;
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
#ifdef FINAL_WITH_TLS_PSK
					conf__set_cur_security_options(config, cur_listener, &cur_security_options);
					if(reload){
						mosquitto__free(cur_security_options->psk_file);
						cur_security_options->psk_file = NULL;
					}
					if(conf__parse_string(&token, "psk_file", &cur_security_options->psk_file, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS/TLS-PSK support not available.");
#endif
				}else if(!strcmp(token, "psk_hint")){
#ifdef FINAL_WITH_TLS_PSK
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_string(&token, "psk_hint", &cur_listener->psk_hint, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS/TLS-PSK support not available.");
#endif
				}else if(!strcmp(token, "queue_qos0_messages")){
					if(conf__parse_bool(&token, token, &config->queue_qos0_messages, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "require_certificate")){
#ifdef WITH_TLS
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_bool(&token, "require_certificate", &cur_listener->require_certificate, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "restart_timeout")){
#ifdef WITH_BRIDGE
					if(reload) continue; /* FIXME */
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					token = strtok_r(NULL, " ", &saveptr);
					if(!token){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty restart_timeout value in configuration.");
						return MOSQ_ERR_INVAL;
					}
					cur_bridge->restart_timeout = atoi(token);
					if(cur_bridge->restart_timeout < 1){
						log__printf(NULL, MOSQ_LOG_NOTICE, "restart_timeout interval too low, using 1 second.");
						cur_bridge->restart_timeout = 1;
					}
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						cur_bridge->backoff_base = cur_bridge->restart_timeout;
						cur_bridge->backoff_cap = atoi(token);
						if(cur_bridge->backoff_cap < cur_bridge->backoff_base){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: backoff cap is lower than the base in restart_timeout.");
							return MOSQ_ERR_INVAL;
						}
					}
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "retain_available")){
					if(conf__parse_bool(&token, token, &config->retain_available, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "retry_interval")){
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: The retry_interval option is no longer available.");
				}else if(!strcmp(token, "round_robin")){
#ifdef WITH_BRIDGE
					if(reload) continue; /* FIXME */
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_bool(&token, "round_robin", &cur_bridge->round_robin, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "set_tcp_nodelay")){
					if(conf__parse_bool(&token, "set_tcp_nodelay", &config->set_tcp_nodelay, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "start_type")){
#ifdef WITH_BRIDGE
					if(reload) continue; /* FIXME */
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
				}else if(!strcmp(token, "socket_domain")){
					if(reload) continue; /* Listeners not valid for reloading. */
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						if(!strcmp(token, "ipv4")){
							cur_listener->socket_domain = AF_INET;
						}else if(!strcmp(token, "ipv6")){
							cur_listener->socket_domain = AF_INET6;
						}else{
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid socket_domain value \"%s\" in configuration.", token);
							return MOSQ_ERR_INVAL;
						}
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty socket_domain value in configuration.");
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "sys_interval")){
					if(conf__parse_int(&token, "sys_interval", &config->sys_interval, saveptr)) return MOSQ_ERR_INVAL;
					if(config->sys_interval < 0 || config->sys_interval > 65535){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid sys_interval value (%d).", config->sys_interval);
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "threshold")){
#ifdef WITH_BRIDGE
					if(reload) continue; /* FIXME */
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
				}else if(!strcmp(token, "tls_engine")){
#ifdef WITH_TLS
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_string(&token, "tls_engine", &cur_listener->tls_engine, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "tls_engine_kpass_sha1")){
#ifdef WITH_TLS
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_string(&token, "tls_engine_kpass_sha1", &kpass_sha, saveptr)) return MOSQ_ERR_INVAL;
					if(mosquitto__hex2bin_sha1(kpass_sha, (unsigned char**)&kpass_sha_bin) != MOSQ_ERR_SUCCESS){
						mosquitto__free(kpass_sha);
						return MOSQ_ERR_INVAL;
					}
					cur_listener->tls_engine_kpass_sha1 = kpass_sha_bin;
					mosquitto__free(kpass_sha);
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "tls_keyform")){
#ifdef WITH_TLS
					if(reload) continue; /* Listeners not valid for reloading. */
					keyform = NULL;
					if(conf__parse_string(&token, "tls_keyform", &keyform, saveptr)) return MOSQ_ERR_INVAL;
					cur_listener->tls_keyform = mosq_k_pem;
					if(!strcmp(keyform, "engine")) cur_listener->tls_keyform = mosq_k_engine;
					mosquitto__free(keyform);
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "tls_version")){
#if defined(WITH_TLS)
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_string(&token, "tls_version", &cur_listener->tls_version, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "topic")){
#ifdef WITH_BRIDGE
					if(reload) continue; /* FIXME */
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					char *topic = NULL;
					enum mosquitto__bridge_direction direction = bd_out;
					uint8_t qos = 0;
					char *local_prefix = NULL, *remote_prefix = NULL;

					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						topic = token;
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty topic value in configuration.");
						return MOSQ_ERR_INVAL;
					}
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						if(!strcasecmp(token, "out")){
							direction = bd_out;
						}else if(!strcasecmp(token, "in")){
							direction = bd_in;
						}else if(!strcasecmp(token, "both")){
							direction = bd_both;
						}else{
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge topic direction '%s'.", token);
							return MOSQ_ERR_INVAL;
						}
						token = strtok_r(NULL, " ", &saveptr);
						if(token){
							if (token[0] == '#'){
								strtok_r(NULL, "", &saveptr);
							}
							qos = (uint8_t)atoi(token);
							if(qos > 2){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge QoS level '%s'.", token);
								return MOSQ_ERR_INVAL;
							}

							token = strtok_r(NULL, " ", &saveptr);
							if(token){
								if(!strcmp(token, "\"\"") || token[0] == '#'){
									local_prefix = NULL;
									if (token[0] == '#'){
										strtok_r(NULL, "", &saveptr);
									}
								}else{
									local_prefix = token;
								}

								token = strtok_r(NULL, " ", &saveptr);
								if(token){
									if(!strcmp(token, "\"\"") || token[0] == '#'){
										remote_prefix = NULL;
									}else{
										remote_prefix = token;
									}
								}
							}
						}
					}

					if(bridge__add_topic(cur_bridge, topic, direction, qos, local_prefix, remote_prefix)){
						return MOSQ_ERR_INVAL;
					}
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "max_topic_alias")){
					if(reload) continue; /* Listeners not valid for reloading. */
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						tmp_int = atoi(token);
						if(tmp_int < 0 || tmp_int > UINT16_MAX){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid max_topic_alias value in configuration.");
							return MOSQ_ERR_INVAL;
						}
						cur_listener->max_topic_alias = (uint16_t)tmp_int;
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty max_topic_alias value in configuration.");
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "try_private")){
#ifdef WITH_BRIDGE
					if(reload) continue; /* FIXME */
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
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_bool(&token, "use_identity_as_username", &cur_listener->use_identity_as_username, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "use_subject_as_username")){
#ifdef WITH_TLS
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_bool(&token, "use_subject_as_username", &cur_listener->use_subject_as_username, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
#endif
				}else if(!strcmp(token, "user")){
					if(reload) continue; /* Drop privileges user not valid for reloading. */
					mosquitto__free(config->user);
					if(conf__parse_string(&token, "user", &config->user, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "use_username_as_clientid")){
					if(reload) continue; /* Listeners not valid for reloading. */
					if(conf__parse_bool(&token, "use_username_as_clientid", &cur_listener->use_username_as_clientid, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "username") || !strcmp(token, "remote_username")){
#ifdef WITH_BRIDGE
					if(reload) continue; /* FIXME */
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					if(conf__parse_string(&token, "bridge remote_username", &cur_bridge->remote_username, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
#endif
				}else if(!strcmp(token, "websockets_log_level")){
#ifdef WITH_WEBSOCKETS
					if(conf__parse_int(&token, "websockets_log_level", &config->websockets_log_level, saveptr)) return MOSQ_ERR_INVAL;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Websockets support not available.");
#endif
				}else if(!strcmp(token, "websockets_headers_size")){
#ifdef WITH_WEBSOCKETS
					if(conf__parse_int(&token, "websockets_headers_size", &tmp_int, saveptr)) return MOSQ_ERR_INVAL;
					if(tmp_int < 0 || tmp_int > UINT16_MAX){
						log__printf(NULL, MOSQ_LOG_WARNING, "Error: Websockets headers size must be between 0 and 65535 inclusive.");
						return MOSQ_ERR_INVAL;
					}
					config->websockets_headers_size = (uint16_t)tmp_int;
#else
					log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Websockets support not available.");
#endif
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
	char *buf;
	int buflen;
#ifndef WIN32
	DIR *dir;
#endif

#ifndef WIN32
	dir = opendir(file);
	if(dir){
		closedir(dir);
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Config file %s is a directory.", file);
		return 1;
	}
#endif

	fptr = mosquitto__fopen(file, "rt", false);
	if(!fptr){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open config file %s.", file);
		return 1;
	}

	buflen = 1000;
	buf = mosquitto__malloc((size_t)buflen);
	if(!buf){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		fclose(fptr);
		return MOSQ_ERR_NOMEM;
	}

	rc = config__read_file_core(config, reload, cr, level, lineno, fptr, &buf, &buflen);
	mosquitto__free(buf);
	fclose(fptr);

	return rc;
}


static int config__check(struct mosquitto__config *config)
{
	/* Checks that are easy to make after the config has been loaded. */

	int i;

#ifdef WITH_BRIDGE
	int j;
	struct mosquitto__bridge *bridge1, *bridge2;
	char hostname[256];
	size_t len;

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

	/* Default to auto_id_prefix = 'auto-' if none set. */
	if(config->per_listener_settings){
		for(i=0; i<config->listener_count; i++){
			if(!config->listeners[i].security_options.auto_id_prefix){
				config->listeners[i].security_options.auto_id_prefix = mosquitto__strdup("auto-");
				if(!config->listeners[i].security_options.auto_id_prefix){
					return MOSQ_ERR_NOMEM;
				}
				config->listeners[i].security_options.auto_id_prefix_len = strlen("auto-");
			}
		}
	}else{
		if(!config->security_options.auto_id_prefix){
			config->security_options.auto_id_prefix = mosquitto__strdup("auto-");
			if(!config->security_options.auto_id_prefix){
				return MOSQ_ERR_NOMEM;
			}
			config->security_options.auto_id_prefix_len = strlen("auto-");
		}
	}

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
			return MOSQ_ERR_INVAL;
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

static int conf__parse_ssize_t(char **token, const char *name, ssize_t *value, char *saveptr)
{
	*token = strtok_r(NULL, " ", &saveptr);
	if(*token){
		*value = atol(*token);
	}else{
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty %s value in configuration.", name);
		return MOSQ_ERR_INVAL;
	}

	return MOSQ_ERR_SUCCESS;
}

static int conf__parse_string(char **token, const char *name, char **value, char *saveptr)
{
	size_t tlen;

	*token = strtok_r(NULL, "", &saveptr);
	if(*token){
		if(*value){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Duplicate %s value in configuration.", name);
			return MOSQ_ERR_INVAL;
		}
		/* Deal with multiple spaces at the beginning of the string. */
		*token = misc__trimblanks(*token);
		if(strlen(*token) == 0){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty %s value in configuration.", name);
			return MOSQ_ERR_INVAL;
		}

		tlen = strlen(*token);
		if(tlen > UINT16_MAX){
			return MOSQ_ERR_INVAL;
		}
		if(mosquitto_validate_utf8(*token, (uint16_t)tlen)){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Malformed UTF-8 in configuration.");
			return MOSQ_ERR_INVAL;
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
