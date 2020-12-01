/*
Copyright (c) 2014-2020 Roger Light <roger@atchoo.org>

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

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#include <strings.h>
#else
#include <process.h>
#include <winsock2.h>
#define snprintf sprintf_s
#define strncasecmp _strnicmp
#endif

#include <mosquitto.h>
#include <mqtt_protocol.h>
#include "client_shared.h"

#ifdef WITH_SOCKS
static int mosquitto__parse_socks_url(struct mosq_config *cfg, char *url);
#endif
static int client_config_line_proc(struct mosq_config *cfg, int pub_or_sub, int argc, char *argv[]);


static int check_format(const char *str)
{
	int i;
	size_t len;

	len = strlen(str);
	for(i=0; i<len; i++){
		if(str[i] == '%'){
			if(i == len-1){
				// error
				fprintf(stderr, "Error: Incomplete format specifier.\n");
				return 1;
			}else{
				if(str[i+1] == '0' || str[i+1] == '-'){
					/* Flag characters */
					i++;
					if(i == len-1){
						// error
						fprintf(stderr, "Error: Incomplete format specifier.\n");
						return 1;
					}
				}

				/* Field width */
				while(str[i+1] >= '0' && str[i+1] <= '9'){
					i++;
					if(i == len-1){
						// error
						fprintf(stderr, "Error: Incomplete format specifier.\n");
						return 1;
					}
				}

				if(str[i+1] == '.'){
					/* Precision specifier */
					i++;
					if(i == len-1){
						// error
						fprintf(stderr, "Error: Incomplete format specifier.\n");
						return 1;
					}
					/* Precision */
					while(str[i+1] >= '0' && str[i+1] <= '9'){
						i++;
						if(i == len-1){
							// error
							fprintf(stderr, "Error: Incomplete format specifier.\n");
							return 1;
						}
					}
				}

				if(str[i+1] == '%'){
					// Print %, ignore
				}else if(str[i+1] == 'A'){
					// MQTT v5 property topic-alias
				}else if(str[i+1] == 'C'){
					// MQTT v5 property content-type
				}else if(str[i+1] == 'D'){
					// MQTT v5 property correlation-data
				}else if(str[i+1] == 'E'){
					// MQTT v5 property message-expiry-interval
				}else if(str[i+1] == 'F'){
					// MQTT v5 property payload-format-indicator
				}else if(str[i+1] == 'I'){
					// ISO 8601 date+time
				}else if(str[i+1] == 'l'){
					// payload length
				}else if(str[i+1] == 'm'){
					// mid
				}else if(str[i+1] == 'P'){
					// MQTT v5 property user-property
				}else if(str[i+1] == 'p'){
					// payload
				}else if(str[i+1] == 'q'){
					// qos
				}else if(str[i+1] == 'R'){
					// MQTT v5 property response-topic
				}else if(str[i+1] == 'S'){
					// MQTT v5 property subscription-identifier
				}else if(str[i+1] == 'r'){
					// retain
				}else if(str[i+1] == 't'){
					// topic
				}else if(str[i+1] == 'j'){
					// JSON output, escaped payload
				}else if(str[i+1] == 'J'){
					// JSON output, assuming JSON payload
				}else if(str[i+1] == 'U'){
					// Unix time+nanoseconds
#ifdef WIN32
					fprintf(stderr, "Error: The %%U format option is not supported on Windows.\n");
					return 1;
#endif
				}else if(str[i+1] == 'x' || str[i+1] == 'X'){
					// payload in hex
				}else{
					fprintf(stderr, "Error: Invalid format specifier '%c'.\n", str[i+1]);
					return 1;
				}
				i++;
			}
		}else if(str[i] == '@'){
			if(i == len-1){
				// error
				fprintf(stderr, "Error: Incomplete format specifier.\n");
				return 1;
			}
			i++;
		}else if(str[i] == '\\'){
			if(i == len-1){
				// error
				fprintf(stderr, "Error: Incomplete escape specifier.\n");
				return 1;
			}else{
				switch(str[i+1]){
					case '\\': // '\'
					case '0':  // 0 (NULL)
					case 'a':  // alert
					case 'e':  // escape
					case 'n':  // new line
					case 'r':  // carriage return
					case 't':  // horizontal tab
					case 'v':  // vertical tab
						break;

					default:
						fprintf(stderr, "Error: Invalid escape specifier '%c'.\n", str[i+1]);
						return 1;
				}
				i++;
			}
		}
	}

	return 0;
}


void init_config(struct mosq_config *cfg, int pub_or_sub)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->port = PORT_UNDEFINED;
	cfg->max_inflight = 20;
	cfg->keepalive = 60;
	cfg->clean_session = true;
	cfg->eol = true;
	cfg->repeat_count = 1;
	cfg->repeat_delay.tv_sec = 0;
	cfg->repeat_delay.tv_usec = 0;
	cfg->random_filter = 10000;
	if(pub_or_sub == CLIENT_RR){
		cfg->protocol_version = MQTT_PROTOCOL_V5;
		cfg->msg_count = 1;
	}else{
		cfg->protocol_version = MQTT_PROTOCOL_V311;
	}
	cfg->session_expiry_interval = -1; /* -1 means unset here, the user can't set it to -1. */
}

void client_config_cleanup(struct mosq_config *cfg)
{
	int i;
	free(cfg->id);
	free(cfg->id_prefix);
	free(cfg->host);
	free(cfg->file_input);
	free(cfg->message);
	free(cfg->topic);
	free(cfg->bind_address);
	free(cfg->username);
	free(cfg->password);
	free(cfg->will_topic);
	free(cfg->will_payload);
	free(cfg->format);
	free(cfg->response_topic);
#ifdef WITH_TLS
	free(cfg->cafile);
	free(cfg->capath);
	free(cfg->certfile);
	free(cfg->keyfile);
	free(cfg->ciphers);
	free(cfg->tls_alpn);
	free(cfg->tls_version);
	free(cfg->tls_engine);
	free(cfg->tls_engine_kpass_sha1);
	free(cfg->keyform);
#  ifdef FINAL_WITH_TLS_PSK
	free(cfg->psk);
	free(cfg->psk_identity);
#  endif
#endif
	if(cfg->topics){
		for(i=0; i<cfg->topic_count; i++){
			free(cfg->topics[i]);
		}
		free(cfg->topics);
	}
	if(cfg->filter_outs){
		for(i=0; i<cfg->filter_out_count; i++){
			free(cfg->filter_outs[i]);
		}
		free(cfg->filter_outs);
	}
	if(cfg->unsub_topics){
		for(i=0; i<cfg->unsub_topic_count; i++){
			free(cfg->unsub_topics[i]);
		}
		free(cfg->unsub_topics);
	}
#ifdef WITH_SOCKS
	free(cfg->socks5_host);
	free(cfg->socks5_username);
	free(cfg->socks5_password);
#endif
	mosquitto_property_free_all(&cfg->connect_props);
	mosquitto_property_free_all(&cfg->publish_props);
	mosquitto_property_free_all(&cfg->subscribe_props);
	mosquitto_property_free_all(&cfg->unsubscribe_props);
	mosquitto_property_free_all(&cfg->disconnect_props);
	mosquitto_property_free_all(&cfg->will_props);
}

int client_config_load(struct mosq_config *cfg, int pub_or_sub, int argc, char *argv[])
{
	int rc;
	FILE *fptr;
	char line[1024];
	int count;
	char *loc = NULL;
	size_t len;
	char *args[3];

#ifndef WIN32
	char *env;
#else
	char env[1024];
#endif
	args[0] = NULL;

	init_config(cfg, pub_or_sub);

	/* Default config file */
#ifndef WIN32
	env = getenv("XDG_CONFIG_HOME");
	if(env){
		len = strlen(env) + strlen("/mosquitto_pub") + 1;
		loc = malloc(len);
		if(!loc){
			err_printf(cfg, "Error: Out of memory.\n");
			return 1;
		}
		if(pub_or_sub == CLIENT_PUB){
			snprintf(loc, len, "%s/mosquitto_pub", env);
		}else if(pub_or_sub == CLIENT_SUB){
			snprintf(loc, len, "%s/mosquitto_sub", env);
		}else{
			snprintf(loc, len, "%s/mosquitto_rr", env);
		}
		loc[len-1] = '\0';
	}else{
		env = getenv("HOME");
		if(env){
			len = strlen(env) + strlen("/.config/mosquitto_pub") + 1;
			loc = malloc(len);
			if(!loc){
				err_printf(cfg, "Error: Out of memory.\n");
				return 1;
			}
			if(pub_or_sub == CLIENT_PUB){
				snprintf(loc, len, "%s/.config/mosquitto_pub", env);
			}else if(pub_or_sub == CLIENT_SUB){
				snprintf(loc, len, "%s/.config/mosquitto_sub", env);
			}else{
				snprintf(loc, len, "%s/.config/mosquitto_rr", env);
			}
			loc[len-1] = '\0';
		}
	}

#else
	rc = GetEnvironmentVariable("USERPROFILE", env, 1024);
	if(rc > 0 && rc < 1024){
		len = strlen(env) + strlen("\\mosquitto_pub.conf") + 1;
		loc = malloc(len);
		if(!loc){
			err_printf(cfg, "Error: Out of memory.\n");
			return 1;
		}
		if(pub_or_sub == CLIENT_PUB){
			snprintf(loc, len, "%s\\mosquitto_pub.conf", env);
		}else if(pub_or_sub == CLIENT_SUB){
			snprintf(loc, len, "%s\\mosquitto_sub.conf", env);
		}else{
			snprintf(loc, len, "%s\\mosquitto_rr.conf", env);
		}
		loc[len-1] = '\0';
	}
#endif

	if(loc){
		fptr = fopen(loc, "rt");
		if(fptr){
			while(fgets(line, 1024, fptr)){
				if(line[0] == '#') continue; /* Comments */

				while(line[strlen(line)-1] == 10 || line[strlen(line)-1] == 13){
					line[strlen(line)-1] = 0;
				}
				/* All offset by one "args" here, because real argc/argv has
				 * program name as the first entry. */
				args[1] = strtok(line, " ");
				if(args[1]){
					args[2] = strtok(NULL, " ");
					if(args[2]){
						count = 3;
					}else{
						count = 2;
					}
					rc = client_config_line_proc(cfg, pub_or_sub, count, args);
					if(rc){
						fclose(fptr);
						free(loc);
						return rc;
					}
				}
			}
			fclose(fptr);
		}
		free(loc);
	}

	/* Deal with real argc/argv */
	rc = client_config_line_proc(cfg, pub_or_sub, argc, argv);
	if(rc) return rc;

	if(cfg->will_payload && !cfg->will_topic){
		fprintf(stderr, "Error: Will payload given, but no will topic given.\n");
		return 1;
	}
	if(cfg->will_retain && !cfg->will_topic){
		fprintf(stderr, "Error: Will retain given, but no will topic given.\n");
		return 1;
	}
#ifdef WITH_TLS
	if((cfg->certfile && !cfg->keyfile) || (cfg->keyfile && !cfg->certfile)){
		fprintf(stderr, "Error: Both certfile and keyfile must be provided if one of them is set.\n");
		return 1;
	}
	if((cfg->keyform && !cfg->keyfile)){
		fprintf(stderr, "Error: If keyform is set, keyfile must be also specified.\n");
		return 1;
	}
	if((cfg->tls_engine_kpass_sha1 && (!cfg->keyform || !cfg->tls_engine))){
		fprintf(stderr, "Error: when using tls-engine-kpass-sha1, both tls-engine and keyform must also be provided.\n");
		return 1;
	}
#endif
#ifdef FINAL_WITH_TLS_PSK
	if((cfg->cafile || cfg->capath) && cfg->psk){
		fprintf(stderr, "Error: Only one of --psk or --cafile/--capath may be used at once.\n");
		return 1;
	}
	if(cfg->psk && !cfg->psk_identity){
		fprintf(stderr, "Error: --psk-identity required if --psk used.\n");
		return 1;
	}
#endif

	if(cfg->protocol_version == 5){
		if(cfg->clean_session == false && cfg->session_expiry_interval == -1){
			/* User hasn't set session-expiry-interval, but has cleared clean
			 * session so default to persistent session. */
			cfg->session_expiry_interval = UINT32_MAX;
		}
		if(cfg->session_expiry_interval > 0){
			if(cfg->session_expiry_interval == UINT32_MAX && (cfg->id_prefix || !cfg->id)){
				fprintf(stderr, "Error: You must provide a client id if you are using an infinite session expiry interval.\n");
				return 1;
			}
			rc = mosquitto_property_add_int32(&cfg->connect_props, MQTT_PROP_SESSION_EXPIRY_INTERVAL, (uint32_t )cfg->session_expiry_interval);
			if(rc){
				fprintf(stderr, "Error adding property session-expiry-interval\n");
			}
		}
	}else{
		if(cfg->clean_session == false && (cfg->id_prefix || !cfg->id)){
			fprintf(stderr, "Error: You must provide a client id if you are using the -c option.\n");
			return 1;
		}
	}

	if(pub_or_sub == CLIENT_SUB){
		if(cfg->topic_count == 0){
			fprintf(stderr, "Error: You must specify a topic to subscribe to.\n");
			return 1;
		}
	}

	if(!cfg->host){
		cfg->host = strdup("localhost");
		if(!cfg->host){
			err_printf(cfg, "Error: Out of memory.\n");
			return 1;
		}
	}

	rc = mosquitto_property_check_all(CMD_CONNECT, cfg->connect_props);
	if(rc){
		err_printf(cfg, "Error in CONNECT properties: %s\n", mosquitto_strerror(rc));
		return 1;
	}
	rc = mosquitto_property_check_all(CMD_PUBLISH, cfg->publish_props);
	if(rc){
		err_printf(cfg, "Error in PUBLISH properties: %s\n", mosquitto_strerror(rc));
		return 1;
	}
	rc = mosquitto_property_check_all(CMD_SUBSCRIBE, cfg->subscribe_props);
	if(rc){
		err_printf(cfg, "Error in SUBSCRIBE properties: %s\n", mosquitto_strerror(rc));
		return 1;
	}
	rc = mosquitto_property_check_all(CMD_UNSUBSCRIBE, cfg->unsubscribe_props);
	if(rc){
		err_printf(cfg, "Error in UNSUBSCRIBE properties: %s\n", mosquitto_strerror(rc));
		return 1;
	}
	rc = mosquitto_property_check_all(CMD_DISCONNECT, cfg->disconnect_props);
	if(rc){
		err_printf(cfg, "Error in DISCONNECT properties: %s\n", mosquitto_strerror(rc));
		return 1;
	}
	rc = mosquitto_property_check_all(CMD_WILL, cfg->will_props);
	if(rc){
		err_printf(cfg, "Error in Will properties: %s\n", mosquitto_strerror(rc));
		return 1;
	}

	return MOSQ_ERR_SUCCESS;
}

int cfg_add_topic(struct mosq_config *cfg, int type, char *topic, const char *arg)
{
	if(mosquitto_validate_utf8(topic, (int )strlen(topic))){
		fprintf(stderr, "Error: Malformed UTF-8 in %s argument.\n\n", arg);
		return 1;
	}
	if(type == CLIENT_PUB || type == CLIENT_RR){
		if(mosquitto_pub_topic_check(topic) == MOSQ_ERR_INVAL){
			fprintf(stderr, "Error: Invalid publish topic '%s', does it contain '+' or '#'?\n", topic);
			return 1;
		}
		cfg->topic = strdup(topic);
	}else if(type == CLIENT_RESPONSE_TOPIC){
		if(mosquitto_pub_topic_check(topic) == MOSQ_ERR_INVAL){
			fprintf(stderr, "Error: Invalid response topic '%s', does it contain '+' or '#'?\n", topic);
			return 1;
		}
		cfg->response_topic = strdup(topic);
	}else{
		if(mosquitto_sub_topic_check(topic) == MOSQ_ERR_INVAL){
			fprintf(stderr, "Error: Invalid subscription topic '%s', are all '+' and '#' wildcards correct?\n", topic);
			return 1;
		}
		cfg->topic_count++;
		cfg->topics = realloc(cfg->topics, (size_t )cfg->topic_count*sizeof(char *));
		if(!cfg->topics){
			err_printf(cfg, "Error: Out of memory.\n");
			return 1;
		}
		cfg->topics[cfg->topic_count-1] = strdup(topic);
	}
	return 0;
}

/* Process a tokenised single line from a file or set of real argc/argv */
int client_config_line_proc(struct mosq_config *cfg, int pub_or_sub, int argc, char *argv[])
{
	int i;
	int tmpi;
	float f;
	size_t szt;

	for(i=1; i<argc; i++){
		if(!strcmp(argv[i], "-A")){
			if(i==argc-1){
				fprintf(stderr, "Error: -A argument given but no address specified.\n\n");
				return 1;
			}else{
				cfg->bind_address = strdup(argv[i+1]);
			}
			i++;
#ifdef WITH_TLS
		}else if(!strcmp(argv[i], "--cafile")){
			if(i==argc-1){
				fprintf(stderr, "Error: --cafile argument given but no file specified.\n\n");
				return 1;
			}else{
				cfg->cafile = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "--capath")){
			if(i==argc-1){
				fprintf(stderr, "Error: --capath argument given but no directory specified.\n\n");
				return 1;
			}else{
				cfg->capath = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "--cert")){
			if(i==argc-1){
				fprintf(stderr, "Error: --cert argument given but no file specified.\n\n");
				return 1;
			}else{
				cfg->certfile = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "--ciphers")){
			if(i==argc-1){
				fprintf(stderr, "Error: --ciphers argument given but no ciphers specified.\n\n");
				return 1;
			}else{
				cfg->ciphers = strdup(argv[i+1]);
			}
			i++;
#endif
		}else if(!strcmp(argv[i], "-C")){
			if(pub_or_sub != CLIENT_SUB){
				goto unknown_option;
			}else{
				if(i==argc-1){
					fprintf(stderr, "Error: -C argument given but no count specified.\n\n");
					return 1;
				}else{
					cfg->msg_count = atoi(argv[i+1]);
					if(cfg->msg_count < 1){
						fprintf(stderr, "Error: Invalid message count \"%d\".\n\n", cfg->msg_count);
						return 1;
					}
				}
				i++;
			}
		}else if(!strcmp(argv[i], "-c") || !strcmp(argv[i], "--disable-clean-session")){
			cfg->clean_session = false;
		}else if(!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")){
			cfg->debug = true;
		}else if(!strcmp(argv[i], "-D") || !strcmp(argv[i], "--property")){
			i++;
			if(cfg_parse_property(cfg, argc, argv, &i)){
				return 1;
			}
			cfg->protocol_version = MQTT_PROTOCOL_V5;
		}else if(!strcmp(argv[i], "-e")){
			if(pub_or_sub != CLIENT_RR){
				goto unknown_option;
			}
			if(i==argc-1){
				fprintf(stderr, "Error: -e argument given but no response topic specified.\n\n");
				return 1;
			}else{
				if(cfg_add_topic(cfg, CLIENT_RESPONSE_TOPIC, argv[i+1], "-e")){
					return 1;
				}
			}
			i++;
		}else if(!strcmp(argv[i], "-E")){
			if(pub_or_sub != CLIENT_SUB){
				goto unknown_option;
			}
			cfg->exit_after_sub = true;
		}else if(!strcmp(argv[i], "-f") || !strcmp(argv[i], "--file")){
			if(pub_or_sub == CLIENT_SUB){
				goto unknown_option;
			}
			if(cfg->pub_mode != MSGMODE_NONE){
				fprintf(stderr, "Error: Only one type of message can be sent at once.\n\n");
				return 1;
			}else if(i==argc-1){
				fprintf(stderr, "Error: -f argument given but no file specified.\n\n");
				return 1;
			}else{
				cfg->pub_mode = MSGMODE_FILE;
				cfg->file_input = strdup(argv[i+1]);
				if(!cfg->file_input){
					err_printf(cfg, "Error: Out of memory.\n");
					return 1;
				}
			}
			i++;
		}else if(!strcmp(argv[i], "-F")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}
			if(i==argc-1){
				fprintf(stderr, "Error: -F argument given but no format specified.\n\n");
				return 1;
			}else{
				cfg->format = strdup(argv[i+1]);
				if(!cfg->format){
					fprintf(stderr, "Error: Out of memory.\n");
					return 1;
				}
				if(check_format(cfg->format)){
					return 1;
				}
			}
			i++;
		}else if(!strcmp(argv[i], "--help")){
			return 2;
		}else if(!strcmp(argv[i], "-h") || !strcmp(argv[i], "--host")){
			if(i==argc-1){
				fprintf(stderr, "Error: -h argument given but no host specified.\n\n");
				return 1;
			}else{
				cfg->host = strdup(argv[i+1]);
			}
			i++;
#ifdef WITH_TLS
		}else if(!strcmp(argv[i], "--insecure")){
			cfg->insecure = true;
#endif
		}else if(!strcmp(argv[i], "-i") || !strcmp(argv[i], "--id")){
			if(cfg->id_prefix){
				fprintf(stderr, "Error: -i and -I argument cannot be used together.\n\n");
				return 1;
			}
			if(i==argc-1){
				fprintf(stderr, "Error: -i argument given but no id specified.\n\n");
				return 1;
			}else{
				cfg->id = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "-I") || !strcmp(argv[i], "--id-prefix")){
			if(cfg->id){
				fprintf(stderr, "Error: -i and -I argument cannot be used together.\n\n");
				return 1;
			}
			if(i==argc-1){
				fprintf(stderr, "Error: -I argument given but no id prefix specified.\n\n");
				return 1;
			}else{
				cfg->id_prefix = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "-k") || !strcmp(argv[i], "--keepalive")){
			if(i==argc-1){
				fprintf(stderr, "Error: -k argument given but no keepalive specified.\n\n");
				return 1;
			}else{
				cfg->keepalive = atoi(argv[i+1]);
				if(cfg->keepalive<5 || cfg->keepalive>UINT16_MAX){
					fprintf(stderr, "Error: Invalid keepalive given, it must be between 5 and 65535 inclusive.\n\n");
					return 1;
				}
			}
			i++;
#ifdef WITH_TLS
		}else if(!strcmp(argv[i], "--key")){
			if(i==argc-1){
				fprintf(stderr, "Error: --key argument given but no file specified.\n\n");
				return 1;
			}else{
				cfg->keyfile = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "--keyform")){
			if(i==argc-1){
				fprintf(stderr, "Error: --keyform argument given but no keyform specified.\n\n");
				return 1;
			}else{
				cfg->keyform = strdup(argv[i+1]);
			}
			i++;
#endif
		}else if(!strcmp(argv[i], "-L") || !strcmp(argv[i], "--url")){
			if(i==argc-1){
				fprintf(stderr, "Error: -L argument given but no URL specified.\n\n");
				return 1;
			} else {
				char *url = argv[i+1];
				char *topic;
				char *tmp;

				if(!strncasecmp(url, "mqtt://", 7)) {
					url += 7;
					cfg->port = 1883;
				} else if(!strncasecmp(url, "mqtts://", 8)) {
#ifdef WITH_TLS
					url += 8;
					cfg->port = 8883;
					cfg->tls_use_os_certs = true;
#else
					fprintf(stderr, "Error: TLS support not available.\n\n");
					return 1;
#endif
				} else {
					fprintf(stderr, "Error: unsupported URL scheme.\n\n");
					return 1;
				}
				topic = strchr(url, '/');
				if(!topic){
					fprintf(stderr, "Error: Invalid URL for -L argument specified - topic missing.\n");
					return 1;
				}
				*topic++ = 0;

				if(cfg_add_topic(cfg, pub_or_sub, topic, "-L topic"))
					return 1;

				tmp = strchr(url, '@');
				if(tmp) {
					*tmp++ = 0;
					char *colon = strchr(url, ':');
					if(colon) {
						*colon = 0;
						cfg->password = strdup(colon + 1);
					}
					cfg->username = strdup(url);
					url = tmp;
				}
				cfg->host = url;

				tmp = strchr(url, ':');
				if(tmp) {
					*tmp++ = 0;
					cfg->port = atoi(tmp);
				}
				/* Now we've removed the port, time to get the host on the heap */
				cfg->host = strdup(cfg->host);
			}
			i++;
		}else if(!strcmp(argv[i], "-l") || !strcmp(argv[i], "--stdin-line")){
			if(pub_or_sub != CLIENT_PUB){
				goto unknown_option;
			}
			if(cfg->pub_mode != MSGMODE_NONE){
				fprintf(stderr, "Error: Only one type of message can be sent at once.\n\n");
				return 1;
			}else{
				cfg->pub_mode = MSGMODE_STDIN_LINE;
			}
		}else if(!strcmp(argv[i], "-m") || !strcmp(argv[i], "--message")){
			if(pub_or_sub == CLIENT_SUB){
				goto unknown_option;
			}
			if(cfg->pub_mode != MSGMODE_NONE){
				fprintf(stderr, "Error: Only one type of message can be sent at once.\n\n");
				return 1;
			}else if(i==argc-1){
				fprintf(stderr, "Error: -m argument given but no message specified.\n\n");
				return 1;
			}else{
				cfg->message = strdup(argv[i+1]);
				if(cfg->message == NULL){
					fprintf(stderr, "Error: Out of memory.\n\n");
					return 1;
				}
				szt = strlen(cfg->message);
				if(szt > MQTT_MAX_PAYLOAD){
					fprintf(stderr, "Error: Message length must be less than %u bytes.\n\n", MQTT_MAX_PAYLOAD);
					return 1;
				}
				cfg->msglen = (int )szt;
				cfg->pub_mode = MSGMODE_CMD;
			}
			i++;
		}else if(!strcmp(argv[i], "-M")){
			if(i==argc-1){
				fprintf(stderr, "Error: -M argument given but max_inflight not specified.\n\n");
				return 1;
			}else{
				tmpi = atoi(argv[i+1]);
				if(tmpi < 1){
					fprintf(stderr, "Error: Maximum inflight messages must be greater than 0.\n\n");
					return 1;
				}
				cfg->max_inflight = (unsigned int )tmpi;
			}
			i++;
		}else if(!strcmp(argv[i], "--nodelay")){
			cfg->tcp_nodelay = true;
		}else if(!strcmp(argv[i], "-n") || !strcmp(argv[i], "--null-message")){
			if(pub_or_sub == CLIENT_SUB){
				goto unknown_option;
			}
			if(cfg->pub_mode != MSGMODE_NONE){
				fprintf(stderr, "Error: Only one type of message can be sent at once.\n\n");
				return 1;
			}else{
				cfg->pub_mode = MSGMODE_NULL;
			}
		}else if(!strcmp(argv[i], "-N")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}
			cfg->eol = false;
		}else if(!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")){
			if(i==argc-1){
				fprintf(stderr, "Error: -p argument given but no port specified.\n\n");
				return 1;
			}else{
				cfg->port = atoi(argv[i+1]);
				if(cfg->port<0 || cfg->port>65535){
					fprintf(stderr, "Error: Invalid port given: %d\n", cfg->port);
					return 1;
				}
			}
			i++;
		}else if(!strcmp(argv[i], "--pretty")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}
			cfg->pretty = true;
		}else if(!strcmp(argv[i], "-P") || !strcmp(argv[i], "--pw")){
			if(i==argc-1){
				fprintf(stderr, "Error: -P argument given but no password specified.\n\n");
				return 1;
			}else{
				cfg->password = strdup(argv[i+1]);
			}
			i++;
#ifdef WITH_SOCKS
		}else if(!strcmp(argv[i], "--proxy")){
			if(i==argc-1){
				fprintf(stderr, "Error: --proxy argument given but no proxy url specified.\n\n");
				return 1;
			}else{
				if(mosquitto__parse_socks_url(cfg, argv[i+1])){
					return 1;
				}
				i++;
			}
#endif
#ifdef FINAL_WITH_TLS_PSK
		}else if(!strcmp(argv[i], "--psk")){
			if(i==argc-1){
				fprintf(stderr, "Error: --psk argument given but no key specified.\n\n");
				return 1;
			}else{
				cfg->psk = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "--psk-identity")){
			if(i==argc-1){
				fprintf(stderr, "Error: --psk-identity argument given but no identity specified.\n\n");
				return 1;
			}else{
				cfg->psk_identity = strdup(argv[i+1]);
			}
			i++;
#endif
		}else if(!strcmp(argv[i], "-q") || !strcmp(argv[i], "--qos")){
			if(i==argc-1){
				fprintf(stderr, "Error: -q argument given but no QoS specified.\n\n");
				return 1;
			}else{
				cfg->qos = atoi(argv[i+1]);
				if(cfg->qos<0 || cfg->qos>2){
					fprintf(stderr, "Error: Invalid QoS given: %d\n", cfg->qos);
					return 1;
				}
			}
			i++;
		}else if(!strcmp(argv[i], "--quiet")){
			cfg->quiet = true;
		}else if(!strcmp(argv[i], "-r") || !strcmp(argv[i], "--retain")){
			if(pub_or_sub != CLIENT_PUB){
				goto unknown_option;
			}
			cfg->retain = 1;
		}else if(!strcmp(argv[i], "-R")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}
			cfg->no_retain = true;
			cfg->sub_opts |= MQTT_SUB_OPT_SEND_RETAIN_NEVER;
		}else if(!strcmp(argv[i], "--random-filter")){
			if(pub_or_sub != CLIENT_SUB){
				goto unknown_option;
			}
			if(i==argc-1){
				fprintf(stderr, "Error: --random-filter argument given but no chance specified.\n\n");
				return 1;
			}else{
				cfg->random_filter = (int)(10.0*atof(argv[i+1]));
				if(cfg->random_filter > 10000 || cfg->random_filter < 1){
					fprintf(stderr, "Error: --random-filter chance must be between 0.1-100.0\n\n");
					return 1;
				}
			}
			i++;
		}else if(!strcmp(argv[i], "--remove-retained")){
			if(pub_or_sub != CLIENT_SUB){
				goto unknown_option;
			}
			cfg->remove_retained = true;
		}else if(!strcmp(argv[i], "--repeat")){
			if(pub_or_sub != CLIENT_PUB){
				goto unknown_option;
			}
			if(i==argc-1){
				fprintf(stderr, "Error: --repeat argument given but no count specified.\n\n");
				return 1;
			}else{
				cfg->repeat_count = atoi(argv[i+1]);
				if(cfg->repeat_count < 1){
					fprintf(stderr, "Error: --repeat argument must be >0.\n\n");
					return 1;
				}
			}
			i++;
		}else if(!strcmp(argv[i], "--repeat-delay")){
			if(pub_or_sub != CLIENT_PUB){
				goto unknown_option;
			}
			if(i==argc-1){
				fprintf(stderr, "Error: --repeat-delay argument given but no time specified.\n\n");
				return 1;
			}else{
				f = (float )atof(argv[i+1]);
				if(f < 0.0f){
					fprintf(stderr, "Error: --repeat-delay argument must be >=0.0.\n\n");
					return 1;
				}
				f *= 1.0e6f;
				cfg->repeat_delay.tv_sec = (int)f/1000000;
				cfg->repeat_delay.tv_usec = (int)f%1000000;
			}
			i++;
		}else if(!strcmp(argv[i], "--retain-as-published")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}
			cfg->sub_opts |= MQTT_SUB_OPT_RETAIN_AS_PUBLISHED;
		}else if(!strcmp(argv[i], "--retained-only")){
			if(pub_or_sub != CLIENT_SUB){
				goto unknown_option;
			}
			cfg->retained_only = true;
		}else if(!strcmp(argv[i], "-s") || !strcmp(argv[i], "--stdin-file")){
			if(pub_or_sub == CLIENT_SUB){
				goto unknown_option;
			}
			if(cfg->pub_mode != MSGMODE_NONE){
				fprintf(stderr, "Error: Only one type of message can be sent at once.\n\n");
				return 1;
			}else{ 
				cfg->pub_mode = MSGMODE_STDIN_FILE;
			}
#ifdef WITH_SRV
		}else if(!strcmp(argv[i], "-S")){
			cfg->use_srv = true;
#endif
		}else if(!strcmp(argv[i], "-t") || !strcmp(argv[i], "--topic")){
			if(i==argc-1){
				fprintf(stderr, "Error: -t argument given but no topic specified.\n\n");
				return 1;
			}else{
				if(cfg_add_topic(cfg, pub_or_sub, argv[i + 1], "-t"))
					return 1;
				i++;
			}
		}else if(!strcmp(argv[i], "-T") || !strcmp(argv[i], "--filter-out")){
			if(pub_or_sub != CLIENT_SUB){
				goto unknown_option;
			}
			if(i==argc-1){
				fprintf(stderr, "Error: -T argument given but no topic filter specified.\n\n");
				return 1;
			}else{
				if(mosquitto_validate_utf8(argv[i+1], (int )strlen(argv[i+1]))){
					fprintf(stderr, "Error: Malformed UTF-8 in -T argument.\n\n");
					return 1;
				}
				if(mosquitto_sub_topic_check(argv[i+1]) == MOSQ_ERR_INVAL){
					fprintf(stderr, "Error: Invalid filter topic '%s', are all '+' and '#' wildcards correct?\n", argv[i+1]);
					return 1;
				}
				cfg->filter_out_count++;
				cfg->filter_outs = realloc(cfg->filter_outs, (size_t )cfg->filter_out_count*sizeof(char *));
				if(!cfg->filter_outs){
					fprintf(stderr, "Error: Out of memory.\n");
					return 1;
				}
				cfg->filter_outs[cfg->filter_out_count-1] = strdup(argv[i+1]);
			}
			i++;
#ifdef WITH_TLS
		}else if(!strcmp(argv[i], "--tls-alpn")){
			if(i==argc-1){
				fprintf(stderr, "Error: --tls-alpn argument given but no protocol specified.\n\n");
				return 1;
			}else{
				cfg->tls_alpn = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "--tls-engine")){
			if(i==argc-1){
				fprintf(stderr, "Error: --tls-engine argument given but no engine_id specified.\n\n");
				return 1;
			}else{
				cfg->tls_engine = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "--tls-engine-kpass-sha1")){
			if(i==argc-1){
				fprintf(stderr, "Error: --tls-engine-kpass-sha1 argument given but no kpass sha1 specified.\n\n");
				return 1;
			}else{
				cfg->tls_engine_kpass_sha1 = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "--tls-use-os-certs")){
			cfg->tls_use_os_certs = true;
		}else if(!strcmp(argv[i], "--tls-version")){
			if(i==argc-1){
				fprintf(stderr, "Error: --tls-version argument given but no version specified.\n\n");
				return 1;
			}else{
				cfg->tls_version = strdup(argv[i+1]);
			}
			i++;
#endif
		}else if(!strcmp(argv[i], "-U") || !strcmp(argv[i], "--unsubscribe")){
			if(pub_or_sub != CLIENT_SUB){
				goto unknown_option;
			}
			if(i==argc-1){
				fprintf(stderr, "Error: -U argument given but no unsubscribe topic specified.\n\n");
				return 1;
			}else{
				if(mosquitto_validate_utf8(argv[i+1], (int )strlen(argv[i+1]))){
					fprintf(stderr, "Error: Malformed UTF-8 in -U argument.\n\n");
					return 1;
				}
				if(mosquitto_sub_topic_check(argv[i+1]) == MOSQ_ERR_INVAL){
					fprintf(stderr, "Error: Invalid unsubscribe topic '%s', are all '+' and '#' wildcards correct?\n", argv[i+1]);
					return 1;
				}
				cfg->unsub_topic_count++;
				cfg->unsub_topics = realloc(cfg->unsub_topics, (size_t )cfg->unsub_topic_count*sizeof(char *));
				if(!cfg->unsub_topics){
					fprintf(stderr, "Error: Out of memory.\n");
					return 1;
				}
				cfg->unsub_topics[cfg->unsub_topic_count-1] = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "-u") || !strcmp(argv[i], "--username")){
			if(i==argc-1){
				fprintf(stderr, "Error: -u argument given but no username specified.\n\n");
				return 1;
			}else{
				cfg->username = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "--unix")){
			if(i==argc-1){
				fprintf(stderr, "Error: --unix argument given but no socket path specified.\n\n");
				return 1;
			}else{
				cfg->host = strdup(argv[i+1]);
				cfg->port = 0;
			}
			i++;
		}else if(!strcmp(argv[i], "-V") || !strcmp(argv[i], "--protocol-version")){
			if(i==argc-1){
				fprintf(stderr, "Error: --protocol-version argument given but no version specified.\n\n");
				return 1;
			}else{
				if(!strcmp(argv[i+1], "mqttv31") || !strcmp(argv[i+1], "31")){
					cfg->protocol_version = MQTT_PROTOCOL_V31;
				}else if(!strcmp(argv[i+1], "mqttv311") || !strcmp(argv[i+1], "311")){
					cfg->protocol_version = MQTT_PROTOCOL_V311;
				}else if(!strcmp(argv[i+1], "mqttv5") || !strcmp(argv[i+1], "5")){
					cfg->protocol_version = MQTT_PROTOCOL_V5;
				}else{
					fprintf(stderr, "Error: Invalid protocol version argument given.\n\n");
					return 1;
				}
				i++;
			}
		}else if(!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}
			cfg->verbose = 1;
		}else if(!strcmp(argv[i], "--version")){
			return 3;
		}else if(!strcmp(argv[i], "-W")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}else{
				if(i==argc-1){
					fprintf(stderr, "Error: -W argument given but no timeout specified.\n\n");
					return 1;
				}else{
					tmpi = atoi(argv[i+1]);
					if(tmpi < 1){
						fprintf(stderr, "Error: Invalid timeout \"%d\".\n\n", tmpi);
						return 1;
					}
					cfg->timeout = (unsigned int )tmpi;
				}
				i++;
			}
		}else if(!strcmp(argv[i], "--will-payload")){
			if(i==argc-1){
				fprintf(stderr, "Error: --will-payload argument given but no will payload specified.\n\n");
				return 1;
			}else{
				cfg->will_payload = strdup(argv[i+1]);
				cfg->will_payloadlen = (int )strlen(cfg->will_payload);
			}
			i++;
		}else if(!strcmp(argv[i], "--will-qos")){
			if(i==argc-1){
				fprintf(stderr, "Error: --will-qos argument given but no will QoS specified.\n\n");
				return 1;
			}else{
				cfg->will_qos = atoi(argv[i+1]);
				if(cfg->will_qos < 0 || cfg->will_qos > 2){
					fprintf(stderr, "Error: Invalid will QoS %d.\n\n", cfg->will_qos);
					return 1;
				}
			}
			i++;
		}else if(!strcmp(argv[i], "--will-retain")){
			cfg->will_retain = true;
		}else if(!strcmp(argv[i], "--will-topic")){
			if(i==argc-1){
				fprintf(stderr, "Error: --will-topic argument given but no will topic specified.\n\n");
				return 1;
			}else{
				if(mosquitto_validate_utf8(argv[i+1], (int )strlen(argv[i+1]))){
					fprintf(stderr, "Error: Malformed UTF-8 in --will-topic argument.\n\n");
					return 1;
				}
				if(mosquitto_pub_topic_check(argv[i+1]) == MOSQ_ERR_INVAL){
					fprintf(stderr, "Error: Invalid will topic '%s', does it contain '+' or '#'?\n", argv[i+1]);
					return 1;
				}
				cfg->will_topic = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "-x")){
			if(i==argc-1){
				fprintf(stderr, "Error: -x argument given but no session expiry interval specified.\n\n");
				return 1;
			}else{
				if(!strcmp(argv[i+1], "∞")){
					cfg->session_expiry_interval = UINT32_MAX;
				}else{
					char *endptr = NULL;
					cfg->session_expiry_interval = strtol(argv[i+1], &endptr, 0);
					if(endptr == argv[i+1] || endptr[0] != '\0'){
						/* Entirety of argument wasn't a number */
						fprintf(stderr, "Error: session-expiry-interval not a number.\n\n");
						return 1;
					}
					if(cfg->session_expiry_interval > UINT32_MAX || cfg->session_expiry_interval < -1){
						fprintf(stderr, "Error: session-expiry-interval out of range.\n\n");
						return 1;
					}
					if(cfg->session_expiry_interval == -1){
						/* Convenience value for infinity. */
						cfg->session_expiry_interval = UINT32_MAX;
					}
				}
			}
			i++;
		}else{
			goto unknown_option;
		}
	}

	return MOSQ_ERR_SUCCESS;

unknown_option:
	fprintf(stderr, "Error: Unknown option '%s'.\n",argv[i]);
	return 1;
}

int client_opts_set(struct mosquitto *mosq, struct mosq_config *cfg)
{
#if defined(WITH_TLS) || defined(WITH_SOCKS)
	int rc;
#endif

	mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, cfg->protocol_version);

	if(cfg->will_topic && mosquitto_will_set_v5(mosq, cfg->will_topic,
				cfg->will_payloadlen, cfg->will_payload, cfg->will_qos,
				cfg->will_retain, cfg->will_props)){

		err_printf(cfg, "Error: Problem setting will.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
	cfg->will_props = NULL;

	if((cfg->username || cfg->password) && mosquitto_username_pw_set(mosq, cfg->username, cfg->password)){
		err_printf(cfg, "Error: Problem setting username and/or password.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#ifdef WITH_TLS
	if(cfg->cafile || cfg->capath){
		rc = mosquitto_tls_set(mosq, cfg->cafile, cfg->capath, cfg->certfile, cfg->keyfile, NULL);
		if(rc){
			if(rc == MOSQ_ERR_INVAL){
				err_printf(cfg, "Error: Problem setting TLS options: File not found.\n");
			}else{
				err_printf(cfg, "Error: Problem setting TLS options: %s.\n", mosquitto_strerror(rc));
			}
			mosquitto_lib_cleanup();
			return 1;
		}
	}else if(cfg->port == 8883){
		mosquitto_int_option(mosq, MOSQ_OPT_TLS_USE_OS_CERTS, 1);
	}
	if(cfg->tls_use_os_certs){
		mosquitto_int_option(mosq, MOSQ_OPT_TLS_USE_OS_CERTS, 1);
	}

	if(cfg->insecure && mosquitto_tls_insecure_set(mosq, true)){
		err_printf(cfg, "Error: Problem setting TLS insecure option.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
	if(cfg->tls_engine && mosquitto_string_option(mosq, MOSQ_OPT_TLS_ENGINE, cfg->tls_engine)){
		err_printf(cfg, "Error: Problem setting TLS engine, is %s a valid engine?\n", cfg->tls_engine);
		mosquitto_lib_cleanup();
		return 1;
	}
	if(cfg->keyform && mosquitto_string_option(mosq, MOSQ_OPT_TLS_KEYFORM, cfg->keyform)){
		err_printf(cfg, "Error: Problem setting key form, it must be one of 'pem' or 'engine'.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
	if(cfg->tls_engine_kpass_sha1 && mosquitto_string_option(mosq, MOSQ_OPT_TLS_ENGINE_KPASS_SHA1, cfg->tls_engine_kpass_sha1)){
		err_printf(cfg, "Error: Problem setting TLS engine key pass sha, is it a 40 character hex string?\n");
		mosquitto_lib_cleanup();
		return 1;
	}
	if(cfg->tls_alpn && mosquitto_string_option(mosq, MOSQ_OPT_TLS_ALPN, cfg->tls_alpn)){
		err_printf(cfg, "Error: Problem setting TLS ALPN protocol.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#  ifdef FINAL_WITH_TLS_PSK
	if(cfg->psk && mosquitto_tls_psk_set(mosq, cfg->psk, cfg->psk_identity, NULL)){
		err_printf(cfg, "Error: Problem setting TLS-PSK options.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#  endif
	if((cfg->tls_version || cfg->ciphers) && mosquitto_tls_opts_set(mosq, 1, cfg->tls_version, cfg->ciphers)){
		err_printf(cfg, "Error: Problem setting TLS options, check the options are valid.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#endif
	mosquitto_max_inflight_messages_set(mosq, cfg->max_inflight);
#ifdef WITH_SOCKS
	if(cfg->socks5_host){
		rc = mosquitto_socks5_set(mosq, cfg->socks5_host, cfg->socks5_port, cfg->socks5_username, cfg->socks5_password);
		if(rc){
			mosquitto_lib_cleanup();
			return rc;
		}
	}
#endif
	if(cfg->tcp_nodelay){
		mosquitto_int_option(mosq, MOSQ_OPT_TCP_NODELAY, 1);
	}
	return MOSQ_ERR_SUCCESS;
}

int client_id_generate(struct mosq_config *cfg)
{
	if(cfg->id_prefix){
		cfg->id = malloc(strlen(cfg->id_prefix)+10);
		if(!cfg->id){
			err_printf(cfg, "Error: Out of memory.\n");
			mosquitto_lib_cleanup();
			return 1;
		}
		snprintf(cfg->id, strlen(cfg->id_prefix)+10, "%s%d", cfg->id_prefix, getpid());
	}
	return MOSQ_ERR_SUCCESS;
}

int client_connect(struct mosquitto *mosq, struct mosq_config *cfg)
{
#ifndef WIN32
	char *err;
#else
	char err[1024];
#endif
	int rc;
	int port;

	if(cfg->port == PORT_UNDEFINED){
#ifdef WITH_TLS
		if(cfg->cafile || cfg->capath
#  ifdef FINAL_WITH_TLS_PSK
				|| cfg->psk
#  endif
				){
			port = 8883;
		}else
#endif
		{
			port = 1883;
		}
	}else{
		port = cfg->port;
	}

#ifdef WITH_SRV
	if(cfg->use_srv){
		rc = mosquitto_connect_srv(mosq, cfg->host, cfg->keepalive, cfg->bind_address);
	}else{
		rc = mosquitto_connect_bind_v5(mosq, cfg->host, port, cfg->keepalive, cfg->bind_address, cfg->connect_props);
	}
#else
	rc = mosquitto_connect_bind_v5(mosq, cfg->host, port, cfg->keepalive, cfg->bind_address, cfg->connect_props);
#endif
	if(rc>0){
		if(rc == MOSQ_ERR_ERRNO){
#ifndef WIN32
			err = strerror(errno);
#else
			FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, errno, 0, (LPTSTR)&err, 1024, NULL);
#endif
			err_printf(cfg, "Error: %s\n", err);
		}else{
			err_printf(cfg, "Unable to connect (%s).\n", mosquitto_strerror(rc));
		}
		mosquitto_lib_cleanup();
		return rc;
	}
	return MOSQ_ERR_SUCCESS;
}

#ifdef WITH_SOCKS
/* Convert %25 -> %, %3a, %3A -> :, %40 -> @ */
static int mosquitto__urldecode(char *str)
{
	int i, j;
	size_t len;
	if(!str) return 0;

	if(!strchr(str, '%')) return 0;

	len = strlen(str);
	for(i=0; i<len; i++){
		if(str[i] == '%'){
			if(i+2 >= len){
				return 1;
			}
			if(str[i+1] == '2' && str[i+2] == '5'){
				str[i] = '%';
				len -= 2;
				for(j=i+1; j<len; j++){
					str[j] = str[j+2];
				}
				str[j] = '\0';
			}else if(str[i+1] == '3' && (str[i+2] == 'A' || str[i+2] == 'a')){
				str[i] = ':';
				len -= 2;
				for(j=i+1; j<len; j++){
					str[j] = str[j+2];
				}
				str[j] = '\0';
			}else if(str[i+1] == '4' && str[i+2] == '0'){
				str[i] = ':';
				len -= 2;
				for(j=i+1; j<len; j++){
					str[j] = str[j+2];
				}
				str[j] = '\0';
			}else{
				return 1;
			}
		}
	}
	return 0;
}

static int mosquitto__parse_socks_url(struct mosq_config *cfg, char *url)
{
	char *str;
	size_t i;
	char *username = NULL, *password = NULL, *host = NULL, *port = NULL;
	char *username_or_host = NULL;
	size_t start;
	size_t len;
	bool have_auth = false;
	int port_int;

	if(!strncmp(url, "socks5h://", strlen("socks5h://"))){
		str = url + strlen("socks5h://");
	}else{
		err_printf(cfg, "Error: Unsupported proxy protocol: %s\n", url);
		return 1;
	}

	// socks5h://username:password@host:1883
	// socks5h://username:password@host
	// socks5h://username@host:1883
	// socks5h://username@host
	// socks5h://host:1883
	// socks5h://host

	start = 0;
	for(i=0; i<strlen(str); i++){
		if(str[i] == ':'){
			if(i == start){
				goto cleanup;
			}
			if(have_auth){
				/* Have already seen a @ , so this must be of form
				 * socks5h://username[:password]@host:port */
				if(host){
					/* Already seen a host, must be malformed. */
					goto cleanup;
				}
				len = i-start;
				host = malloc(len + 1);
				if(!host){
					err_printf(cfg, "Error: Out of memory.\n");
					goto cleanup;
				}
				memcpy(host, &(str[start]), len);
				host[len] = '\0';
				start = i+1;
			}else if(!username_or_host){
				/* Haven't seen a @ before, so must be of form
				 * socks5h://host:port or
				 * socks5h://username:password@host[:port] */
				len = i-start;
				username_or_host = malloc(len + 1);
				if(!username_or_host){
					err_printf(cfg, "Error: Out of memory.\n");
					goto cleanup;
				}
				memcpy(username_or_host, &(str[start]), len);
				username_or_host[len] = '\0';
				start = i+1;
			}
		}else if(str[i] == '@'){
			if(i == start){
				goto cleanup;
			}
			have_auth = true;
			if(username_or_host){
				/* Must be of form socks5h://username:password@... */
				username = username_or_host;
				username_or_host = NULL;

				len = i-start;
				password = malloc(len + 1);
				if(!password){
					err_printf(cfg, "Error: Out of memory.\n");
					goto cleanup;
				}
				memcpy(password, &(str[start]), len);
				password[len] = '\0';
				start = i+1;
			}else{
				/* Haven't seen a : yet, so must be of form
				 * socks5h://username@... */
				if(username){
					/* Already got a username, must be malformed. */
					goto cleanup;
				}
				len = i-start;
				username = malloc(len + 1);
				if(!username){
					err_printf(cfg, "Error: Out of memory.\n");
					goto cleanup;
				}
				memcpy(username, &(str[start]), len);
				username[len] = '\0';
				start = i+1;
			}
		}
	}

	/* Deal with remainder */
	if(i > start){
		len = i-start;
		if(host){
			/* Have already seen a @ , so this must be of form
			 * socks5h://username[:password]@host:port */
			port = malloc(len + 1);
			if(!port){
				err_printf(cfg, "Error: Out of memory.\n");
				goto cleanup;
			}
			memcpy(port, &(str[start]), len);
			port[len] = '\0';
		}else if(username_or_host){
			/* Haven't seen a @ before, so must be of form
			 * socks5h://host:port */
			host = username_or_host;
			username_or_host = NULL;
			port = malloc(len + 1);
			if(!port){
				err_printf(cfg, "Error: Out of memory.\n");
				goto cleanup;
			}
			memcpy(port, &(str[start]), len);
			port[len] = '\0';
		}else{
			host = malloc(len + 1);
			if(!host){
				err_printf(cfg, "Error: Out of memory.\n");
				goto cleanup;
			}
			memcpy(host, &(str[start]), len);
			host[len] = '\0';
		}
	}

	if(!host){
		err_printf(cfg, "Error: Invalid proxy.\n");
		goto cleanup;
	}

	if(mosquitto__urldecode(username)){
		goto cleanup;
	}
	if(mosquitto__urldecode(password)){
		goto cleanup;
	}
	if(port){
		port_int = atoi(port);
		if(port_int < 1 || port_int > 65535){
			err_printf(cfg, "Error: Invalid proxy port %d\n", port_int);
			goto cleanup;
		}
		free(port);
	}else{
		port_int = 1080;
	}

	cfg->socks5_username = username;
	cfg->socks5_password = password;
	cfg->socks5_host = host;
	cfg->socks5_port = port_int;

	return 0;
cleanup:
	free(username_or_host);
	free(username);
	free(password);
	free(host);
	free(port);
	return 1;
}
#endif

void err_printf(const struct mosq_config *cfg, const char *fmt, ...)
{
	va_list va;

	if(cfg->quiet) return;

	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
}

