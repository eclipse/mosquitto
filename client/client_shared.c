/*
Copyright (c) 2014 Roger Light <roger@atchoo.org>

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


#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#else
#include <process.h>
#include <winsock2.h>
#define snprintf sprintf_s
#endif

#include <mosquitto.h>
#include "client_shared.h"

static int mosquitto__parse_socks_url(struct mosq_config *cfg, char *url);
static int client_config_line_proc(struct mosq_config *cfg, int pub_or_sub, int argc, char *argv[]);

void init_config(struct mosq_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->port = 1883;
	cfg->max_inflight = 20;
	cfg->keepalive = 60;
	cfg->clean_session = true;
	cfg->eol = true;
	cfg->protocol_version = MQTT_PROTOCOL_V31;
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
#ifdef WITH_TLS
	free(cfg->cafile);
	free(cfg->capath);
	free(cfg->certfile);
	free(cfg->keyfile);
	free(cfg->ciphers);
	free(cfg->tls_version);
#  ifdef WITH_TLS_PSK
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
#ifdef WITH_SOCKS
	free(cfg->socks5_host);
	free(cfg->socks5_username);
	free(cfg->socks5_password);
#endif
}

int client_config_load(struct mosq_config *cfg, int pub_or_sub, int argc, char *argv[])
{
	int rc;
	FILE *fptr;
	char line[1024];
	int count;
	char *loc = NULL;
	int len;
	char *args[3];

#ifndef WIN32
	char *env;
#else
	char env[1024];
#endif
	args[0] = NULL;

	init_config(cfg);

	/* Default config file */
#ifndef WIN32
	env = getenv("XDG_CONFIG_HOME");
	if(env){
		len = strlen(env) + strlen("/mosquitto_pub") + 1;
		loc = malloc(len);
		if(!loc){
			fprintf(stderr, "Error: Out of memory.\n");
			return 1;
		}
		if(pub_or_sub == CLIENT_PUB){
			snprintf(loc, len, "%s/mosquitto_pub", env);
		}else{
			snprintf(loc, len, "%s/mosquitto_sub", env);
		}
		loc[len-1] = '\0';
	}else{
		env = getenv("HOME");
		if(env){
			len = strlen(env) + strlen("/.config/mosquitto_pub") + 1;
			loc = malloc(len);
			if(!loc){
				fprintf(stderr, "Error: Out of memory.\n");
				return 1;
			}
			if(pub_or_sub == CLIENT_PUB){
				snprintf(loc, len, "%s/.config/mosquitto_pub", env);
			}else{
				snprintf(loc, len, "%s/.config/mosquitto_sub", env);
			}
			loc[len-1] = '\0';
		}else{
			fprintf(stderr, "Warning: Unable to locate configuration directory, default config not loaded.\n");
		}
	}

#else
	rc = GetEnvironmentVariable("USERPROFILE", env, 1024);
	if(rc > 0 && rc < 1024){
		len = strlen(env) + strlen("\\mosquitto_pub.conf") + 1;
		loc = malloc(len);
		if(!loc){
			fprintf(stderr, "Error: Out of memory.\n");
			return 1;
		}
		if(pub_or_sub == CLIENT_PUB){
			snprintf(loc, len, "%s\\mosquitto_pub.conf", env);
		}else{
			snprintf(loc, len, "%s\\mosquitto_sub.conf", env);
		}
		loc[len-1] = '\0';
	}else{
		fprintf(stderr, "Warning: Unable to locate configuration directory, default config not loaded.\n");
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
	if(cfg->password && !cfg->username){
		if(!cfg->quiet) fprintf(stderr, "Warning: Not using password since username not set.\n");
	}
#ifdef WITH_TLS
	if((cfg->certfile && !cfg->keyfile) || (cfg->keyfile && !cfg->certfile)){
		fprintf(stderr, "Error: Both certfile and keyfile must be provided if one of them is.\n");
		return 1;
	}
#endif
#ifdef WITH_TLS_PSK
	if((cfg->cafile || cfg->capath) && cfg->psk){
		if(!cfg->quiet) fprintf(stderr, "Error: Only one of --psk or --cafile/--capath may be used at once.\n");
		return 1;
	}
	if(cfg->psk && !cfg->psk_identity){
		if(!cfg->quiet) fprintf(stderr, "Error: --psk-identity required if --psk used.\n");
		return 1;
	}
#endif

	if(pub_or_sub == CLIENT_SUB){
		if(cfg->clean_session == false && (cfg->id_prefix || !cfg->id)){
			if(!cfg->quiet) fprintf(stderr, "Error: You must provide a client id if you are using the -c option.\n");
			return 1;
		}
		if(cfg->topic_count == 0){
			if(!cfg->quiet) fprintf(stderr, "Error: You must specify a topic to subscribe to.\n");
			return 1;
		}
	}

	if(!cfg->host){
		cfg->host = "localhost";
	}
	return MOSQ_ERR_SUCCESS;
}

/* Process a tokenised single line from a file or set of real argc/argv */
int client_config_line_proc(struct mosq_config *cfg, int pub_or_sub, int argc, char *argv[])
{
	int i;

	for(i=1; i<argc; i++){
		if(!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")){
			if(i==argc-1){
				fprintf(stderr, "Error: -p argument given but no port specified.\n\n");
				return 1;
			}else{
				cfg->port = atoi(argv[i+1]);
				if(cfg->port<1 || cfg->port>65535){
					fprintf(stderr, "Error: Invalid port given: %d\n", cfg->port);
					return 1;
				}
			}
			i++;
		}else if(!strcmp(argv[i], "-A")){
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
			if(pub_or_sub == CLIENT_PUB){
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
		}else if(!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")){
			cfg->debug = true;
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
				if(cfg->keepalive>65535){
					fprintf(stderr, "Error: Invalid keepalive given: %d\n", cfg->keepalive);
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
#endif
		}else if(!strcmp(argv[i], "-l") || !strcmp(argv[i], "--stdin-line")){
			if(pub_or_sub == CLIENT_SUB){
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
				cfg->msglen = strlen(cfg->message);
				cfg->pub_mode = MSGMODE_CMD;
			}
			i++;
		}else if(!strcmp(argv[i], "-M")){
			if(i==argc-1){
				fprintf(stderr, "Error: -M argument given but max_inflight not specified.\n\n");
				return 1;
			}else{
				cfg->max_inflight = atoi(argv[i+1]);
			}
			i++;
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
		}else if(!strcmp(argv[i], "-V") || !strcmp(argv[i], "--protocol-version")){
			if(i==argc-1){
				fprintf(stderr, "Error: --protocol-version argument given but no version specified.\n\n");
				return 1;
			}else{
				if(!strcmp(argv[i+1], "mqttv31")){
					cfg->protocol_version = MQTT_PROTOCOL_V31;
				}else if(!strcmp(argv[i+1], "mqttv311")){
					cfg->protocol_version = MQTT_PROTOCOL_V311;
				}else{
					fprintf(stderr, "Error: Invalid protocol version argument given.\n\n");
					return 1;
				}
				i++;
			}
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
#ifdef WITH_TLS_PSK
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
			if(pub_or_sub == CLIENT_SUB){
				goto unknown_option;
			}
			cfg->retain = 1;
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
				if(pub_or_sub == CLIENT_PUB){
					if(mosquitto_pub_topic_check(argv[i+1]) == MOSQ_ERR_INVAL){
						fprintf(stderr, "Error: Invalid publish topic '%s', does it contain '+' or '#'?\n", argv[i+1]);
						return 1;
					}
					cfg->topic = strdup(argv[i+1]);
				}else{
					if(mosquitto_sub_topic_check(argv[i+1]) == MOSQ_ERR_INVAL){
						fprintf(stderr, "Error: Invalid subscription topic '%s', are all '+' and '#' wildcards correct?\n", argv[i+1]);
						return 1;
					}
					cfg->topic_count++;
					cfg->topics = realloc(cfg->topics, cfg->topic_count*sizeof(char *));
					cfg->topics[cfg->topic_count-1] = strdup(argv[i+1]);
				}
				i++;
			}
		}else if(!strcmp(argv[i], "-T") || !strcmp(argv[i], "--filter-out")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}
			if(i==argc-1){
				fprintf(stderr, "Error: -T argument given but no topic filter specified.\n\n");
				return 1;
			}else{
				if(mosquitto_sub_topic_check(argv[i+1]) == MOSQ_ERR_INVAL){
					fprintf(stderr, "Error: Invalid filter topic '%s', are all '+' and '#' wildcards correct?\n", argv[i+1]);
					return 1;
				}
				cfg->filter_out_count++;
				cfg->filter_outs = realloc(cfg->filter_outs, cfg->filter_out_count*sizeof(char *));
				cfg->filter_outs[cfg->filter_out_count-1] = strdup(argv[i+1]);
			}
			i++;
#ifdef WITH_TLS
		}else if(!strcmp(argv[i], "--tls-version")){
			if(i==argc-1){
				fprintf(stderr, "Error: --tls-version argument given but no version specified.\n\n");
				return 1;
			}else{
				cfg->tls_version = strdup(argv[i+1]);
			}
			i++;
#endif
		}else if(!strcmp(argv[i], "-u") || !strcmp(argv[i], "--username")){
			if(i==argc-1){
				fprintf(stderr, "Error: -u argument given but no username specified.\n\n");
				return 1;
			}else{
				cfg->username = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "-P") || !strcmp(argv[i], "--pw")){
			if(i==argc-1){
				fprintf(stderr, "Error: -P argument given but no password specified.\n\n");
				return 1;
			}else{
				cfg->password = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "--will-payload")){
			if(i==argc-1){
				fprintf(stderr, "Error: --will-payload argument given but no will payload specified.\n\n");
				return 1;
			}else{
				cfg->will_payload = strdup(argv[i+1]);
				cfg->will_payloadlen = strlen(cfg->will_payload);
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
				if(mosquitto_pub_topic_check(argv[i+1]) == MOSQ_ERR_INVAL){
					fprintf(stderr, "Error: Invalid will topic '%s', does it contain '+' or '#'?\n", argv[i+1]);
					return 1;
				}
				cfg->will_topic = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "-c") || !strcmp(argv[i], "--disable-clean-session")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}
			cfg->clean_session = false;
		}else if(!strcmp(argv[i], "-N")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}
			cfg->eol = false;
		}else if(!strcmp(argv[i], "-R")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}
			cfg->no_retain = true;
		}else if(!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}
			cfg->verbose = 1;
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
	int rc;

	if(cfg->will_topic && mosquitto_will_set(mosq, cfg->will_topic,
				cfg->will_payloadlen, cfg->will_payload, cfg->will_qos,
				cfg->will_retain)){

		if(!cfg->quiet) fprintf(stderr, "Error: Problem setting will.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
	if(cfg->username && mosquitto_username_pw_set(mosq, cfg->username, cfg->password)){
		if(!cfg->quiet) fprintf(stderr, "Error: Problem setting username and password.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#ifdef WITH_TLS
	if((cfg->cafile || cfg->capath)
			&& mosquitto_tls_set(mosq, cfg->cafile, cfg->capath, cfg->certfile, cfg->keyfile, NULL)){

		if(!cfg->quiet) fprintf(stderr, "Error: Problem setting TLS options.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
	if(cfg->insecure && mosquitto_tls_insecure_set(mosq, true)){
		if(!cfg->quiet) fprintf(stderr, "Error: Problem setting TLS insecure option.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#  ifdef WITH_TLS_PSK
	if(cfg->psk && mosquitto_tls_psk_set(mosq, cfg->psk, cfg->psk_identity, NULL)){
		if(!cfg->quiet) fprintf(stderr, "Error: Problem setting TLS-PSK options.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#  endif
	if((cfg->tls_version || cfg->ciphers) && mosquitto_tls_opts_set(mosq, 1, cfg->tls_version, cfg->ciphers)){
		if(!cfg->quiet) fprintf(stderr, "Error: Problem setting TLS options.\n");
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
	mosquitto_opts_set(mosq, MOSQ_OPT_PROTOCOL_VERSION, &(cfg->protocol_version));
	return MOSQ_ERR_SUCCESS;
}

int client_id_generate(struct mosq_config *cfg, const char *id_base)
{
	int len;
	char hostname[256];

	if(cfg->id_prefix){
		cfg->id = malloc(strlen(cfg->id_prefix)+10);
		if(!cfg->id){
			if(!cfg->quiet) fprintf(stderr, "Error: Out of memory.\n");
			mosquitto_lib_cleanup();
			return 1;
		}
		snprintf(cfg->id, strlen(cfg->id_prefix)+10, "%s%d", cfg->id_prefix, getpid());
	}else if(!cfg->id){
		hostname[0] = '\0';
		gethostname(hostname, 256);
		hostname[255] = '\0';
		len = strlen(id_base) + strlen("|-") + 6 + strlen(hostname);
		cfg->id = malloc(len);
		if(!cfg->id){
			if(!cfg->quiet) fprintf(stderr, "Error: Out of memory.\n");
			mosquitto_lib_cleanup();
			return 1;
		}
		snprintf(cfg->id, len, "%s|%d-%s", id_base, getpid(), hostname);
		if(strlen(cfg->id) > MOSQ_MQTT_ID_MAX_LENGTH){
			/* Enforce maximum client id length of 23 characters */
			cfg->id[MOSQ_MQTT_ID_MAX_LENGTH] = '\0';
		}
	}
	return MOSQ_ERR_SUCCESS;
}

int client_connect(struct mosquitto *mosq, struct mosq_config *cfg)
{
	char err[1024];
	int rc;

#ifdef WITH_SRV
	if(cfg->use_srv){
		rc = mosquitto_connect_srv(mosq, cfg->host, cfg->keepalive, cfg->bind_address);
	}else{
		rc = mosquitto_connect_bind(mosq, cfg->host, cfg->port, cfg->keepalive, cfg->bind_address);
	}
#else
	rc = mosquitto_connect_bind(mosq, cfg->host, cfg->port, cfg->keepalive, cfg->bind_address);
#endif
	if(rc>0){
		if(!cfg->quiet){
			if(rc == MOSQ_ERR_ERRNO){
#ifndef WIN32
				strerror_r(errno, err, 1024);
#else
				FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, errno, 0, (LPTSTR)&err, 1024, NULL);
#endif
				fprintf(stderr, "Error: %s\n", err);
			}else{
				fprintf(stderr, "Unable to connect (%s).\n", mosquitto_strerror(rc));
			}
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
	int len;
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
	int i;
	char *username = NULL, *password = NULL, *host = NULL, *port = NULL;
	char *username_or_host = NULL;
	int start;
	int len;
	bool have_auth = false;
	int port_int;

	if(!strncmp(url, "socks5h://", strlen("socks5h://"))){
		str = url + strlen("socks5h://");
	}else{
		fprintf(stderr, "Error: Unsupported proxy protocol: %s\n", url);
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
				memcpy(host, &(str[start]), len);
				host[len] = '\0';
				start = i+1;
			}else if(!username_or_host){
				/* Haven't seen a @ before, so must be of form
				 * socks5h://host:port or
				 * socks5h://username:password@host[:port] */
				len = i-start;
				username_or_host = malloc(len + 1);
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
			memcpy(port, &(str[start]), len);
			port[len] = '\0';
		}else if(username_or_host){
			/* Haven't seen a @ before, so must be of form
			 * socks5h://host:port */
			host = username_or_host;
			username_or_host = NULL;
			port = malloc(len + 1);
			memcpy(port, &(str[start]), len);
			port[len] = '\0';
		}else{
			host = malloc(len + 1);
			if(!host){
				fprintf(stderr, "Error: Out of memory.\n");
				goto cleanup;
			}
			memcpy(host, &(str[start]), len);
			host[len] = '\0';
		}
	}

	if(!host){
		fprintf(stderr, "Error: Invalid proxy.\n");
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
			fprintf(stderr, "Error: Invalid proxy port %d\n", port_int);
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
	if(username_or_host) free(username_or_host);
	if(username) free(username);
	if(password) free(password);
	if(host) free(host);
	if(port) free(port);
	return 1;
}

#endif
