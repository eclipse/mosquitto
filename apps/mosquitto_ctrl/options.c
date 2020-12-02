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
#include "mosquitto_ctrl.h"
#include "get_password.h"

#ifdef WITH_SOCKS
static int mosquitto__parse_socks_url(struct mosq_config *cfg, char *url);
#endif
static int client_config_line_proc(struct mosq_config *cfg, int *argc, char **argvp[]);


void init_config(struct mosq_config *cfg)
{
	cfg->qos = 1;
	cfg->port = PORT_UNDEFINED;
	cfg->protocol_version = MQTT_PROTOCOL_V5;
}

void client_config_cleanup(struct mosq_config *cfg)
{
	free(cfg->id);
	free(cfg->host);
	free(cfg->bind_address);
	free(cfg->username);
	free(cfg->password);
	free(cfg->options_file);
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
#ifdef WITH_SOCKS
	free(cfg->socks5_host);
	free(cfg->socks5_username);
	free(cfg->socks5_password);
#endif
}

int ctrl_config_parse(struct mosq_config *cfg, int *argc, char **argv[])
{
	int rc;

	init_config(cfg);

	/* Deal with real argc/argv */
	rc = client_config_line_proc(cfg, argc, argv);
	if(rc) return rc;

	rc = client_config_load(cfg);
	if(rc) return rc;

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

	if(!cfg->host){
		cfg->host = strdup("localhost");
		if(!cfg->host){
			fprintf(stderr, "Error: Out of memory.\n");
			return 1;
		}
	}

	return MOSQ_ERR_SUCCESS;
}

/* Process a tokenised single line from a file or set of real argc/argv */
static int client_config_line_proc(struct mosq_config *cfg, int *argc, char **argvp[])
{
	char **argv = *argvp;

	while((*argc) && argv[0][0] == '-'){
		if(!strcmp(argv[0], "-A")){
			if((*argc) == 1){
				fprintf(stderr, "Error: -A argument given but no address specified.\n\n");
				return 1;
			}else{
				cfg->bind_address = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
#ifdef WITH_TLS
		}else if(!strcmp(argv[0], "--cafile")){
			if((*argc) == 1){
				fprintf(stderr, "Error: --cafile argument given but no file specified.\n\n");
				return 1;
			}else{
				cfg->cafile = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
		}else if(!strcmp(argv[0], "--capath")){
			if((*argc) == 1){
				fprintf(stderr, "Error: --capath argument given but no directory specified.\n\n");
				return 1;
			}else{
				cfg->capath = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
		}else if(!strcmp(argv[0], "--cert")){
			if((*argc) == 1){
				fprintf(stderr, "Error: --cert argument given but no file specified.\n\n");
				return 1;
			}else{
				cfg->certfile = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
		}else if(!strcmp(argv[0], "--ciphers")){
			if((*argc) == 1){
				fprintf(stderr, "Error: --ciphers argument given but no ciphers specified.\n\n");
				return 1;
			}else{
				cfg->ciphers = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
#endif
		}else if(!strcmp(argv[0], "-d") || !strcmp(argv[0], "--debug")){
			cfg->debug = true;
		}else if(!strcmp(argv[0], "--help")){
			return 2;
		}else if(!strcmp(argv[0], "-h") || !strcmp(argv[0], "--host")){
			if((*argc) == 1){
				fprintf(stderr, "Error: -h argument given but no host specified.\n\n");
				return 1;
			}else{
				cfg->host = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
#ifdef WITH_TLS
		}else if(!strcmp(argv[0], "--insecure")){
			cfg->insecure = true;
#endif
		}else if(!strcmp(argv[0], "-i") || !strcmp(argv[0], "--id")){
			if((*argc) == 1){
				fprintf(stderr, "Error: -i argument given but no id specified.\n\n");
				return 1;
			}else{
				cfg->id = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
#ifdef WITH_TLS
		}else if(!strcmp(argv[0], "--key")){
			if((*argc) == 1){
				fprintf(stderr, "Error: --key argument given but no file specified.\n\n");
				return 1;
			}else{
				cfg->keyfile = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
		}else if(!strcmp(argv[0], "--keyform")){
			if((*argc) == 1){
				fprintf(stderr, "Error: --keyform argument given but no keyform specified.\n\n");
				return 1;
			}else{
				cfg->keyform = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
#endif
		}else if(!strcmp(argv[0], "-L") || !strcmp(argv[0], "--url")){
			if((*argc) == 1){
				fprintf(stderr, "Error: -L argument given but no URL specified.\n\n");
				return 1;
			} else {
				char *url = argv[1];
				char *topic;
				char *tmp;

				if(!strncasecmp(url, "mqtt://", 7)) {
					url += 7;
					cfg->port = 1883;
				} else if(!strncasecmp(url, "mqtts://", 8)) {
					url += 8;
					cfg->port = 8883;
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
			argv++;
			(*argc)--;
		}else if(!strcmp(argv[0], "-o")){
			if((*argc) == 1){
				fprintf(stderr, "Error: -o argument given but no options file specified.\n\n");
				return 1;
			}else{
				cfg->options_file = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
		}else if(!strcmp(argv[0], "-p") || !strcmp(argv[0], "--port")){
			if((*argc) == 1){
				fprintf(stderr, "Error: -p argument given but no port specified.\n\n");
				return 1;
			}else{
				cfg->port = atoi(argv[1]);
				if(cfg->port<0 || cfg->port>65535){
					fprintf(stderr, "Error: Invalid port given: %d\n", cfg->port);
					return 1;
				}
			}
			argv++;
			(*argc)--;
		}else if(!strcmp(argv[0], "-P") || !strcmp(argv[0], "--pw")){
			if((*argc) == 1){
				fprintf(stderr, "Error: -P argument given but no password specified.\n\n");
				return 1;
			}else{
				cfg->password = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
#ifdef WITH_SOCKS
		}else if(!strcmp(argv[0], "--proxy")){
			if((*argc) == 1){
				fprintf(stderr, "Error: --proxy argument given but no proxy url specified.\n\n");
				return 1;
			}else{
				if(mosquitto__parse_socks_url(cfg, argv[1])){
					return 1;
				}
			}
			argv++;
			(*argc)--;
#endif
#ifdef FINAL_WITH_TLS_PSK
		}else if(!strcmp(argv[0], "--psk")){
			if((*argc) == 1){
				fprintf(stderr, "Error: --psk argument given but no key specified.\n\n");
				return 1;
			}else{
				cfg->psk = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
		}else if(!strcmp(argv[0], "--psk-identity")){
			if((*argc) == 1){
				fprintf(stderr, "Error: --psk-identity argument given but no identity specified.\n\n");
				return 1;
			}else{
				cfg->psk_identity = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
#endif
		}else if(!strcmp(argv[0], "-q") || !strcmp(argv[0], "--qos")){
			if((*argc) == 1){
				fprintf(stderr, "Error: -q argument given but no QoS specified.\n\n");
				return 1;
			}else{
				cfg->qos = atoi(argv[1]);
				if(cfg->qos<0 || cfg->qos>2){
					fprintf(stderr, "Error: Invalid QoS given: %d\n", cfg->qos);
					return 1;
				}
			}
			argv++;
			(*argc)--;
		}else if(!strcmp(argv[0], "--quiet")){
			cfg->quiet = true;
#ifdef WITH_TLS
		}else if(!strcmp(argv[0], "--tls-alpn")){
			if((*argc) == 1){
				fprintf(stderr, "Error: --tls-alpn argument given but no protocol specified.\n\n");
				return 1;
			}else{
				cfg->tls_alpn = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
		}else if(!strcmp(argv[0], "--tls-engine")){
			if((*argc) == 1){
				fprintf(stderr, "Error: --tls-engine argument given but no engine_id specified.\n\n");
				return 1;
			}else{
				cfg->tls_engine = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
		}else if(!strcmp(argv[0], "--tls-engine-kpass-sha1")){
			if((*argc) == 1){
				fprintf(stderr, "Error: --tls-engine-kpass-sha1 argument given but no kpass sha1 specified.\n\n");
				return 1;
			}else{
				cfg->tls_engine_kpass_sha1 = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
		}else if(!strcmp(argv[0], "--tls-version")){
			if((*argc) == 1){
				fprintf(stderr, "Error: --tls-version argument given but no version specified.\n\n");
				return 1;
			}else{
				cfg->tls_version = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
#endif
		}else if(!strcmp(argv[0], "-u") || !strcmp(argv[0], "--username")){
			if((*argc) == 1){
				fprintf(stderr, "Error: -u argument given but no username specified.\n\n");
				return 1;
			}else{
				cfg->username = strdup(argv[1]);
			}
			argv++;
			(*argc)--;
		}else if(!strcmp(argv[0], "--unix")){
			if((*argc) == 1){
				fprintf(stderr, "Error: --unix argument given but no socket path specified.\n\n");
				return 1;
			}else{
				cfg->host = strdup(argv[1]);
				cfg->port = 0;
			}
			argv++;
			(*argc)--;
		}else if(!strcmp(argv[0], "-V") || !strcmp(argv[0], "--protocol-version")){
			if((*argc) == 1){
				fprintf(stderr, "Error: --protocol-version argument given but no version specified.\n\n");
				return 1;
			}else{
				if(!strcmp(argv[1], "mqttv31") || !strcmp(argv[1], "31")){
					cfg->protocol_version = MQTT_PROTOCOL_V31;
				}else if(!strcmp(argv[1], "mqttv311") || !strcmp(argv[1], "311")){
					cfg->protocol_version = MQTT_PROTOCOL_V311;
				}else if(!strcmp(argv[1], "mqttv5") || !strcmp(argv[1], "5")){
					cfg->protocol_version = MQTT_PROTOCOL_V5;
				}else{
					fprintf(stderr, "Error: Invalid protocol version argument given.\n\n");
					return 1;
				}
			}
			argv++;
			(*argc)--;
		}else if(!strcmp(argv[0], "-v") || !strcmp(argv[0], "--verbose")){
			cfg->verbose = 1;
		}else if(!strcmp(argv[0], "--version")){
			return 3;
		}else{
			goto unknown_option;
		}
		argv++;
		(*argc)--;
	}
	*argvp = argv;

	return MOSQ_ERR_SUCCESS;

unknown_option:
	fprintf(stderr, "Error: Unknown option '%s'.\n",argv[0]);
	return 1;
}

static char *get_default_cfg_location(void)
{
	char *loc = NULL;
	size_t len;
#ifndef WIN32
	char *env;
#else
	char env[1024];
	int rc;
#endif

#ifndef WIN32
	env = getenv("XDG_CONFIG_HOME");
	if(env){
		len = strlen(env) + strlen("/mosquitto_ctrl") + 1;
		loc = malloc(len);
		if(!loc){
			fprintf(stderr, "Error: Out of memory.\n");
			return NULL;
		}
		snprintf(loc, len, "%s/mosquitto_ctrl", env);
		loc[len-1] = '\0';
	}else{
		env = getenv("HOME");
		if(env){
			len = strlen(env) + strlen("/.config/mosquitto_ctrl") + 1;
			loc = malloc(len);
			if(!loc){
				fprintf(stderr, "Error: Out of memory.\n");
				return NULL;
			}
			snprintf(loc, len, "%s/.config/mosquitto_ctrl", env);
			loc[len-1] = '\0';
		}
	}

#else
	rc = GetEnvironmentVariable("USERPROFILE", env, 1024);
	if(rc > 0 && rc < 1024){
		len = strlen(env) + strlen("\\mosquitto_ctrl.conf") + 1;
		loc = malloc(len);
		if(!loc){
			fprintf(stderr, "Error: Out of memory.\n");
			return NULL;
		}
		snprintf(loc, len, "%s\\mosquitto_ctrl.conf", env);
		loc[len-1] = '\0';
	}
#endif
	return loc;
}

int client_config_load(struct mosq_config *cfg)
{
	int rc;
	FILE *fptr = NULL;
	char line[1024];
	int count;
	char **local_args, **args;
	char *default_cfg;

	if(cfg->options_file){
		fptr = fopen(cfg->options_file, "rt");
	}else{
		default_cfg = get_default_cfg_location();
		if(default_cfg){
			fptr = fopen(default_cfg, "rt");
			free(default_cfg);
		}
	}

	if(fptr){
		local_args = malloc(3*sizeof(char *));
		if(local_args == NULL){
			fprintf(stderr, "Error: Out of memory.\n");
			fclose(fptr);
			return 1;
		}
		while(fgets(line, 1024, fptr)){
			if(line[0] == '#') continue; /* Comments */

			while(line[strlen(line)-1] == 10 || line[strlen(line)-1] == 13){
				line[strlen(line)-1] = 0;
			}
			local_args[0] = strtok(line, " ");
			if(local_args[0]){
				local_args[1] = strtok(NULL, " ");
				if(local_args[1]){
					count = 2;
				}else{
					count = 1;
				}
				args = local_args;
				rc = client_config_line_proc(cfg, &count, &args);
				if(rc){
					fclose(fptr);
					free(local_args);
					return rc;
				}
			}
		}
		fclose(fptr);
		free(local_args);
	}
	return 0;
}


int client_opts_set(struct mosquitto *mosq, struct mosq_config *cfg)
{
	int rc;
	char prompt[1000];
	char password[1000];

	mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, cfg->protocol_version);

	if(cfg->username && cfg->password == NULL){
		/* Ask for password */
		snprintf(prompt, sizeof(prompt), "Password for %s: ", cfg->username);
		rc = get_password(prompt, NULL, false, password, sizeof(password));
		if(rc){
			fprintf(stderr, "Error getting password.\n");
			mosquitto_lib_cleanup();
			return 1;
		}
		cfg->password = strdup(password);
		if(cfg->password == NULL){
			fprintf(stderr, "Error: Out of memory.\n");
			mosquitto_lib_cleanup();
			return 1;
		}
	}

	if((cfg->username || cfg->password) && mosquitto_username_pw_set(mosq, cfg->username, cfg->password)){
		fprintf(stderr, "Error: Problem setting username and/or password.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#ifdef WITH_TLS
	if(cfg->cafile || cfg->capath){
		rc = mosquitto_tls_set(mosq, cfg->cafile, cfg->capath, cfg->certfile, cfg->keyfile, NULL);
		if(rc){
			if(rc == MOSQ_ERR_INVAL){
				fprintf(stderr, "Error: Problem setting TLS options: File not found.\n");
			}else{
				fprintf(stderr, "Error: Problem setting TLS options: %s.\n", mosquitto_strerror(rc));
			}
			mosquitto_lib_cleanup();
			return 1;
		}
	}
	if(cfg->insecure && mosquitto_tls_insecure_set(mosq, true)){
		fprintf(stderr, "Error: Problem setting TLS insecure option.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
	if(cfg->tls_engine && mosquitto_string_option(mosq, MOSQ_OPT_TLS_ENGINE, cfg->tls_engine)){
		fprintf(stderr, "Error: Problem setting TLS engine, is %s a valid engine?\n", cfg->tls_engine);
		mosquitto_lib_cleanup();
		return 1;
	}
	if(cfg->keyform && mosquitto_string_option(mosq, MOSQ_OPT_TLS_KEYFORM, cfg->keyform)){
		fprintf(stderr, "Error: Problem setting key form, it must be one of 'pem' or 'engine'.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
	if(cfg->tls_engine_kpass_sha1 && mosquitto_string_option(mosq, MOSQ_OPT_TLS_ENGINE_KPASS_SHA1, cfg->tls_engine_kpass_sha1)){
		fprintf(stderr, "Error: Problem setting TLS engine key pass sha, is it a 40 character hex string?\n");
		mosquitto_lib_cleanup();
		return 1;
	}
	if(cfg->tls_alpn && mosquitto_string_option(mosq, MOSQ_OPT_TLS_ALPN, cfg->tls_alpn)){
		fprintf(stderr, "Error: Problem setting TLS ALPN protocol.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#  ifdef FINAL_WITH_TLS_PSK
	if(cfg->psk && mosquitto_tls_psk_set(mosq, cfg->psk, cfg->psk_identity, NULL)){
		fprintf(stderr, "Error: Problem setting TLS-PSK options.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#  endif
	if((cfg->tls_version || cfg->ciphers) && mosquitto_tls_opts_set(mosq, 1, cfg->tls_version, cfg->ciphers)){
		fprintf(stderr, "Error: Problem setting TLS options, check the options are valid.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#endif
#ifdef WITH_SOCKS
	if(cfg->socks5_host){
		rc = mosquitto_socks5_set(mosq, cfg->socks5_host, cfg->socks5_port, cfg->socks5_username, cfg->socks5_password);
		if(rc){
			mosquitto_lib_cleanup();
			return rc;
		}
	}
#endif
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

	rc = mosquitto_connect_bind_v5(mosq, cfg->host, port, 60, cfg->bind_address, NULL);
	if(rc>0){
		if(rc == MOSQ_ERR_ERRNO){
#ifndef WIN32
			err = strerror(errno);
#else
			FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, errno, 0, (LPTSTR)&err, 1024, NULL);
#endif
			fprintf(stderr, "Error: %s\n", err);
		}else{
			fprintf(stderr, "Unable to connect (%s).\n", mosquitto_strerror(rc));
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
				if(!host){
					fprintf(stderr, "Error: Out of memory.\n");
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
					fprintf(stderr, "Error: Out of memory.\n");
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
					fprintf(stderr, "Error: Out of memory.\n");
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
					fprintf(stderr, "Error: Out of memory.\n");
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
				fprintf(stderr, "Error: Out of memory.\n");
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
				fprintf(stderr, "Error: Out of memory.\n");
				goto cleanup;
			}
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
	free(username_or_host);
	free(username);
	free(password);
	free(host);
	free(port);
	return 1;
}
#endif
