/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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

#include "config.h"

#ifndef WIN32
/* For initgroups() */
#  include <unistd.h>
#  include <grp.h>
#  include <assert.h>
#endif

#ifndef WIN32
#include <pwd.h>
#else
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifndef WIN32
#  include <sys/time.h>
#endif

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#ifdef WITH_SYSTEMD
#  include <systemd/sd-daemon.h>
#endif
#ifdef WITH_WRAP
#include <tcpd.h>
#endif
#ifdef WITH_WEBSOCKETS
#  include <libwebsockets.h>
#endif

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "misc_mosq.h"
#include "util_mosq.h"

struct mosquitto_db int_db;

bool flag_reload = false;
#ifdef WITH_PERSISTENCE
bool flag_db_backup = false;
#endif
bool flag_tree_print = false;
int run;
#ifdef WITH_WRAP
#include <syslog.h>
int allow_severity = LOG_INFO;
int deny_severity = LOG_INFO;
#endif

void handle_sigint(int signal);
void handle_sigusr1(int signal);
void handle_sigusr2(int signal);
#ifdef SIGHUP
void handle_sighup(int signal);
#endif

struct mosquitto_db *mosquitto__get_db(void)
{
	return &int_db;
}

/* mosquitto shouldn't run as root.
 * This function will attempt to change to an unprivileged user and group if
 * running as root. The user is given in config->user.
 * Returns 1 on failure (unknown user, setuid/setgid failure)
 * Returns 0 on success.
 * Note that setting config->user to "root" does not produce an error, but it
 * strongly discouraged.
 */
int drop_privileges(struct mosquitto__config *config, bool temporary)
{
#if !defined(__CYGWIN__) && !defined(WIN32)
	struct passwd *pwd;
	char *err;
	int rc;

	const char *snap = getenv("SNAP_NAME");
	if(snap && !strcmp(snap, "mosquitto")){
		/* Don't attempt to drop privileges if running as a snap */
		return MOSQ_ERR_SUCCESS;
	}

	if(geteuid() == 0){
		if(config->user && strcmp(config->user, "root")){
			pwd = getpwnam(config->user);
			if(!pwd){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid user '%s'.", config->user);
				return 1;
			}
			if(initgroups(config->user, pwd->pw_gid) == -1){
				err = strerror(errno);
				log__printf(NULL, MOSQ_LOG_ERR, "Error setting groups whilst dropping privileges: %s.", err);
				return 1;
			}
			if(temporary){
				rc = setegid(pwd->pw_gid);
			}else{
				rc = setgid(pwd->pw_gid);
			}
			if(rc == -1){
				err = strerror(errno);
				log__printf(NULL, MOSQ_LOG_ERR, "Error setting gid whilst dropping privileges: %s.", err);
				return 1;
			}
			if(temporary){
				rc = seteuid(pwd->pw_uid);
			}else{
				rc = setuid(pwd->pw_uid);
			}
			if(rc == -1){
				err = strerror(errno);
				log__printf(NULL, MOSQ_LOG_ERR, "Error setting uid whilst dropping privileges: %s.", err);
				return 1;
			}
		}
		if(geteuid() == 0 || getegid() == 0){
			log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Mosquitto should not be run as root/administrator.");
		}
	}
#endif
	return MOSQ_ERR_SUCCESS;
}

int restore_privileges(void)
{
#if !defined(__CYGWIN__) && !defined(WIN32)
	char *err;
	int rc;

	if(getuid() == 0){
		rc = setegid(0);
		if(rc == -1){
			err = strerror(errno);
			log__printf(NULL, MOSQ_LOG_ERR, "Error setting gid whilst restoring privileges: %s.", err);
			return 1;
		}
		rc = seteuid(0);
		if(rc == -1){
			err = strerror(errno);
			log__printf(NULL, MOSQ_LOG_ERR, "Error setting uid whilst restoring privileges: %s.", err);
			return 1;
		}
	}
#endif
	return MOSQ_ERR_SUCCESS;
}


void mosquitto__daemonise(void)
{
#ifndef WIN32
	char *err;
	pid_t pid;

	pid = fork();
	if(pid < 0){
		err = strerror(errno);
		log__printf(NULL, MOSQ_LOG_ERR, "Error in fork: %s", err);
		exit(1);
	}
	if(pid > 0){
		exit(0);
	}
	if(setsid() < 0){
		err = strerror(errno);
		log__printf(NULL, MOSQ_LOG_ERR, "Error in setsid: %s", err);
		exit(1);
	}

	assert(freopen("/dev/null", "r", stdin));
	assert(freopen("/dev/null", "w", stdout));
	assert(freopen("/dev/null", "w", stderr));
#else
	log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Can't start in daemon mode in Windows.");
#endif
}


int main(int argc, char *argv[])
{
	mosq_sock_t *listensock = NULL;
	int listensock_count = 0;
	int listensock_index = 0;
	struct mosquitto__config config;
	int i, j;
	FILE *pid;
	int rc;
#ifdef WIN32
	SYSTEMTIME st;
#else
	struct timeval tv;
#endif
	struct mosquitto *ctxt, *ctxt_tmp;

#if defined(WIN32) || defined(__CYGWIN__)
	if(argc == 2){
		if(!strcmp(argv[1], "run")){
			service_run();
			return 0;
		}else if(!strcmp(argv[1], "install")){
			service_install();
			return 0;
		}else if(!strcmp(argv[1], "uninstall")){
			service_uninstall();
			return 0;
		}
	}
#endif


#ifdef WIN32
	GetSystemTime(&st);
	srand(st.wSecond + st.wMilliseconds);
#else
	gettimeofday(&tv, NULL);
	srand(tv.tv_sec + tv.tv_usec);
#endif

#ifdef WIN32
	_setmaxstdio(2048);
#endif

	memset(&int_db, 0, sizeof(struct mosquitto_db));

	net__broker_init();

	config__init(&int_db, &config);
	rc = config__parse_args(&int_db, &config, argc, argv);
	if(rc != MOSQ_ERR_SUCCESS) return rc;
	int_db.config = &config;

	if(config.daemon){
		mosquitto__daemonise();
	}

	if(config.daemon && config.pid_file){
		pid = mosquitto__fopen(config.pid_file, "wt", false);
		if(pid){
			fprintf(pid, "%d", getpid());
			fclose(pid);
		}else{
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to write pid file.");
			return 1;
		}
	}

	rc = db__open(&config, &int_db);
	if(rc != MOSQ_ERR_SUCCESS){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Couldn't open database.");
		return rc;
	}

	/* Initialise logging only after initialising the database in case we're
	 * logging to topics */
	if(log__init(&config)){
		rc = 1;
		return rc;
	}
	log__printf(NULL, MOSQ_LOG_INFO, "mosquitto version %s starting", VERSION);
	if(int_db.config_file){
		log__printf(NULL, MOSQ_LOG_INFO, "Config loaded from %s.", int_db.config_file);
	}else{
		log__printf(NULL, MOSQ_LOG_INFO, "Using default config.");
	}

	rc = mosquitto_security_module_init(&int_db);
	if(rc) return rc;
	rc = mosquitto_security_init(&int_db, false);
	if(rc) return rc;

#ifdef WITH_SYS_TREE
	sys_tree__init(&int_db);
#endif

	listensock_index = 0;
	for(i=0; i<config.listener_count; i++){
		if(config.listeners[i].protocol == mp_mqtt){
			if(net__socket_listen(&config.listeners[i])){
				db__close(&int_db);
				if(config.pid_file){
					remove(config.pid_file);
				}
				return 1;
			}
			listensock_count += config.listeners[i].sock_count;
			listensock = mosquitto__realloc(listensock, sizeof(mosq_sock_t)*listensock_count);
			if(!listensock){
				db__close(&int_db);
				if(config.pid_file){
					remove(config.pid_file);
				}
				return 1;
			}
			for(j=0; j<config.listeners[i].sock_count; j++){
				if(config.listeners[i].socks[j] == INVALID_SOCKET){
					db__close(&int_db);
					if(config.pid_file){
						remove(config.pid_file);
					}
					return 1;
				}
				listensock[listensock_index] = config.listeners[i].socks[j];
				listensock_index++;
			}
		}else if(config.listeners[i].protocol == mp_websockets){
#ifdef WITH_WEBSOCKETS
			config.listeners[i].ws_context = mosq_websockets_init(&config.listeners[i], &config);
			if(!config.listeners[i].ws_context){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to create websockets listener on port %d.", config.listeners[i].port);
				return 1;
			}
#endif
		}
	}
	if(listensock == NULL){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to start any listening sockets, exiting.");
		return 1;
	}

	rc = drop_privileges(&config, false);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	signal(SIGINT, handle_sigint);
	signal(SIGTERM, handle_sigint);
#ifdef SIGHUP
	signal(SIGHUP, handle_sighup);
#endif
#ifndef WIN32
	signal(SIGUSR1, handle_sigusr1);
	signal(SIGUSR2, handle_sigusr2);
	signal(SIGPIPE, SIG_IGN);
#endif
#ifdef WIN32
	CreateThread(NULL, 0, SigThreadProc, NULL, 0, NULL);
#endif

#ifdef WITH_BRIDGE
	for(i=0; i<config.bridge_count; i++){
		if(bridge__new(&int_db, &(config.bridges[i]))){
			log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Unable to connect to bridge %s.", 
					config.bridges[i].name);
		}
	}
#endif

	log__printf(NULL, MOSQ_LOG_INFO, "mosquitto version %s running", VERSION);
#ifdef WITH_SYSTEMD
	sd_notify(0, "READY=1");
#endif

	run = 1;
	rc = mosquitto_main_loop(&int_db, listensock, listensock_count);

	log__printf(NULL, MOSQ_LOG_INFO, "mosquitto version %s terminating", VERSION);

#ifdef WITH_WEBSOCKETS
	for(i=0; i<int_db.config->listener_count; i++){
		if(int_db.config->listeners[i].ws_context){
			libwebsocket_context_destroy(int_db.config->listeners[i].ws_context);
		}
		mosquitto__free(int_db.config->listeners[i].ws_protocol);
	}
#endif

	/* FIXME - this isn't quite right, all wills with will delay zero should be
	 * sent now, but those with positive will delay should be persisted and
	 * restored, pending the client reconnecting in time. */
	HASH_ITER(hh_id, int_db.contexts_by_id, ctxt, ctxt_tmp){
		context__send_will(&int_db, ctxt);
	}
	will_delay__send_all(&int_db);

#ifdef WITH_PERSISTENCE
	if(config.persistence){
		persist__backup(&int_db, true);
	}
#endif
	session_expiry__remove_all(&int_db);

	HASH_ITER(hh_id, int_db.contexts_by_id, ctxt, ctxt_tmp){
#ifdef WITH_WEBSOCKETS
		if(!ctxt->wsi){
			context__cleanup(&int_db, ctxt, true);
		}
#else
		context__cleanup(&int_db, ctxt, true);
#endif
	}
	HASH_ITER(hh_sock, int_db.contexts_by_sock, ctxt, ctxt_tmp){
		context__cleanup(&int_db, ctxt, true);
	}
#ifdef WITH_BRIDGE
	for(i=0; i<int_db.bridge_count; i++){
		if(int_db.bridges[i]){
			context__cleanup(&int_db, int_db.bridges[i], true);
		}
	}
	mosquitto__free(int_db.bridges);
#endif
	context__free_disused(&int_db);

	db__close(&int_db);

	for(i=0; i<listensock_count; i++){
		if(listensock[i] != INVALID_SOCKET){
#ifndef WIN32
			close(listensock[i]);
#else
			closesocket(listensock[i]);
#endif
		}
	}
	mosquitto__free(listensock);

	mosquitto_security_module_cleanup(&int_db);

	if(config.pid_file){
		remove(config.pid_file);
	}

	log__close(&config);
	config__cleanup(int_db.config);
	net__broker_cleanup();

	return rc;
}

#ifdef WIN32
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	char **argv;
	int argc = 1;
	char *token;
	char *saveptr = NULL;
	int rc;

	argv = mosquitto__malloc(sizeof(char *)*1);
	argv[0] = "mosquitto";
	token = strtok_r(lpCmdLine, " ", &saveptr);
	while(token){
		argc++;
		argv = mosquitto__realloc(argv, sizeof(char *)*argc);
		if(!argv){
			fprintf(stderr, "Error: Out of memory.\n");
			return MOSQ_ERR_NOMEM;
		}
		argv[argc-1] = token;
		token = strtok_r(NULL, " ", &saveptr);
	}
	rc = main(argc, argv);
	mosquitto__free(argv);
	return rc;
}
#endif
