/*
Copyright (c) 2024 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mosquitto_signal.h"

#ifndef PATH_MAX
#  define PATH_MAX 4096
#endif


void signal_all(enum mosq_signal sig)
{
	DIR *dir;
	struct dirent *d;
	char pathbuf[PATH_MAX+1];
	char cmdline[256];
	const char *cmd;
	FILE *fptr;
	pid_t pid;

	dir = opendir("/proc");
	if(dir == NULL){
		fprintf(stderr, "Error reading /proc: %s.\n", strerror(errno));
		return;
	}

	while((d = readdir(dir))){
#ifdef DT_DIR
		if(d->d_type == DT_DIR)
#endif
		{
			pid = atoi(d->d_name);
			if(pid > 0){
				snprintf(pathbuf, sizeof(pathbuf), "/proc/%s/cmdline", d->d_name);
				fptr = fopen(pathbuf, "r");
				if(fptr){
					if(fgets(cmdline, sizeof(cmdline), fptr)){
						cmd = strrchr(cmdline, '/');
						if(cmd){
							cmd += 1;
						}else{
							cmd = cmdline;
						}
						if(!strcmp(cmd, "mosquitto")){
							if(kill(pid, sig) < 0){
								fprintf(stderr, "Unable to signal process %d: %s\n", pid, strerror(errno));
							}
						}
					}
					fclose(fptr);
				}
			}
		}
	}

	closedir(dir);
}


void send_signal(int pid, enum mosq_signal msig)
{
	int sig;

	switch(msig){
		case MSIG_CONFIG_RELOAD:
			sig = SIGHUP;
			break;
		case MSIG_LOG_ROTATE:
			sig = SIGHUP;
			break;
		case MSIG_SHUTDOWN:
			sig = SIGINT;
			break;
		case MSIG_TREE_PRINT:
			sig = SIGUSR2;
			break;
#ifdef SIGRTMIN
		case MSIG_XTREPORT:
			sig = SIGRTMIN;
			break;
#endif
		default:
			return;
	}

	if(pid > 0){
		if(kill(pid, sig) != 0){
			fprintf(stderr, "Error sending signal to process %d: %s\n", pid, strerror(errno));
		}
	}else{
		signal_all(sig);
	}
}
