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
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mosquitto_signal.h"

#undef WITH_TLS
#include "config.h"


static const char *msig_to_string(enum mosq_signal msig)
{
	switch(msig){
		case MSIG_CONFIG_RELOAD:
			return "reload";
		case MSIG_LOG_ROTATE:
			return "log_rotate";
		case MSIG_SHUTDOWN:
			return "shutdown";
		case MSIG_TREE_PRINT:
			return "tree_print";
		case MSIG_XTREPORT:
			return "xtreport";
		default:
			return "";
	}
}


void signal_all(enum mosq_signal msig)
{
	DWORD processes[2048], cbneeded, count;
	int pid;

	if(!EnumProcesses(processes, sizeof(processes), &cbneeded)){
		fprintf(stderr, "Error enumerating processes.\n");
		return;
	}

	count = cbneeded / sizeof(DWORD);
	for(DWORD i=0; i<count; i++){
		if(processes[i]){
			HANDLE hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
			if(hproc){
				HMODULE hmod;
				char procname[MAX_PATH];
				if(EnumProcessModules(hproc, &hmod, sizeof(hmod), &cbneeded)){
					GetModuleBaseName(hproc, hmod, procname, sizeof(procname));
					if(!strcasecmp(procname, "mosquitto.exe")){
						pid = GetProcessId(hproc);
						send_signal(pid, msig);
					}
				}
				CloseHandle(hproc);
			}
		}
	}
}


void send_signal(int pid, enum mosq_signal msig)
{
	HANDLE evt;
	char eventbuf[MAX_PATH+1];
	BOOL res;

	snprintf(eventbuf, sizeof(eventbuf), "mosq%d_%s", pid, msig_to_string(msig));
	evt = OpenEvent(EVENT_MODIFY_STATE, FALSE, eventbuf);
	if(evt){
		res = PulseEvent(evt);
		CloseHandle(evt);
	}
}
