/*
Copyright (c) 2016-2018 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
   Dmitry Kaukov - windows named events implementation.
*/

#include "config.h"

#ifndef WIN32
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
#include "util_mosq.h"

extern bool flag_reload;
#ifdef WITH_PERSISTENCE
extern bool flag_db_backup;
#endif
extern bool flag_tree_print;
extern int run;

#ifdef SIGHUP
/* Signal handler for SIGHUP - flag a config reload. */
void handle_sighup(int signal)
{
	flag_reload = true;
}
#endif

/* Signal handler for SIGINT and SIGTERM - just stop gracefully. */
void handle_sigint(int signal)
{
	run = 0;
}

/* Signal handler for SIGUSR1 - backup the db. */
void handle_sigusr1(int signal)
{
#ifdef WITH_PERSISTENCE
	flag_db_backup = true;
#endif
}

/* Signal handler for SIGUSR2 - print subscription / retained tree. */
void handle_sigusr2(int signal)
{
	flag_tree_print = true;
}

/*
 *
 * Signalling mosquitto process on Win32.
 *
 *  On Windows we we can use named events to pass signals to the mosquitto process.
 *  List of events :
 *
 *    mosqPID_shutdown
 *    mosqPID_reload
 *    mosqPID_backup
 *
 * (where PID is the PID of the mosquitto process).
 */
#ifdef WIN32
DWORD WINAPI SigThreadProc(void* data)
{
	TCHAR evt_name[MAX_PATH];
	static HANDLE evt[3];
	int pid = GetCurrentProcessId();

	sprintf_s(evt_name, MAX_PATH, "mosq%d_shutdown", pid);
	evt[0] = CreateEvent(NULL, TRUE, FALSE, evt_name);
	sprintf_s(evt_name, MAX_PATH, "mosq%d_reload", pid);
	evt[1] = CreateEvent(NULL, FALSE, FALSE, evt_name);
	sprintf_s(evt_name, MAX_PATH, "mosq%d_backup", pid);
	evt[2] = CreateEvent(NULL, FALSE, FALSE, evt_name);

	while (true) {
		int wr = WaitForMultipleObjects(sizeof(evt) / sizeof(HANDLE), evt, FALSE, INFINITE);
		switch (wr) {
			case WAIT_OBJECT_0 + 0:
				handle_sigint(SIGINT);
				break;
			case WAIT_OBJECT_0 + 1:
				flag_reload = true;
				continue;
			case WAIT_OBJECT_0 + 2:
				handle_sigusr1(0);
				continue;
				break;
		}
	}
	CloseHandle(evt[0]);
	CloseHandle(evt[1]);
	CloseHandle(evt[2]);
	return 0;
}
#endif

