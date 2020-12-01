/*
Copyright (c) 2011-2020 Roger Light <roger@atchoo.org>

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

#if defined(WIN32) || defined(__CYGWIN__)

#include "config.h"

#include <windows.h>

#include "memory_mosq.h"

extern int run;
SERVICE_STATUS_HANDLE service_handle = 0;
static SERVICE_STATUS service_status;
int main(int argc, char *argv[]);

static void print_error(void)
{
	char *buf;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL, GetLastError(), LANG_NEUTRAL, (LPTSTR)&buf, 0, NULL);

	fprintf(stderr, "Error: %s\n", buf);
	LocalFree(buf);
}


/* Service control callback */
void __stdcall service_handler(DWORD fdwControl)
{
	switch(fdwControl){
		case SERVICE_CONTROL_CONTINUE:
			/* Continue from Paused state. */
			break;
		case SERVICE_CONTROL_PAUSE:
			/* Pause service. */
			break;
		case SERVICE_CONTROL_SHUTDOWN:
			/* System is shutting down. */
		case SERVICE_CONTROL_STOP:
			/* Service should stop. */
			service_status.dwCurrentState = SERVICE_STOP_PENDING;
			SetServiceStatus(service_handle, &service_status);
			run = 0;
			break;
	}
}

/* Function called when started as a service. */
void __stdcall service_main(DWORD dwArgc, LPTSTR *lpszArgv)
{
	char **argv;
	int argc = 1;
	char conf_path[MAX_PATH + 20];
	int rc;

	service_handle = RegisterServiceCtrlHandler("mosquitto", service_handler);
	if(service_handle){
		memset(conf_path, 0, sizeof(conf_path));
		rc = GetEnvironmentVariable("MOSQUITTO_DIR", conf_path, MAX_PATH);
		if(!rc || rc == MAX_PATH){
			service_status.dwCurrentState = SERVICE_STOPPED;
			SetServiceStatus(service_handle, &service_status);
			return;
		}
		strcat(conf_path, "/mosquitto.conf");

		argv = mosquitto__malloc(sizeof(char *)*3);
		argv[0] = "mosquitto";
		argv[1] = "-c";
		argv[2] = conf_path;
		argc = 3;

		service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
		service_status.dwCurrentState = SERVICE_RUNNING;
		service_status.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_STOP;
		service_status.dwWin32ExitCode = NO_ERROR;
		service_status.dwCheckPoint = 0;
		SetServiceStatus(service_handle, &service_status);

		main(argc, argv);
		mosquitto__free(argv);

		service_status.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(service_handle, &service_status);
	}
}

void service_install(void)
{
	SC_HANDLE sc_manager, svc_handle;
	char service_string[MAX_PATH + 20];
	char exe_path[MAX_PATH + 1];
	SERVICE_DESCRIPTION svc_desc;

	memset(exe_path, 0, sizeof(exe_path));
	if(GetModuleFileName(NULL, exe_path, MAX_PATH) == MAX_PATH){
		fprintf(stderr, "Error: Path too long.\n");
		return;
	}
	snprintf(service_string, sizeof(service_string), "\"%s\" run", exe_path);

	sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if(sc_manager){
		svc_handle = CreateService(sc_manager, "mosquitto", "Mosquitto Broker", 
				SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG,
				SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
				service_string, NULL, NULL, NULL, NULL, NULL);

		if(svc_handle){
			svc_desc.lpDescription = "Eclipse Mosquitto MQTT v5/v3.1.1 broker";
			ChangeServiceConfig2(svc_handle, SERVICE_CONFIG_DESCRIPTION, &svc_desc);
			CloseServiceHandle(svc_handle);
		}else{
			print_error();
		}
		CloseServiceHandle(sc_manager);
	} else {
		print_error();
	}
}

void service_uninstall(void)
{
	SC_HANDLE sc_manager, svc_handle;
	SERVICE_STATUS status;

	sc_manager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
	if(sc_manager){
		svc_handle = OpenService(sc_manager, "mosquitto", SERVICE_QUERY_STATUS | DELETE);
		if(svc_handle){
			if(QueryServiceStatus(svc_handle, &status)){
				if(status.dwCurrentState == SERVICE_STOPPED){
					DeleteService(svc_handle);
				}
			}
			CloseServiceHandle(svc_handle);
		}else{
			print_error();
		}
		CloseServiceHandle(sc_manager);
	}else{
		print_error();
	}
}

void service_run(void)
{
	SERVICE_TABLE_ENTRY ste[] = {
		{ "mosquitto", service_main },
		{ NULL, NULL }
	};

	StartServiceCtrlDispatcher(ste);
}

#endif
