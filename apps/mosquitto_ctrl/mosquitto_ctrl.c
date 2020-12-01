/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>

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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib_load.h"
#include "mosquitto.h"
#include "mosquitto_ctrl.h"

void print_version(void)
{
	int major, minor, revision;

	mosquitto_lib_version(&major, &minor, &revision);
	printf("mosquitto_ctrl version %s running on libmosquitto %d.%d.%d.\n", VERSION, major, minor, revision);
}

void print_usage(void)
{
	printf("mosquitto_ctrl is a tool for administering certain Mosquitto features.\n");
	print_version();
	printf("\nGeneral usage: mosquitto_ctrl <module> <module-command> <command-options>\n");
	printf("For module specific help use: mosquitto_ctrl <module> help\n");
	printf("\nModules available: dynsec\n");
	printf("\nSee https://mosquitto.org/man/mosquitto_ctrl-1.html for more information.\n\n");
}


int main(int argc, char *argv[])
{
	struct mosq_ctrl ctrl;
	int rc = MOSQ_ERR_SUCCESS;
	FUNC_ctrl_main ctrl_main = NULL;
	void *lib = NULL;
	char lib_name[200];

	if(argc == 1){
		print_usage();
		return 1;
	}

	memset(&ctrl, 0, sizeof(ctrl));
	init_config(&ctrl.cfg);

	/* Shift program name out of args */
	argc--;
	argv++;

	ctrl_config_parse(&ctrl.cfg, &argc, &argv);

	if(argc < 2){
		print_usage();
		return 1;
	}
 
	/* In built modules */
	if(!strcasecmp(argv[0], "dynsec")){
		ctrl_main = dynsec__main;
	}else{
		/* Attempt external module */
		snprintf(lib_name, sizeof(lib_name), "mosquitto_ctrl_%s.so", argv[0]);
		lib = LIB_LOAD(lib_name);
		if(lib){
			ctrl_main = (FUNC_ctrl_main)LIB_SYM(lib, "ctrl_main");
		}
	}
	if(ctrl_main == NULL){
		fprintf(stderr, "Error: Module '%s' not supported.\n", argv[0]);
		rc = MOSQ_ERR_NOT_SUPPORTED;
	}

	if(ctrl_main){
		rc = ctrl_main(argc-1, &argv[1], &ctrl);
		if(rc < 0){
			/* Usage print */
			rc = 0;
		}else if(rc == MOSQ_ERR_SUCCESS){
			rc = client_request_response(&ctrl);
		}else if(rc == MOSQ_ERR_UNKNOWN){
			/* Message printed already */
		}else{
			fprintf(stderr, "Error: %s\n", mosquitto_strerror(rc));
		}
	}

	client_config_cleanup(&ctrl.cfg);
	return rc;
}
