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

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef WIN32
#else
#  include <dirent.h>
#endif

#ifndef WIN32
#  include <strings.h>
#  include <netdb.h>
#  include <sys/socket.h>
#else
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif

#if !defined(WIN32) && !defined(__CYGWIN__) && !defined(__QNX__)
#  include <sys/syslog.h>
#endif

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "tls_mosq.h"
#include "util_mosq.h"
#include "mqtt_protocol.h"


int scmp_p(const void *p1, const void *p2)
{
	const char *s1 = *(const char **)p1;
	const char *s2 = *(const char **)p2;
	int result;

	while(s1[0] && s2[0]){
		/* Sort by case insensitive part first */
		result = toupper(s1[0]) - toupper(s2[0]);
		if(result == 0){
			/* Case insensitive part matched, now distinguish between case */
			result = s1[0] - s2[0];
			if(result != 0){
				return result;
			}
		}else{
			/* Return case insensitive match fail */
			return result;
		}
		s1++;
		s2++;
	}

	return s1[0] - s2[0];
}

#ifdef WIN32
int config__get_dir_files(const char *include_dir, char ***files, int *file_count)
{
	int len;
	int i;
	char **l_files = NULL;
	int l_file_count = 0;
	char **files_tmp;

	HANDLE fh;
	char dirpath[MAX_PATH];
	WIN32_FIND_DATA find_data;

	snprintf(dirpath, MAX_PATH, "%s\\*.conf", include_dir);
	fh = FindFirstFile(dirpath, &find_data);
	if(fh == INVALID_HANDLE_VALUE){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open include_dir '%s'.", include_dir);
		return 1;
	}

	do{
		len = strlen(include_dir)+1+strlen(find_data.cFileName)+1;

		l_file_count++;
		files_tmp = mosquitto__realloc(l_files, l_file_count*sizeof(char *));
		if(!files_tmp){
			for(i=0; i<l_file_count-1; i++){
				mosquitto__free(l_files[i]);
			}
			mosquitto__free(l_files);
			FindClose(fh);
			return MOSQ_ERR_NOMEM;
		}
		l_files = files_tmp;

		l_files[l_file_count-1] = mosquitto__malloc(len+1);
		if(!l_files[l_file_count-1]){
			for(i=0; i<l_file_count-1; i++){
				mosquitto__free(l_files[i]);
			}
			mosquitto__free(l_files);
			FindClose(fh);
			return MOSQ_ERR_NOMEM;
		}
		snprintf(l_files[l_file_count-1], len, "%s/%s", include_dir, find_data.cFileName);
		l_files[l_file_count-1][len] = '\0';
	}while(FindNextFile(fh, &find_data));

	FindClose(fh);

	if(l_files){
		qsort(l_files, l_file_count, sizeof(char *), scmp_p);
	}
	*files = l_files;
	*file_count = l_file_count;

	return 0;
}
#endif


#ifndef WIN32

int config__get_dir_files(const char *include_dir, char ***files, int *file_count)
{
	char **l_files = NULL;
	int l_file_count = 0;
	char **files_tmp;
	size_t len;
	int i;

	DIR *dh;
	struct dirent *de;

	dh = opendir(include_dir);
	if(!dh){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open include_dir '%s'.", include_dir);
		return 1;
	}
	while((de = readdir(dh)) != NULL){
		if(strlen(de->d_name) > 5){
			if(!strcmp(&de->d_name[strlen(de->d_name)-5], ".conf")){
				len = strlen(include_dir)+1+strlen(de->d_name)+1;

				l_file_count++;
				files_tmp = mosquitto__realloc(l_files, (size_t)l_file_count*sizeof(char *));
				if(!files_tmp){
					for(i=0; i<l_file_count-1; i++){
						mosquitto__free(l_files[i]);
					}
					mosquitto__free(l_files);
					closedir(dh);
					return MOSQ_ERR_NOMEM;
				}
				l_files = files_tmp;

				l_files[l_file_count-1] = mosquitto__malloc(len+1);
				if(!l_files[l_file_count-1]){
					for(i=0; i<l_file_count-1; i++){
						mosquitto__free(l_files[i]);
					}
					mosquitto__free(l_files);
					closedir(dh);
					return MOSQ_ERR_NOMEM;
				}
				snprintf(l_files[l_file_count-1], len, "%s/%s", include_dir, de->d_name);
				l_files[l_file_count-1][len] = '\0';
			}
		}
	}
	closedir(dh);

	if(l_files){
		qsort(l_files, (size_t)l_file_count, sizeof(char *), scmp_p);
	}
	*files = l_files;
	*file_count = l_file_count;

	return 0;
}
#endif


