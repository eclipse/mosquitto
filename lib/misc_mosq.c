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

/* This contains general purpose utility functions that are not specific to
 * Mosquitto/MQTT features. */

#include "config.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#  include <winsock2.h>
#  include <aclapi.h>
#  include <io.h>
#  include <lmcons.h>
#else
#  include <sys/stat.h>
#endif


FILE *mosquitto__fopen(const char *path, const char *mode, bool restrict_read)
{
#ifdef WIN32
	char buf[4096];
	int rc;
	rc = ExpandEnvironmentStringsA(path, buf, 4096);
	if(rc == 0 || rc > 4096){
		return NULL;
	}else{
		if (restrict_read) {
			HANDLE hfile;
			SECURITY_ATTRIBUTES sec;
			EXPLICIT_ACCESS_A ea;
			PACL pacl = NULL;
			char username[UNLEN + 1];
			DWORD ulen = UNLEN;
			SECURITY_DESCRIPTOR sd;
			DWORD dwCreationDisposition;

			switch(mode[0]){
				case 'a':
					dwCreationDisposition = OPEN_ALWAYS;
					break;
				case 'r':
					dwCreationDisposition = OPEN_EXISTING;
					break;
				case 'w':
					dwCreationDisposition = CREATE_ALWAYS;
					break;
				default:
					return NULL;
			}

			GetUserNameA(username, &ulen);
			if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
				return NULL;
			}
			BuildExplicitAccessWithNameA(&ea, username, GENERIC_ALL, SET_ACCESS, NO_INHERITANCE);
			if (SetEntriesInAclA(1, &ea, NULL, &pacl) != ERROR_SUCCESS) {
				return NULL;
			}
			if (!SetSecurityDescriptorDacl(&sd, TRUE, pacl, FALSE)) {
				LocalFree(pacl);
				return NULL;
			}

			sec.nLength = sizeof(SECURITY_ATTRIBUTES);
			sec.bInheritHandle = FALSE;
			sec.lpSecurityDescriptor = &sd;

			hfile = CreateFileA(buf, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
				&sec,
				dwCreationDisposition,
				FILE_ATTRIBUTE_NORMAL,
				NULL);

			LocalFree(pacl);

			int fd = _open_osfhandle((intptr_t)hfile, 0);
			if (fd < 0) {
				return NULL;
			}

			FILE *fptr = _fdopen(fd, mode);
			if (!fptr) {
				_close(fd);
				return NULL;
			}
			return fptr;

		}else {
			return fopen(buf, mode);
		}
	}
#else
	if (restrict_read) {
		FILE *fptr;
		mode_t old_mask;

		old_mask = umask(0077);
		fptr = fopen(path, mode);
		umask(old_mask);

		return fptr;
	}else{
		return fopen(path, mode);
	}
#endif
}


char *misc__trimblanks(char *str)
{
	char *endptr;

	if(str == NULL) return NULL;

	while(isspace(str[0])){
		str++;
	}
	endptr = &str[strlen(str)-1];
	while(endptr > str && isspace(endptr[0])){
		endptr[0] = '\0';
		endptr--;
	}
	return str;
}


char *fgets_extending(char **buf, int *buflen, FILE *stream)
{
	char *rc;
	char endchar;
	int offset = 0;
	char *newbuf;

	if(stream == NULL || buf == NULL || buflen == NULL || *buflen < 1){
		return NULL;
	}

	do{
		rc = fgets(&((*buf)[offset]), (*buflen)-offset, stream);
		if(feof(stream)){
			return rc;
		}

		endchar = (*buf)[strlen(*buf)-1];
		if(endchar == '\n'){
			return rc;
		}
		/* No EOL char found, so extend buffer */
		offset = (*buflen)-1;
		*buflen += 1000;
		newbuf = realloc(*buf, (size_t)*buflen);
		if(!newbuf){
			return NULL;
		}
		*buf = newbuf;
	}while(1);
}
