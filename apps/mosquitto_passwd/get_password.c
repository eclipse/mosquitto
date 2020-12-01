/*
Copyright (c) 2012-2020 Roger Light <roger@atchoo.org>

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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#  include <windows.h>
#  include <process.h>
#   define snprintf sprintf_s
#	include <io.h>
#	include <windows.h>
#else
#  include <unistd.h>
#  include <termios.h>
#  include <sys/stat.h>
#endif

#define MAX_BUFFER_LEN 65536
#define SALT_LEN 12

void get_password__reset_term(void)
{
#ifndef WIN32
	struct termios ts;

	tcgetattr(0, &ts);
	ts.c_lflag |= ECHO | ICANON;
	tcsetattr(0, TCSANOW, &ts);
#endif
}


static int gets_quiet(char *s, int len)
{
#ifdef WIN32
	HANDLE h;
	DWORD con_orig, con_quiet = 0;
	DWORD read_len = 0;

	memset(s, 0, len);
	h  = GetStdHandle(STD_INPUT_HANDLE);
	GetConsoleMode(h, &con_orig);
	con_quiet = con_orig;
	con_quiet &= ~ENABLE_ECHO_INPUT;
	con_quiet |= ENABLE_LINE_INPUT;
	SetConsoleMode(h, con_quiet);
	if(!ReadConsole(h, s, len, &read_len, NULL)){
		SetConsoleMode(h, con_orig);
		return 1;
	}
	while(s[strlen(s)-1] == 10 || s[strlen(s)-1] == 13){
		s[strlen(s)-1] = 0;
	}
	if(strlen(s) == 0){
		return 1;
	}
	SetConsoleMode(h, con_orig);

	return 0;
#else
	struct termios ts_quiet, ts_orig;
	char *rs;

	memset(s, 0, (size_t)len);
	tcgetattr(0, &ts_orig);
	ts_quiet = ts_orig;
	ts_quiet.c_lflag &= (unsigned int)(~(ECHO | ICANON));
	tcsetattr(0, TCSANOW, &ts_quiet);

	rs = fgets(s, len, stdin);
	tcsetattr(0, TCSANOW, &ts_orig);

	if(!rs){
		return 1;
	}else{
		while(s[strlen(s)-1] == 10 || s[strlen(s)-1] == 13){
			s[strlen(s)-1] = 0;
		}
		if(strlen(s) == 0){
			return 1;
		}
	}
	return 0;
#endif
}

int get_password(const char *prompt, const char *verify_prompt, bool quiet, char *password, size_t len)
{
	char pw1[MAX_BUFFER_LEN], pw2[MAX_BUFFER_LEN];
	size_t minLen;
	minLen = len < MAX_BUFFER_LEN ? len : MAX_BUFFER_LEN;

	printf("%s", prompt);
	fflush(stdout);
	if(gets_quiet(pw1, (int)minLen)){
		if(!quiet){
			fprintf(stderr, "Error: Empty password.\n");
		}
		return 1;
	}
	printf("\n");

	if(verify_prompt){
		printf("%s", verify_prompt);
		fflush(stdout);
		if(gets_quiet(pw2, (int)minLen)){
			if(!quiet){
				fprintf(stderr, "Error: Empty password.\n");
			}
			return 1;
		}
		printf("\n");

		if(strcmp(pw1, pw2)){
			if(!quiet){
				fprintf(stderr, "Error: Passwords do not match.\n");
			}
			return 1;
		}
	}

	strncpy(password, pw1, minLen);
	return 0;
}
