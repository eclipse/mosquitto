/*
Copyright (c) 2009-2018 Roger Light <roger@atchoo.org>

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

#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef WIN32
#include <unistd.h>
#else
#include <process.h>
#include <winsock2.h>
#define snprintf sprintf_s
#endif

#include <mosquitto.h>
#include "client_shared.h"


static int get_time(struct tm **ti, long *ns)
{
#ifdef WIN32
	SYSTEMTIME st;
#else
	struct timespec ts;
#endif
	time_t s;

#ifdef WIN32
	s = time(NULL);

	GetLocalTime(&st);
	*ns = st.wMilliseconds*1000000L;
#else
	if(clock_gettime(CLOCK_REALTIME, &ts) != 0){
		fprintf(stderr, "Error obtaining system time.\n");
		return 1;
	}
	s = ts.tv_sec;
	*ns = ts.tv_nsec;
#endif

	*ti = localtime(&s);
	if(!(*ti)){
		fprintf(stderr, "Error obtaining system time.\n");
		return 1;
	}

	return 0;
}


static void write_payload(const unsigned char *payload, int payloadlen, int hex)
{
	int i;

	if(hex == 0){
		(void)fwrite(payload, 1, payloadlen, stdout);
	}else if(hex == 1){
		for(i=0; i<payloadlen; i++){
			fprintf(stdout, "%x", payload[i]);
		}
	}else if(hex == 2){
		for(i=0; i<payloadlen; i++){
			fprintf(stdout, "%X", payload[i]);
		}
	}
}


static void write_json_payload(const char *payload, int payloadlen)
{
	int i;

	for(i=0; i<payloadlen; i++){
		if(payload[i] == '"' || payload[i] == '\\' || (payload[i] >=0 && payload[i] < 32)){
			printf("\\u%04d", payload[i]);
		}else{
			fputc(payload[i], stdout);
		}
	}
}


static void json_print(const struct mosquitto_message *message, const struct tm *ti, bool escaped)
{
	char buf[100];

	strftime(buf, 100, "%s", ti);
	printf("{\"tst\":%s,\"topic\":\"%s\",\"qos\":%d,\"retain\":%d,\"payloadlen\":%d,", buf, message->topic, message->qos, message->retain, message->payloadlen);
	if(message->qos > 0){
		printf("\"mid\":%d,", message->mid);
	}
	if(escaped){
		fputs("\"payload\":\"", stdout);
		write_json_payload(message->payload, message->payloadlen);
		fputs("\"}", stdout);
	}else{
		fputs("\"payload\":", stdout);
		write_payload(message->payload, message->payloadlen, 0);
		fputs("}", stdout);
	}
}


static void formatted_print(const struct mosq_config *cfg, const struct mosquitto_message *message)
{
	int len;
	int i;
	struct tm *ti = NULL;
	long ns;
	char strf[3];
	char buf[100];

	len = strlen(cfg->format);

	for(i=0; i<len; i++){
		if(cfg->format[i] == '%'){
			if(i < len-1){
				i++;
				switch(cfg->format[i]){
					case '%':
						fputc('%', stdout);
						break;

					case 'I':
						if(!ti){
							if(get_time(&ti, &ns)){
								fprintf(stderr, "Error obtaining system time.\n");
								return;
							}
						}
						if(strftime(buf, 100, "%FT%T%z", ti) != 0){
							fputs(buf, stdout);
						}
						break;

					case 'j':
						if(!ti){
							if(get_time(&ti, &ns)){
								fprintf(stderr, "Error obtaining system time.\n");
								return;
							}
						}
						json_print(message, ti, true);
						break;

					case 'J':
						if(!ti){
							if(get_time(&ti, &ns)){
								fprintf(stderr, "Error obtaining system time.\n");
								return;
							}
						}
						json_print(message, ti, false);
						break;

					case 'l':
						printf("%d", message->payloadlen);
						break;

					case 'm':
						printf("%d", message->mid);
						break;

					case 'p':
						write_payload(message->payload, message->payloadlen, 0);
						break;

					case 'q':
						fputc(message->qos + 48, stdout);
						break;

					case 'r':
						if(message->retain){
							fputc('1', stdout);
						}else{
							fputc('0', stdout);
						}
						break;

					case 't':
						fputs(message->topic, stdout);
						break;

					case 'U':
						if(!ti){
							if(get_time(&ti, &ns)){
								fprintf(stderr, "Error obtaining system time.\n");
								return;
							}
						}
						if(strftime(buf, 100, "%s", ti) != 0){
							printf("%s.%09ld", buf, ns);
						}
						break;

					case 'x':
						write_payload(message->payload, message->payloadlen, 1);
						break;

					case 'X':
						write_payload(message->payload, message->payloadlen, 2);
						break;
				}
			}
		}else if(cfg->format[i] == '@'){
			if(i < len-1){
				i++;
				if(cfg->format[i] == '@'){
					fputc('@', stdout);
				}else{
					if(!ti){
						if(get_time(&ti, &ns)){
							fprintf(stderr, "Error obtaining system time.\n");
							return;
						}
					}

					strf[0] = '%';
					strf[1] = cfg->format[i];
					strf[2] = 0;

					if(cfg->format[i] == 'N'){
						printf("%09ld", ns);
					}else{
						if(strftime(buf, 100, strf, ti) != 0){
							fputs(buf, stdout);
						}
					}
				}
			}
		}else if(cfg->format[i] == '\\'){
			if(i < len-1){
				i++;
				switch(cfg->format[i]){
					case '\\':
						fputc('\\', stdout);
						break;

					case '0':
						fputc('\0', stdout);
						break;

					case 'a':
						fputc('\a', stdout);
						break;

					case 'e':
						fputc('\033', stdout);
						break;

					case 'n':
						fputc('\n', stdout);
						break;

					case 'r':
						fputc('\r', stdout);
						break;

					case 't':
						fputc('\t', stdout);
						break;

					case 'v':
						fputc('\v', stdout);
						break;
				}
			}
		}else{
			fputc(cfg->format[i], stdout);
		}
	}
	if(cfg->eol){
		fputc('\n', stdout);
	}
	fflush(stdout);
}


void print_message(struct mosq_config *cfg, const struct mosquitto_message *message)
{
	if(cfg->format){
		formatted_print(cfg, message);
	}else if(cfg->verbose){
		if(message->payloadlen){
			printf("%s ", message->topic);
			write_payload(message->payload, message->payloadlen, false);
			if(cfg->eol){
				printf("\n");
			}
		}else{
			if(cfg->eol){
				printf("%s (null)\n", message->topic);
			}
		}
		fflush(stdout);
	}else{
		if(message->payloadlen){
			write_payload(message->payload, message->payloadlen, false);
			if(cfg->eol){
				printf("\n");
			}
			fflush(stdout);
		}
	}
}

