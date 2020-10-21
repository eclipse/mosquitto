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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#include <syslog.h>
#endif
#include <time.h>

#ifdef WITH_DLT
#include <sys/stat.h>
#include <dlt/dlt.h>
#endif

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "misc_mosq.h"
#include "util_mosq.h"

extern struct mosquitto_db int_db;

#ifdef WIN32
HANDLE syslog_h;
#endif

/* Options for logging should be:
 *
 * A combination of:
 * Via syslog
 * To a file
 * To stdout/stderr
 * To topics
 */

/* Give option of logging timestamp.
 * Logging pid.
 */
static unsigned int log_destinations = MQTT3_LOG_STDERR;
static unsigned int log_priorities = MOSQ_LOG_ERR | MOSQ_LOG_WARNING | MOSQ_LOG_NOTICE | MOSQ_LOG_INFO;

#ifdef WITH_DLT
static DltContext dltContext;
static bool dlt_allowed = false;

void dlt_fifo_check(void)
{
	struct stat statbuf;
	int fd;

	/* If we start DLT but the /tmp/dlt fifo doesn't exist, or isn't available
	 * for writing then there is a big delay when we try and close the log
	 * later, so check for it first. This has the side effect of not letting
	 * people using DLT create the fifo after Mosquitto has started, but at the
	 * benefit of not having a massive delay for everybody else. */
	memset(&statbuf, 0, sizeof(statbuf));
	if(stat("/tmp/dlt", &statbuf) == 0){
		if(S_ISFIFO(statbuf.st_mode)){
			fd = open("/tmp/dlt", O_NONBLOCK | O_WRONLY);
			if(fd != -1){
				dlt_allowed = true;
				close(fd);
			}
		}
	}
}
#endif

static int get_time(struct tm **ti)
{
#if defined(__APPLE__)
	struct timeval tv;
#else
	struct timespec ts;
#endif
	time_t s;

#ifdef WIN32
	s = time(NULL);

#elif defined(__APPLE__)
	gettimeofday(&tv, NULL);
	s = tv.tv_sec;
#else
	if(clock_gettime(CLOCK_REALTIME, &ts) != 0){
		fprintf(stderr, "Error obtaining system time.\n");
		return 1;
	}
	s = ts.tv_sec;
#endif

	*ti = localtime(&s);
	if(!(*ti)){
		fprintf(stderr, "Error obtaining system time.\n");
		return 1;
	}

	return 0;
}


int log__init(struct mosquitto__config *config)
{
	int rc = 0;

	log_priorities = config->log_type;
	log_destinations = config->log_dest;

	if(log_destinations & MQTT3_LOG_SYSLOG){
#ifndef WIN32
		openlog("mosquitto", LOG_PID|LOG_CONS, config->log_facility);
#else
		syslog_h = OpenEventLog(NULL, "mosquitto");
#endif
	}

	if(log_destinations & MQTT3_LOG_FILE){
		if(drop_privileges(config, true)){
			return 1;
		}
		config->log_fptr = mosquitto__fopen(config->log_file, "at", true);
		if(config->log_fptr){
			setvbuf(config->log_fptr, NULL, _IOLBF, 0);
		}else{
			log_destinations = MQTT3_LOG_STDERR;
			log_priorities = MOSQ_LOG_ERR;
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open log file %s for writing.", config->log_file);
		}
		restore_privileges();
	}
#ifdef WITH_DLT
	dlt_fifo_check();
	if(dlt_allowed){
		DLT_REGISTER_APP("MQTT","mosquitto log");
		dlt_register_context(&dltContext, "MQTT", "mosquitto DLT context");
	}
#endif
	return rc;
}

int log__close(struct mosquitto__config *config)
{
	if(log_destinations & MQTT3_LOG_SYSLOG){
#ifndef WIN32
		closelog();
#else
		CloseEventLog(syslog_h);
#endif
	}
	if(log_destinations & MQTT3_LOG_FILE){
		if(config->log_fptr){
			fclose(config->log_fptr);
			config->log_fptr = NULL;
		}
	}

#ifdef WITH_DLT
	if(dlt_allowed){
		dlt_unregister_context(&dltContext);
		DLT_UNREGISTER_APP();
	}
#endif
	/* FIXME - do something for all destinations! */
	return MOSQ_ERR_SUCCESS;
}

#ifdef WITH_DLT
DltLogLevelType get_dlt_level(unsigned int priority)
{
	switch (priority) {
		case MOSQ_LOG_ERR:
			return DLT_LOG_ERROR;
		case MOSQ_LOG_WARNING:
			return DLT_LOG_WARN;
		case MOSQ_LOG_INFO:
			return DLT_LOG_INFO;
		case MOSQ_LOG_DEBUG:
			return DLT_LOG_DEBUG;
		case MOSQ_LOG_NOTICE:
		case MOSQ_LOG_SUBSCRIBE:
		case MOSQ_LOG_UNSUBSCRIBE:
			return DLT_LOG_VERBOSE;
		default:
			return DLT_LOG_DEFAULT;
	}
}
#endif

int log__vprintf(unsigned int priority, const char *fmt, va_list va)
{
	char *s;
	char *st;
	size_t len;
#ifdef WIN32
	char *sp;
#endif
	const char *topic;
	int syslog_priority;
	time_t now = time(NULL);
	char time_buf[50];
	bool log_timestamp = true;
	char *log_timestamp_format = NULL;
	FILE *log_fptr = NULL;

	if(int_db.config){
		log_timestamp = int_db.config->log_timestamp;
		log_timestamp_format = int_db.config->log_timestamp_format;
		log_fptr = int_db.config->log_fptr;
	}

	if((log_priorities & priority) && log_destinations != MQTT3_LOG_NONE){
		switch(priority){
			case MOSQ_LOG_SUBSCRIBE:
				topic = "$SYS/broker/log/M/subscribe";
#ifndef WIN32
				syslog_priority = LOG_NOTICE;
#else
				syslog_priority = EVENTLOG_INFORMATION_TYPE;
#endif
				break;
			case MOSQ_LOG_UNSUBSCRIBE:
				topic = "$SYS/broker/log/M/unsubscribe";
#ifndef WIN32
				syslog_priority = LOG_NOTICE;
#else
				syslog_priority = EVENTLOG_INFORMATION_TYPE;
#endif
				break;
			case MOSQ_LOG_DEBUG:
				topic = "$SYS/broker/log/D";
#ifndef WIN32
				syslog_priority = LOG_DEBUG;
#else
				syslog_priority = EVENTLOG_INFORMATION_TYPE;
#endif
				break;
			case MOSQ_LOG_ERR:
				topic = "$SYS/broker/log/E";
#ifndef WIN32
				syslog_priority = LOG_ERR;
#else
				syslog_priority = EVENTLOG_ERROR_TYPE;
#endif
				break;
			case MOSQ_LOG_WARNING:
				topic = "$SYS/broker/log/W";
#ifndef WIN32
				syslog_priority = LOG_WARNING;
#else
				syslog_priority = EVENTLOG_WARNING_TYPE;
#endif
				break;
			case MOSQ_LOG_NOTICE:
				topic = "$SYS/broker/log/N";
#ifndef WIN32
				syslog_priority = LOG_NOTICE;
#else
				syslog_priority = EVENTLOG_INFORMATION_TYPE;
#endif
				break;
			case MOSQ_LOG_INFO:
				topic = "$SYS/broker/log/I";
#ifndef WIN32
				syslog_priority = LOG_INFO;
#else
				syslog_priority = EVENTLOG_INFORMATION_TYPE;
#endif
				break;
#ifdef WITH_WEBSOCKETS
			case MOSQ_LOG_WEBSOCKETS:
				topic = "$SYS/broker/log/WS";
#ifndef WIN32
				syslog_priority = LOG_DEBUG;
#else
				syslog_priority = EVENTLOG_INFORMATION_TYPE;
#endif
				break;
#endif
			default:
				topic = "$SYS/broker/log/E";
#ifndef WIN32
				syslog_priority = LOG_ERR;
#else
				syslog_priority = EVENTLOG_ERROR_TYPE;
#endif
		}
		len = strlen(fmt) + 500;
		s = mosquitto__malloc(len*sizeof(char));
		if(!s) return MOSQ_ERR_NOMEM;

		vsnprintf(s, len, fmt, va);
		s[len-1] = '\0'; /* Ensure string is null terminated. */

		if(log_timestamp && log_timestamp_format){
			struct tm *ti = NULL;
			get_time(&ti);
			if(strftime(time_buf, 50, log_timestamp_format, ti) == 0){
				snprintf(time_buf, 50, "Time error");
			}
		}
		if(log_destinations & MQTT3_LOG_STDOUT){
			if(log_timestamp){
				if(log_timestamp_format){
					fprintf(stdout, "%s: %s\n", time_buf, s);
				}else{
					fprintf(stdout, "%d: %s\n", (int)now, s);
				}
			}else{
				fprintf(stdout, "%s\n", s);
			}
		}
		if(log_destinations & MQTT3_LOG_STDERR){
			if(log_timestamp){
				if(log_timestamp_format){
					fprintf(stderr, "%s: %s\n", time_buf, s);
				}else{
					fprintf(stderr, "%d: %s\n", (int)now, s);
				}
			}else{
				fprintf(stderr, "%s\n", s);
			}
		}
		if(log_destinations & MQTT3_LOG_FILE && log_fptr){
			if(log_timestamp){
				if(log_timestamp_format){
					fprintf(log_fptr, "%s: %s\n", time_buf, s);
				}else{
					fprintf(log_fptr, "%d: %s\n", (int)now, s);
				}
			}else{
				fprintf(log_fptr, "%s\n", s);
			}
		}
		if(log_destinations & MQTT3_LOG_SYSLOG){
#ifndef WIN32
			syslog(syslog_priority, "%s", s);
#else
			sp = (char *)s;
			ReportEvent(syslog_h, syslog_priority, 0, 0, NULL, 1, 0, &sp, NULL);
#endif
		}
		if(log_destinations & MQTT3_LOG_TOPIC && priority != MOSQ_LOG_DEBUG && priority != MOSQ_LOG_INTERNAL){
			if(log_timestamp){
				len += 30;
				st = mosquitto__malloc(len*sizeof(char));
				if(!st){
					mosquitto__free(s);
					return MOSQ_ERR_NOMEM;
				}
				snprintf(st, len, "%d: %s", (int)now, s);
				db__messages_easy_queue(&int_db, NULL, topic, 2, (uint32_t)strlen(st), st, 0, 20, NULL);
				mosquitto__free(st);
			}else{
				db__messages_easy_queue(&int_db, NULL, topic, 2, (uint32_t)strlen(s), s, 0, 20, NULL);
			}
		}
#ifdef WITH_DLT
		if(log_destinations & MQTT3_LOG_DLT && priority != MOSQ_LOG_INTERNAL){
			DLT_LOG_STRING(dltContext, get_dlt_level(priority), s);
		}
#endif
		mosquitto__free(s);
	}

	return MOSQ_ERR_SUCCESS;
}

int log__printf(struct mosquitto *mosq, unsigned int priority, const char *fmt, ...)
{
	va_list va;
	int rc;

	UNUSED(mosq);

	va_start(va, fmt);
	rc = log__vprintf(priority, fmt, va);
	va_end(va);

	return rc;
}

void log__internal(const char *fmt, ...)
{
	va_list va;
	char buf[200];
	int len;

	va_start(va, fmt);
	len = vsnprintf(buf, 200, fmt, va);
	va_end(va);

	if(len >= 200){
		log__printf(NULL, MOSQ_LOG_INTERNAL, "Internal log buffer too short (%d)", len);
		return;
	}

	log__printf(NULL, MOSQ_LOG_INTERNAL, "%s%s%s", "\e[32m", buf, "\e[0m");
}

int mosquitto_log_vprintf(int level, const char *fmt, va_list va)
{
	return log__vprintf((unsigned int)level, fmt, va);
}

void mosquitto_log_printf(int level, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	log__vprintf((unsigned int)level, fmt, va);
	va_end(va);
}

