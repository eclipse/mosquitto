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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#include <syslog.h>
#endif
#include <time.h>

#if defined(__APPLE__)
#  include <sys/time.h>
#endif

#ifdef WITH_DLT
#include <sys/stat.h>
#include <dlt/dlt.h>
#endif

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "misc_mosq.h"
#include "util_mosq.h"

#ifdef WIN32
HANDLE syslog_h;
#endif

static char log_fptr_buffer[BUFSIZ];

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
	time_t s;

	s = db.now_real_s;

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
		config->log_fptr = mosquitto__fopen(config->log_file, "at", true);
		if(config->log_fptr){
			setvbuf(config->log_fptr, log_fptr_buffer, _IOLBF, sizeof(log_fptr_buffer));
		}else{
			log_destinations = MQTT3_LOG_STDERR;
			log_priorities = MOSQ_LOG_ERR;
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open log file %s for writing.", config->log_file);
		}
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
	const char *topic;
	int syslog_priority;
	char log_line[1000];
	size_t log_line_pos;
#ifdef WIN32
	char *sp;
#endif
	bool log_timestamp = true;
	char *log_timestamp_format = NULL;
	FILE *log_fptr = NULL;

	if(db.config){
		log_timestamp = db.config->log_timestamp;
		log_timestamp_format = db.config->log_timestamp_format;
		log_fptr = db.config->log_fptr;
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
		if(log_timestamp){
			if(log_timestamp_format){
				struct tm *ti = NULL;
				get_time(&ti);
				log_line_pos = strftime(log_line, sizeof(log_line), log_timestamp_format, ti);
				if(log_line_pos == 0){
					log_line_pos = (size_t)snprintf(log_line, sizeof(log_line), "Time error");
				}
			}else{
				log_line_pos = (size_t)snprintf(log_line, sizeof(log_line), "%d", (int)db.now_real_s);
			}
			if(log_line_pos < sizeof(log_line)-3){
				log_line[log_line_pos] = ':';
				log_line[log_line_pos+1] = ' ';
				log_line[log_line_pos+2] = '\0';
				log_line_pos += 2;
			}
		}else{
			log_line_pos = 0;
		}
		vsnprintf(&log_line[log_line_pos], sizeof(log_line)-log_line_pos, fmt, va);
		log_line[sizeof(log_line)-1] = '\0'; /* Ensure string is null terminated. */

		if(log_destinations & MQTT3_LOG_STDOUT){
			fprintf(stdout, "%s\n", log_line);
		}
		if(log_destinations & MQTT3_LOG_STDERR){
			fprintf(stderr, "%s\n", log_line);
		}
		if(log_destinations & MQTT3_LOG_FILE && log_fptr){
			fprintf(log_fptr, "%s\n", log_line);
#ifdef WIN32
			/* Windows doesn't support line buffering, so flush. */
			fflush(log_fptr);
#endif
		}
		if(log_destinations & MQTT3_LOG_SYSLOG){
#ifndef WIN32
			syslog(syslog_priority, "%s", log_line);
#else
			sp = (char *)log_line;
			ReportEvent(syslog_h, syslog_priority, 0, 0, NULL, 1, 0, &sp, NULL);
#endif
		}
		if(log_destinations & MQTT3_LOG_TOPIC && priority != MOSQ_LOG_DEBUG && priority != MOSQ_LOG_INTERNAL){
			db__messages_easy_queue(NULL, topic, 2, (uint32_t)strlen(log_line), log_line, 0, 20, NULL);
		}
#ifdef WITH_DLT
		if(log_destinations & MQTT3_LOG_DLT && priority != MOSQ_LOG_INTERNAL){
			DLT_LOG_STRING(dltContext, get_dlt_level(priority), log_line);
		}
#endif
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

#ifdef WIN32
	log__printf(NULL, MOSQ_LOG_INTERNAL, "%s", buf);
#else
	log__printf(NULL, MOSQ_LOG_INTERNAL, "%s%s%s", "\e[32m", buf, "\e[0m");
#endif
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

