/*
Copyright (c) 2013-2020 Roger Light <roger@atchoo.org>

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

#include "config.h"

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_time.h>
#endif

#ifdef WIN32
#if !(defined(_MSC_VER) && _MSC_VER <= 1500)
#  define _WIN32_WINNT _WIN32_WINNT_VISTA
#endif
#  include <windows.h>
#else
#  include <unistd.h>
#endif
#include <time.h>

#include "mosquitto.h"
#include "time_mosq.h"

#if _POSIX_TIMERS>0 && defined(_POSIX_MONOTONIC_CLOCK)
static clockid_t time_clock;
#endif

void mosquitto_time_init(void)
{
#if _POSIX_TIMERS>0 && defined(_POSIX_MONOTONIC_CLOCK)
	struct timespec tp;

#ifdef CLOCK_BOOTTIME
	if (clock_gettime(CLOCK_BOOTTIME, &tp) == 0) {
		time_clock = CLOCK_BOOTTIME;
	} else {
		time_clock = CLOCK_MONOTONIC;
	}
#else
	time_clock = CLOCK_MONOTONIC;
#endif
#endif
}

time_t mosquitto_time(void)
{
#ifdef WIN32
	return GetTickCount64()/1000;
#elif _POSIX_TIMERS>0 && defined(_POSIX_MONOTONIC_CLOCK)
	struct timespec tp;

	if (clock_gettime(time_clock, &tp) == 0)
		return tp.tv_sec;

	return (time_t) -1;
#elif defined(__APPLE__)
	static mach_timebase_info_data_t tb;
    uint64_t ticks;
	uint64_t sec;

	ticks = mach_absolute_time();

	if(tb.denom == 0){
		mach_timebase_info(&tb);
	}
	sec = ticks*tb.numer/tb.denom/1000000000;

	return (time_t)sec;
#else
	return time(NULL);
#endif
}

