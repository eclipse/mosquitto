/*
Copyright (c) 2009-2021 Roger Light <roger@atchoo.org>

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

#include <stdlib.h>
#include <string.h>

#include "mosquitto.h"

#if defined(WITH_MEMORY_TRACKING) && defined(WITH_BROKER)
#  if defined(__APPLE__) || defined(__FreeBSD__) || defined(__GLIBC__)
#    define REAL_WITH_MEMORY_TRACKING
#  endif
#endif

#ifdef REAL_WITH_MEMORY_TRACKING
#  if defined(__APPLE__)
#    include <malloc/malloc.h>
#    define malloc_usable_size malloc_size
#  elif defined(__FreeBSD__)
#    include <malloc_np.h>
#  else
#    include <malloc.h>
#  endif
#endif

#ifdef REAL_WITH_MEMORY_TRACKING
static unsigned long memcount = 0;
static unsigned long max_memcount = 0;
#endif

static size_t mem_limit = 0;
void mosquitto_memory_set_limit(size_t lim)
{
	mem_limit = lim;
}

BROKER_EXPORT void *mosquitto_calloc(size_t nmemb, size_t size)
{
	void *mem;
#ifdef REAL_WITH_MEMORY_TRACKING
	if(mem_limit && memcount + size > mem_limit){
		return NULL;
	}
#endif
	mem = calloc(nmemb, size);

#ifdef REAL_WITH_MEMORY_TRACKING
	if(mem){
		memcount += malloc_usable_size(mem);
		if(memcount > max_memcount){
			max_memcount = memcount;
		}
	}
#endif

	return mem;
}

BROKER_EXPORT void mosquitto_free(void *mem)
{
#ifdef REAL_WITH_MEMORY_TRACKING
	if(!mem){
		return;
	}
	memcount -= malloc_usable_size(mem);
#endif
	free(mem);
}

BROKER_EXPORT void *mosquitto_malloc(size_t size)
{
	void *mem;

#ifdef REAL_WITH_MEMORY_TRACKING
	if(mem_limit && memcount + size > mem_limit){
		return NULL;
	}
#endif

	mem = malloc(size);

#ifdef REAL_WITH_MEMORY_TRACKING
	if(mem){
		memcount += malloc_usable_size(mem);
		if(memcount > max_memcount){
			max_memcount = memcount;
		}
	}
#endif

	return mem;
}

#ifdef REAL_WITH_MEMORY_TRACKING
unsigned long mosquitto_memory_used(void)
{
	return memcount;
}

unsigned long mosquitto_max_memory_used(void)
{
	return max_memcount;
}
#endif

BROKER_EXPORT void *mosquitto_realloc(void *ptr, size_t size)
{
	void *mem;
#ifdef REAL_WITH_MEMORY_TRACKING
	if(mem_limit && memcount + size > mem_limit){
		return NULL;
	}
	if(ptr){
		memcount -= malloc_usable_size(ptr);
	}
#endif
	mem = realloc(ptr, size);

#ifdef REAL_WITH_MEMORY_TRACKING
	if(mem){
		memcount += malloc_usable_size(mem);
		if(memcount > max_memcount){
			max_memcount = memcount;
		}
	}
#endif

	return mem;
}

BROKER_EXPORT char *mosquitto_strdup(const char *s)
{
	char *str;
#ifdef REAL_WITH_MEMORY_TRACKING
	if(mem_limit && memcount + strlen(s) > mem_limit){
		return NULL;
	}
#endif
	str = strdup(s);

#ifdef REAL_WITH_MEMORY_TRACKING
	if(str){
		memcount += malloc_usable_size(str);
		if(memcount > max_memcount){
			max_memcount = memcount;
		}
	}
#endif

	return str;
}

BROKER_EXPORT char *mosquitto_strndup(const char *s, size_t n)
{
	char *str;
#ifdef REAL_WITH_MEMORY_TRACKING
	if(mem_limit && memcount + strlen(s) > mem_limit){
		return NULL;
	}
#endif

#ifdef WIN32
	str = malloc(n+1);
	if(!str) return NULL;
	memcpy(str, s, n);
	str[n] = 0;
#else
	str = strndup(s, n);
#endif

#ifdef REAL_WITH_MEMORY_TRACKING
	if(str){
		memcount += malloc_usable_size(str);
		if(memcount > max_memcount){
			max_memcount = memcount;
		}
	}
#endif

	return str;
}
