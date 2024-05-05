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
#include <stdbool.h>

#include "mosquitto.h"

#if defined(WITH_MEMORY_TRACKING)
#  if defined(__APPLE__) || defined(__FreeBSD__) || defined(__linux__)
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

static unsigned long memcount = 0;
static unsigned long max_memcount = 0;

static size_t mem_limit = 0;
void mosquitto_memory_set_limit(size_t lim)
{
	mem_limit = lim;
}

unsigned long mosquitto_memory_used(void)
{
	return memcount;
}

unsigned long mosquitto_max_memory_used(void)
{
	return max_memcount;
}

#ifdef REAL_WITH_MEMORY_TRACKING

/* ==================================================
 * Alloc mismatch tracking
 * ================================================== */
#if defined(ALLOC_MISMATCH_INVALID_READ) || defined(ALLOC_MISMATCH_ABORT)
#define ALLOC_MARKER_SIZE 8
static const char *alloc_marker = "MOSQ_MEM";

static unsigned long dummycounter = 0;
unsigned long mosq__get_dummy_counter(void)
{
	return dummycounter;
}

static void set_alloc_marker(char *mem, size_t size)
{
	memcpy(mem + size - ALLOC_MARKER_SIZE, alloc_marker, ALLOC_MARKER_SIZE);
}

static bool check_alloc_marker(char *mem, size_t size)
{
	return strncmp(mem + size - ALLOC_MARKER_SIZE, alloc_marker, ALLOC_MARKER_SIZE) == 0;
}

static void trigger_alloc_mismatch(char *mem, size_t size)
{
	(void)mem;
	(void)size;
#ifdef ALLOC_MISMATCH_INVALID_READ
	/* Trigger an invalid read on the freed memory and increment dummy counter */
	if(strncmp(mem + size - ALLOC_MARKER_SIZE, alloc_marker, ALLOC_MARKER_SIZE) == 0){
		++dummycounter;
	}
#endif
#ifdef ALLOC_MISMATCH_ABORT
	abort();
#endif
}

#if defined(__linux__)

#if !defined(__libc_free)
void __libc_free(void *ptr);
#endif

void free(void *ptr)
{
	if(!ptr){
		return;
	}
	size_t free_size = malloc_usable_size(ptr);

	/* If we find the marker the memory was allocated using mosquitto_* allocation function */
	bool alloc_mismatch = check_alloc_marker(ptr, free_size);

	__libc_free(ptr);

	if(alloc_mismatch){
		trigger_alloc_mismatch(ptr, free_size);
	}
}
#endif /* defined(__linux__) */

#else /* defined(ALLOC_MISMATCH_INVALID_READ) || defined(ALLOC_MISMATCH_ABORT) */

#define ALLOC_MARKER_SIZE 0

static void set_alloc_marker(char* mem, size_t size) { UNUSED(mem); UNUSED(size); }

#endif /* defined(ALLOC_MISMATCH_INVALID_READ) */


/* ==================================================
 * Alloc functions with tracking
 * ================================================== */

BROKER_EXPORT void *mosquitto_malloc(size_t size)
{
	void *mem;

	if(mem_limit && memcount + size > mem_limit){
		return NULL;
	}
	mem = malloc(size + ALLOC_MARKER_SIZE);
	if(mem){
		size = malloc_usable_size(mem);
		memcount += size;
		if(memcount > max_memcount){
			max_memcount = memcount;
		}
		set_alloc_marker(mem, size);
	}

	return mem;
}

BROKER_EXPORT void *mosquitto_realloc(void *ptr, size_t size)
{
	void *mem;
	size_t free_size = ptr != NULL ? malloc_usable_size(ptr) : 0UL;

#if ALLOC_MARKER_SIZE
	bool alloc_mismatch = free_size > 0 && !check_alloc_marker(ptr, free_size);
#endif

	/* Avoid counter underflow due to mismatched memory allocation function usage */
	if(free_size > memcount){
		free_size = memcount;
	}
	if(mem_limit && memcount - free_size + size > mem_limit){
		return NULL;
	}
	mem = realloc(ptr, size + ALLOC_MARKER_SIZE);
#if ALLOC_MARKER_SIZE
	if(alloc_mismatch){
		/* This will not trigger if realloc was able to extend the memory in place. */
		trigger_alloc_mismatch(ptr, free_size);
	}
#endif

	if(mem){
		size = malloc_usable_size(mem);
		memcount -= free_size;
		memcount += size;
		if(memcount > max_memcount){
			max_memcount = memcount;
		}
		set_alloc_marker(mem, size);
	}else if(size == 0){
		memcount -= free_size;
	}

	return mem;
}

BROKER_EXPORT void mosquitto_free(void *mem)
{
	if(!mem){
		return;
	}
	size_t free_size = malloc_usable_size(mem);
#if ALLOC_MARKER_SIZE
	bool alloc_mismatch = !check_alloc_marker(mem, free_size);
#ifdef __linux__
	__libc_free(mem);
#else
	free(mem);
#endif

	if(alloc_mismatch){
		trigger_alloc_mismatch(mem, free_size);
	}
#else /* ALLOC_MARKER_SIZE */
	free(mem);
#endif /* ALLOC_MARKER_SIZE */

	/* Avoid counter underflow due to mismatched memory function allocation usage */
	if(free_size > memcount){
		free_size = memcount;
	}
	memcount -= free_size;
}

#else /* #ifdef WITH_REAL_MEMORY_TRACKING */

/* ==================================================
 * Alloc functions without tracking
 * ================================================== */

BROKER_EXPORT void *mosquitto_malloc(size_t size)
{
	return malloc(size);
}

BROKER_EXPORT void *mosquitto_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

BROKER_EXPORT void mosquitto_free(void *mem)
{
	free(mem);
}

#endif /* #ifdef WITH_REAL_MEMORY_TRACKING */


/* ==================================================
 * Alloc functions that use the tracked/untracked versions
 * ================================================== */

BROKER_EXPORT void *mosquitto_calloc(size_t nmemb, size_t size)
{
	void *mem;
	const size_t alloc_size = nmemb * size;
	mem = mosquitto_malloc(alloc_size);
	if(mem){
		memset(mem, 0, alloc_size);
	}
	return mem;
}

BROKER_EXPORT char *mosquitto_strdup(const char *s)
{
	char *str;
	size_t size = strlen(s) + 1;

	str = mosquitto_malloc(size);
	if(str){
		memcpy(str, s, size);
	}
	return str;
}

BROKER_EXPORT char *mosquitto_strndup(const char *s, size_t n)
{
	char *str;
	size_t size = strnlen(s, n);

	if(size > n){
		size = n;
	}
	str = mosquitto_malloc(size + 1);
	if(str){
		memcpy(str, s, size);
	}
	str[size] = 0;
	return str;
}
