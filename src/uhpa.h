/*
Copyright (c) 2015-2016 Roger Light <roger@atchoo.org>

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
#ifndef UHPA_H
#define UHPA_H

/* "Union of heap pointer and array"
 *
 * This set of macros is intended to provide a simple means of treating a
 * variable as a heap pointer or a fixed size array, depending on the size of
 * the data being stored. It was borne out of the situation where the majority
 * of calls to malloc for a struct member were ending up less than 8 bytes -
 * i.e. the size of the 64-bit pointer. By using uhpa a great number of calls
 * to malloc could be avoided. The downsize to this method is that you must
 * always know the length of data that you are dealing with.
 *
 * The data structure you provide must look something like:
 *
 * typedef union {
 *		void *ptr;
 *		char array[MAX_ARRAY_SIZE];
 *	} uhpa_u
 *
 * This code really only makes sense if the data types you want to store are
 * smaller than a pointer - the most obvious choice being bytes. All of these
 * functions assume that the array is made up of single bytes.
 *
 * You can change the type of ptr to match your needs, with the above caveat
 * about array. So make ptr a char*, uint8_t*, unsigned char*, ...
 *
 * It should be possible to modify the code to work with arrays that have
 * element sizes bigger than a byte.
 *
 * Define MAX_ARRAY_SIZE to be as large as you want, depending on the size of
 * your commonly used data. Define MAX_ARRAY_SIZE to be sizeof(void *) if you
 * do not want to "waste" any memory per item - with the tradeoff that calls to
 * malloc will be more frequent because MAX_ARRAY_SIZE will only be 4 or 8
 * bytes, depending on your architecture.
 *
 * =============================================================================
 * Basic Functions
 * =============================================================================
 *
 * Note that if you are using strings, set size to be strlen(s)+1, so that the
 * null terminator is included, or use the _STR functions below.
 *
 * UHPA_ALLOC(u, size)
 *		Call to allocate memory to a uhpa variable if required.
 *
 *		u : the uhpa data type that will have memory allocated or not,
 *		depending on "size".
 *		size : the length of the data to be stored, in bytes.
 *
 *		returns :	1 if memory was allocated successfully
 *					0 if memory was not able to be allocated
 *					-1 if no memory needed to be allocated
 * 
 * UHPA_ACCESS(u, size)
 *		Call to access (for read or write) a uhpa variable that has already had
 *		UHPA_ALLOC() called on it.
 *
 *		u : the uhpa data type that has already had memory allocated.
 *		size : the length of the stored data, in bytes.
 *
 *		returns : an appropriate pointer/array address
 *
 * UHPA_FREE(u, size)
 *		Call to free memory associated with a uhpa variable. This is safe to
 *		call with a data structure that does not have heap allocated memory.
 *
 *		u : the uhpa data type that has already had memory allocated.
 *		size : the length of the stored data, in bytes.
 *		
 * UHPA_MOVE(dest, src, src_size)
 *		Call to move memory stored in one uhpa variable to another. If the data
 *		is stored with heap allocated memory, then dest.ptr is set to src.ptr.
 *		If the data is stored as an array, memmove is used to copy data from
 *		src to dest. In both cases the data stored in src is invalidated by
 *		setting src.ptr to NULL and calling memset(src.array, 0, src_size)
 *		respectively.
 *
 * =============================================================================
 * String Functions
 * =============================================================================
 *
 * Convenience functions when working with strings. These are identical to the
 * non-string versions, except that they increase the value of "size" by 1, to
 * take into account the need for storing the 0 termination character.
 *
 * UHPA_ALLOC_STR(u, size)
 * UHPA_ACCESS_STR(u, size)
 * UHPA_FREE_STR(u, size)
 * UHPA_MOVE_STR(dest, src, size)
 *		
 * =============================================================================
 * Forcing use of malloc
 * =============================================================================
 *
 * If you wish to force the use of malloc without removing the UHPA macros from
 * your code (i.e. the macros will never use the array part of the union) then
 * #define UHPA_FORCE_MALLOC before including this file.
 *
 * =============================================================================
 * Memory Functions
 * =============================================================================
 *
 * If you wish to use your own memory functions for alloc/free, #define both
 * uhpa_malloc and uhpa_free to your own functions.
 */


#ifndef uhpa_malloc
#	define uhpa_malloc(size) malloc(size)
#endif

#ifndef uhpa_free
#	define uhpa_free(ptr) free(ptr)
#endif

#define UHPA_ALLOC_CHK(u, size) \
	((size) > sizeof((u).array)? \
		(((u).ptr = uhpa_malloc((size)))?1:0) \
		:-1)

#define UHPA_ACCESS_CHK(u, size) ((size) > sizeof((u).array)?(u).ptr:(u).array)

#define UHPA_FREE_CHK(u, size) \
	if((size) > sizeof((u).array) && (u).ptr){ \
		uhpa_free((u).ptr); \
		(u).ptr = NULL; \
	} 

#define UHPA_MOVE_CHK(dest, src, src_size) \
	if((src_size) > sizeof((src).array) && (src).ptr){ \
		(dest).ptr = (src).ptr; \
		(src).ptr = NULL; \
	}else{ \
		memmove((dest).array, (src).array, (src_size)); \
		memset((src).array, 0, (src_size)); \
	}

#ifdef UHPA_FORCE_MALLOC
#  define UHPA_ALLOC(u, size) ((u).ptr = uhpa_malloc(size))
#  define UHPA_ACCESS(u, size) (u).ptr
#  define UHPA_FREE(u, size) uhpa_free((u).ptr); (u).ptr = NULL;
#  define UHPA_MOVE(dest, src, src_size) {(dest).ptr = (src).ptr; (src).ptr = NULL}
#else
#  define UHPA_ALLOC(u, size) UHPA_ALLOC_CHK(u, size)
#  define UHPA_ACCESS(u, size) UHPA_ACCESS_CHK(u, size)
#  define UHPA_FREE(u, size) UHPA_FREE_CHK(u, size)
#  define UHPA_MOVE(dest, src, src_size) UHPA_MOVE_CHK(dest, src, src_size)
#endif

#define UHPA_ALLOC_STR(u, size) UHPA_ALLOC((u), (size)+1)
#define UHPA_ACCESS_STR(u, size) ((char *)UHPA_ACCESS((u), (size)+1))
#define UHPA_FREE_STR(u, size) UHPA_FREE((u), (size)+1)
#define UHPA_MOVE_STR(dest, src, src_size) UHPA_MOVE((dest), (src), (src_size)+1)

#endif
