/*
Copyright (c) 2021 Roger Light <roger@atchoo.org>

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
#if defined(WIN32) && defined(WITH_THREADING)

#include "winthread_mosq.h"

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*thread_main) (void *), void *arg)
{
	if(thread == NULL || thread_main == NULL){
		return 1;
	}

	*thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)thread_main, arg, 0, NULL);
	if(*thread){
		return 0;
	}else{
		return 1;
	}
}

int pthread_join(pthread_t thread, void **retval)
{
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
	return 0;
}

int pthread_self(void)
{
	return GetCurrentThreadId();
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr)
{
	if(mutex == NULL) return 1;
	InitializeCriticalSection(mutex);
	return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	if(mutex == NULL) return 1;
	DeleteCriticalSection(mutex);
	return 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
	if(mutex == NULL) return 1;
	EnterCriticalSection(mutex);
	return 0;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	if(mutex == NULL) return 1;
	LeaveCriticalSection(mutex);
	return 0;
}

int pthread_cond_init(pthread_cond_t *cond, pthread_condattr_t *attr)
{
	if(cond == NULL) return 1;
	InitializeConditionVariable(cond);
	return 0;
}

int pthread_cond_destroy(pthread_cond_t *cond)
{
	return 0;
}

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
	if(cond == NULL || mutex == NULL) return 1;

	return !SleepConditionVariableCS(cond, mutex, INFINITE);
}

int pthread_cond_signal(pthread_cond_t *cond)
{
	if(cond == NULL) return 1;
	WakeConditionVariable(cond);
	return 0;
}

#endif
