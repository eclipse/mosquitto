#include "mosquitto_threading.h"

#ifndef WIN32
int mosquitto_thread_create(mosquitto_thread_handle *thread, void *(*start_routine)(void *), void *arg) {
	return pthread_create(thread, NULL, start_routine, arg);
}

int mosquitto_thread_join(mosquitto_thread_handle thread) {
	return pthread_join(thread, NULL);
}

mosquitto_thread_handle mosquitto_current_thread_handle() {
	return pthread_self();
}

int mosquitto_thread_cancel(mosquitto_thread_handle thread) {
	return pthread_cancel(thread);
}

int mosquitto_thread_equal(mosquitto_thread_handle thread_1, mosquitto_thread_handle thread_2) {
	return pthread_equal(thread_1, thread_2);
}

int mosquitto_mutex_init(mosquitto_mutex *mutex) {
	return pthread_mutex_init(mutex, NULL);
}

int mosquitto_mutex_destroy(mosquitto_mutex *mutex) {
	return pthread_mutex_destroy(mutex);
}

int mosquitto_mutex_lock(mosquitto_mutex *mutex) {
	return pthread_mutex_lock(mutex);
}

int mosquitto_mutex_unlock(mosquitto_mutex *mutex) {
	return pthread_mutex_unlock(mutex);
}

#else

int mosquitto_thread_create(mosquitto_thread_handle *thread, void *(*start_routine)(void *), void *arg) {
	if (thread == NULL || start_routine == NULL)
		return 1;

	*thread = CreateThread(NULL, 0, start_routine, arg, 0, NULL);
	if (*thread == NULL)
		return 1;

	return 0;
}

int mosquitto_thread_join(mosquitto_thread_handle thread) {
	if (WaitForSingleObject(thread, INFINITE) == WAIT_FAILED)
		return 1;

	if (!CloseHandle(thread))
		return 2;

	return 0;
}

mosquitto_thread_handle mosquitto_current_thread_handle() {
	return GetCurrentThread();
}

int mosquitto_thread_cancel(mosquitto_thread_handle thread) {
	if (!TerminateThread(thread, 0))
		return 1;

	return 0;
}

int mosquitto_thread_equal(mosquitto_thread_handle thread_1, mosquitto_thread_handle thread_2) {
	if (GetThreadId(thread_1) == GetThreadId(thread_2))
		return 1;

	return 0;
}

int mosquitto_mutex_init(mosquitto_mutex *mutex) {
	if (mutex == NULL)
		return 1;

	InitializeCriticalSection(mutex);
	return 0;
}

int mosquitto_mutex_destroy(mosquitto_mutex *mutex) {
	if (mutex == NULL)
		return 1;

	DeleteCriticalSection(mutex);
	return 0;
}

int mosquitto_mutex_lock(mosquitto_mutex *mutex) {
	if (mutex == NULL)
		return 1;

	EnterCriticalSection(mutex);
	return 0;
}

int mosquitto_mutex_unlock(mosquitto_mutex *mutex) {
	if (mutex == NULL)
		return 1;

	LeaveCriticalSection(mutex);
	return 0;
}

#endif
