#ifndef MOSQUITTO_THREADING_H
#define MOSQUITTO_THREADING_H

#ifndef WIN32
#  include <pthread.h>
#else
#  include <windows.h>
#endif

#ifndef WIN32
typedef pthread_mutex_t mosquitto_mutex;
typedef pthread_t mosquitto_thread_handle;
#else
typedef CRITICAL_SECTION mosquitto_mutex;
typedef HANDLE mosquitto_thread_handle;
#endif

int mosquitto_thread_create(mosquitto_thread_handle *thread, void *(*mosquitto_thread_function)(void *), void *arg);
int mosquitto_thread_join(mosquitto_thread_handle thread);
mosquitto_thread_handle mosquitto_current_thread_handle();
int mosquitto_thread_cancel(mosquitto_thread_handle thread);
int mosquitto_thread_equal(mosquitto_thread_handle thread_1, mosquitto_thread_handle thread_2);
int mosquitto_mutex_init(mosquitto_mutex *mutex);
int mosquitto_mutex_destroy(mosquitto_mutex *mutex);
int mosquitto_mutex_lock(mosquitto_mutex *mutex);
int mosquitto_mutex_unlock(mosquitto_mutex *mutex);

#endif
