#ifndef DUMMY_THREADING_H
#define DUMMY_THREADING_H

#define mosquitto_thread_create(A, B, C)
#define mosquitto_thread_join(A)
#define mosquitto_thread_cancel(A)

#define mosquitto_mutex_init(A)
#define mosquitto_mutex_destroy(A)
#define mosquitto_mutex_lock(A)
#define mosquitto_mutex_unlock(A)

#endif
