#ifndef DUMMYPTHREAD_H
#define DUMMYPTHREAD_H

#define pthread_create(A, B, C, D)
#define pthread_join(A, B)
#define pthread_cancel(A)
#define pthread_testcancel()

#define pthread_mutex_init(A, B)
#define pthread_mutex_destroy(A)
#define pthread_mutex_lock(A)
#define pthread_mutex_unlock(A)

#endif
