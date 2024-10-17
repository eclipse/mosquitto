#ifndef PTHREAD_COMPAT_
#define PTHREAD_COMPAT_

#if defined(WITH_THREADING) && !defined(WITH_BROKER)
#  include <pthread.h>

#  define COMPAT_pthread_create(A, B, C, D) pthread_create((A), (B), (C), (D))
#  define COMPAT_pthread_join(A, B) pthread_join((A), (B))
#  define COMPAT_pthread_cancel(A) pthread_cancel((A))
#  define COMPAT_pthread_testcancel() pthread_testcancel()

#  define COMPAT_pthread_mutex_init(A, B) pthread_mutex_init((A), (B))
#  define COMPAT_pthread_mutex_destroy(A) pthread_mutex_destroy((A))
#  define COMPAT_pthread_mutex_lock(A) pthread_mutex_lock((A))
#  define COMPAT_pthread_mutex_unlock(A) pthread_mutex_unlock((A))
#else
#  define COMPAT_pthread_create(A, B, C, D)
#  define COMPAT_pthread_join(A, B)
#  define COMPAT_pthread_cancel(A)
#  define COMPAT_pthread_testcancel()

#  define COMPAT_pthread_mutex_init(A, B)
#  define COMPAT_pthread_mutex_destroy(A)
#  define COMPAT_pthread_mutex_lock(A)
#  define COMPAT_pthread_mutex_unlock(A)
#endif

#endif
