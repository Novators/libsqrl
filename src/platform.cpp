/** @file platform.h 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/  

#include "sqrl_internal.h"
#include "sqrl.h"

void sqrl_sleep(int sleepMs)
{
#ifdef UNIX
    usleep(sleepMs * 1000);   // usleep takes sleep time in us (1 millionth of a second)
#endif
#ifdef WIN32
    Sleep(sleepMs);
#endif
}

SqrlMutex sqrl_mutex_create()
{
    #ifdef _WIN32
    CRITICAL_SECTION *cs = (CRITICAL_SECTION*)calloc( 1, sizeof( CRITICAL_SECTION ));
    InitializeCriticalSection( cs );
    return (SqrlMutex*)cs;
    #else
    pthread_mutex_t *mutex = calloc( 1, sizeof( pthread_mutex_t ));
    pthread_mutex_init(mutex, NULL);
    return (SqrlMutex*)mutex;
    #endif
}

void sqrl_mutex_destroy( SqrlMutex sm )
{
    #ifdef _WIN32
    DeleteCriticalSection( (CRITICAL_SECTION*) sm );
    #else
    pthread_mutex_destroy( (pthread_mutex_t*)sm );
    #endif
}

bool sqrl_mutex_enter( SqrlMutex sm )
{
    if( sm != NULL ) {
        #ifdef _WIN32
        EnterCriticalSection( (CRITICAL_SECTION*)sm );
        #else
        pthread_mutex_lock( (pthread_mutex_t*)sm );
        #endif
        return true;
    }
    return false;
}

void sqrl_mutex_leave( SqrlMutex sm )
{
    #ifdef _WIN32
    LeaveCriticalSection( (CRITICAL_SECTION*)sm );
    #else
    pthread_mutex_unlock( (pthread_mutex_t*)sm );
    #endif
}

SqrlThread sqrl_thread_create( sqrl_thread_function function, SQRL_THREAD_FUNCTION_INPUT_TYPE input )
{
#ifdef WIN32
    return CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)function, input, 0, NULL );
#endif
#ifdef UNIX
    pthread_attr_t attr;
    pthread_attr_init( &attr );
    pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_JOINABLE );

    SqrlThread thread;

    pthread_create( &thread, &attr, function, input );
    pthread_attr_destroy( &attr );
    return thread;
#endif
}


