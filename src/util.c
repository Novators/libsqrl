/** @file util.c -- Various utility functions 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#ifndef CONFIG_H_INCLUDED
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sodium.h>


#include "sqrl_internal.h"
#include "crypto/gcm.h"

#ifdef _WIN32
#include <Windows.h>
#else
#include <pthread.h>
#endif


static bool sqrl_is_initialized = false;

SqrlMutex sqrl_mutex_create()
{
	#ifdef _WIN32
	CRITICAL_SECTION *cs = calloc( 1, sizeof( CRITICAL_SECTION ));
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
	//DEBUG_PRINT( "Mutex Left\n" );
}

struct Sqrl_Global_Mutices SQRL_GLOBAL_MUTICES;

/**
 * Initializes the SQRL library.  Must be called once, before any SQRL functions are used.
 */
int sqrl_init()
{
	if( !sqrl_is_initialized ) {
		sqrl_is_initialized = true;
		SQRL_GLOBAL_MUTICES.user = sqrl_mutex_create();
		#ifdef DEBUG
		DEBUG_PRINTF( DEBUG_INFO, "libsqrl %s\n", SQRL_LIB_VERSION );
		#endif
		gcm_initialize();
		return sodium_init();
	}
	return 0;
}

DLL_PUBLIC
void utstring_zero( UT_string *str )
{
	if( !str ) return;
	sodium_memzero( utstring_body( str ), utstring_len( str ));
}

void bin2rc( char *buf, uint8_t *bin ) 
{
	// bin must be 512+ bits of entropy!
	int i, j, k, a, b;
	uint64_t *tmp = (uint64_t*)bin;
	for( i = 0, j = 0; i < 3; i++ ) {
		for( k = 0; k < 8; k++ ) {
			buf[j++] = '0' + (tmp[k] % 10);
			tmp[k] /= 10;
		}
	}
	buf[j] = 0;
}

void sqrl_lcstr( char *str )
{
	int i;
	for( i = 0; str[i] != 0; i++ ) {
		if( str[i] > 64 && str[i] < 91 ) {
			str[i] += 32;
		}
	}
}

void printhex( char *label, uint8_t *bin, size_t bin_len )
{
	size_t l = bin_len * 2 + 1;
	char *txt = calloc( 1, l );
	sodium_bin2hex( txt, l, bin, bin_len );
	printf( "%s: %s\n", label, txt );
	free( txt );
}

uint16_t readint_16( void *buf )
{
	uint8_t *b = (uint8_t*)buf;
	return (uint16_t)( b[0] | ( b[1] << 8 ));
}

