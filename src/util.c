/** @file util.c -- Various utility functions 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sodium.h>


#include "sqrl_internal.h"
#include "crypto/gcm.h"


static bool sqrl_is_initialized = false;

struct Sqrl_Global_Mutices SQRL_GLOBAL_MUTICES;

/**
Initializes the SQRL library.  Must be called once, before any SQRL functions are used.
*/
DLL_PUBLIC
int sqrl_init()
{
	if( !sqrl_is_initialized ) {
		sqrl_is_initialized = true;
		SQRL_GLOBAL_MUTICES.user = sqrl_mutex_create();
		SQRL_GLOBAL_MUTICES.site = sqrl_mutex_create();
		SQRL_GLOBAL_MUTICES.transaction = sqrl_mutex_create();
		#ifdef DEBUG
		DEBUG_PRINTF( "libsqrl %s\n", SQRL_LIB_VERSION );
		#endif
		gcm_initialize();
		return sodium_init();
	}
	return 0;
}

/**
Performs clean-up as a client is closing.  Erases and frees memory used by libsqrl.
If a User cannot safely be freed, it is hintlocked (encrypted).

\note Do not call any libsqrl functions after \p sqrl_stop()

@return Number of objects that could not safely be removed from memory, so they were encrypted.
@return -1 if libsqrl has not been initialized with \p sqrl_init()
*/
DLL_PUBLIC
int sqrl_stop()
{
	if( sqrl_is_initialized ) {
		sqrl_client_site_maintenance( true );
		sqrl_client_user_maintenance( true );
		int transactionCount = sqrl_transaction_count();
		int userCount = sqrl_user_count();
		int siteCount = sqrl_site_count();
#ifdef DEBUG
		DEBUG_PRINTF( "%10s: %d open sites\n", "sqrl_stop", siteCount );
		DEBUG_PRINTF( "%10s: %d open transactions\n", "sqrl_stop", transactionCount );
		DEBUG_PRINTF( "%10s: %d open users\n", "sqrl_stop", userCount );
#endif
		return transactionCount + userCount + siteCount;
	}
	return -1;
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

