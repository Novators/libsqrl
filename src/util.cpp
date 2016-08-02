/** @file util.c -- Various utility functions

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "version.h"
#include "gcm.h"

static bool sqrl_is_initialized = false;

void SqrlInit() {
	if( !sqrl_is_initialized ) {
		gcm_initialize();
		sodium_init();
		sqrl_is_initialized = true;
	}
}

int sqrl_mlock( void * const addr, size_t len ) {
	return sodium_mlock( addr, len );
}

int sqrl_munlock( void * const addr, size_t len ) {
	return sodium_munlock( addr, len );
}

int sqrl_mprotect_noaccess( void *ptr) {
	return sodium_mprotect_noaccess( ptr );
}

int sqrl_mprotect_readwrite( void *ptr ) {
	return sodium_mprotect_readwrite( ptr );
}

int sqrl_mprotect_readonly( void *ptr ) {
	return sodium_mprotect_readonly( ptr );
}

void sqrl_randombytes( void *ptr, size_t len ) {
	randombytes_buf( ptr, len );
}

uint32_t sqrl_random() {
	return randombytes_random();
}

void sqrl_memzero( void *buf, size_t len ) {
#ifdef ARDUINO
	size_t i = 0;
	uint8_t *ptr = (uint8_t*)buf;
	while( i < len ) {
		ptr[i] = 0;
		i++;
	}
#else
	sodium_memzero( buf, len );
#endif
}

int sqrl_memcmp( const void * const b1_, const void * const b2_, size_t len ) {
#ifdef ARDUINO
	const volatile unsigned char *volatile b1 =
		(const volatile unsigned char * volatile)b1_;
	const volatile unsigned char *volatile b2 =
		(const volatile unsigned char * volatile)b2_;
	size_t               i;
	unsigned char        d = (unsigned char)0U;

	for( i = 0U; i < len; i++ ) {
		d |= b1[i] ^ b2[i];
	}
	return (1 & ((d - 1) >> 8)) - 1;
#else
	return sodium_memcmp( b1_, b2_, len );
#endif
}

void * sqrl_malloc( const size_t size ) {
#ifdef ARDUINO
	void *ptr;

	if( (ptr = malloc( size )) == NULL ) {
		return NULL;
	}
	memset( ptr, 0, size );

	return ptr;
#else
	return sodium_malloc( size );
#endif
}

void sqrl_free( void *ptr, size_t len ) {
#ifdef ARDUINO
	sqrl_memzero( ptr, len );
	free( ptr );
	return NULL;
#else
	sodium_free( ptr );
#endif
}

bool sqrl_parse_key_value( char **strPtr, char **keyPtr, char **valPtr,
    size_t *key_len, size_t *val_len, char *sep )
{
    if( !*strPtr ) return false;
    char *p, *pp;
    p = strchr( *strPtr, '=' );
    if( p ) {
        *keyPtr = *strPtr;
        *key_len = p - *keyPtr;
        *valPtr = p + 1;
        pp = strstr( *valPtr, sep );
        if( pp ) {
            *val_len = pp - *valPtr;
            *strPtr = pp + strlen( sep );
        } else {
            *val_len = strlen( *valPtr );
            *strPtr = NULL;
        }
        return true;
    }
    *strPtr = NULL;
    return false;
}


size_t Sqrl_Version( char *buffer, size_t buffer_len ) {
	static const char *ver = SQRL_LIB_VERSION;
	size_t len = strlen( ver );
	if( buffer ) {
		strncpy( buffer, ver, buffer_len );
	}
	return len;
}

uint16_t Sqrl_Version_Major() { return SQRL_LIB_VERSION_MAJOR; }
uint16_t Sqrl_Version_Minor() { return SQRL_LIB_VERSION_MINOR; }
uint16_t Sqrl_Version_Build() { return SQRL_LIB_VERSION_BUILD_DATE; }
uint16_t Sqrl_Version_Revision() { return SQRL_LIB_VERSION_REVISION; }
