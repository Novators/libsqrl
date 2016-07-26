/** @file util.c -- Various utility functions 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "version.h"


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
	strncpy( buffer, ver, buffer_len );
	return len;
}

uint16_t Sqrl_Version_Major() { return SQRL_LIB_VERSION_MAJOR; }
uint16_t Sqrl_Version_Minor() { return SQRL_LIB_VERSION_MINOR; }
uint16_t Sqrl_Version_Build() { return SQRL_LIB_VERSION_BUILD_DATE; }
uint16_t Sqrl_Version_Revision() { return SQRL_LIB_VERSION_REVISION; }
