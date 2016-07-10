/** @file sqrl_common.h 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/  
#ifndef SQRL_COMMON_H_INCLUDED
#define SQRL_COMMON_H_INCLUDED

#include <stdint.h>
#include <stdbool.h>
#include "utstring.h"

#ifndef DLL_PUBLIC
#define DLL_PUBLIC _declspec(dllimport)
#endif

// SQRL_BASE64_PAD_CHAR = 0x3D for = padding.
// SQRL_BASE64_PAD_CHAR = 0x00 for no padding.
#define SQRL_BASE64_PAD_CHAR 				  0x00

// Buffer sizes for keys, etc...
#define SQRL_KEY_SIZE 						    32
#define SQRL_SIG_SIZE 						    64

#define SQRL_OPTION_TOKEN_SQRLONLY      "sqrlonly"
#define SQRL_OPTION_TOKEN_HARDLOCK      "hardlock"
#define SQRL_OPTION_TOKEN_CPS                "cps"
#define SQRL_OPTION_TOKEN_SUK                "suk"
#define SQRL_OPTION_TOKEN_SEPARATOR            '~'

/**
\defgroup URI SQRL URI Functions

@{ */

typedef enum {
	SQRL_SCHEME_INVALID = 0,
	SQRL_SCHEME_SQRL,
	SQRL_SCHEME_FILE
} Sqrl_Scheme;

#include "uri.h"

typedef enum {
	SQRL_CMD_QUERY,
	SQRL_CMD_IDENT,
	SQRL_CMD_DISABLE,
	SQRL_CMD_ENABLE,
	SQRL_CMD_REMOVE
} Sqrl_Cmd;

typedef unsigned int Sqrl_Tif;

#define SQRL_TIF_ID_MATCH 					 0x0001
#define SQRL_TIF_PREVIOUS_ID_MATCH 			 0x0002
#define SQRL_TIF_IP_MATCH 					 0x0004
#define SQRL_TIF_SQRL_DISABLED 				 0x0008
#define SQRL_TIF_FUNCTION_NOT_SUPPORTED 	 0x0010
#define SQRL_TIF_TRANSIENT_ERR 				 0x0020
#define SQRL_TIF_COMMAND_FAILURE 			 0x0040
#define SQRL_TIF_CLIENT_FAILURE 			 0x0080

/**
\defgroup encdec Encoding Functions

Functions for encoding and decoding data in various formats.  We use the 
[UT_string](http://troydhanson.github.io/uthash/utstring.html) macros by Troy Hanson
for easy string handling.  There are functions for URL-encoding (aka %-encoding) and SQRL's
slightly modified base64url encoding.

@{ */
DLL_PUBLIC UT_string*	sqrl_b64u_decode( UT_string * dest, const char *src, size_t src_len );
DLL_PUBLIC void 		sqrl_b64u_decode_append( UT_string *dest, const char *src, size_t src_len );
DLL_PUBLIC UT_string*	sqrl_b64u_encode( UT_string *dest, const uint8_t *src, size_t src_len );
DLL_PUBLIC void 		sqrl_b64u_encode_append( UT_string *dest, const uint8_t *src, size_t src_len );
DLL_PUBLIC uint32_t	sqrl_hex2uint( const char *hex );
DLL_PUBLIC UT_string*	sqrl_urldecode( UT_string *dest, const char *src );
DLL_PUBLIC UT_string*	sqrl_urlencode( UT_string *dest, const char *src );
/** @} */ // endgroup encdec

/** \defgroup util Utility Functions

@{ */

DLL_PUBLIC int 		sqrl_init();
DLL_PUBLIC int         sqrl_stop();

/**
Get a string representing the version of SQRL lib in use

@param buffer A char buffer to hold the string
@param buffer_len the length of \p buffer
@return size_t The length of the string copied to \p buffer
@return 0 \p buffer was NULL or \p buffer_len too short
*/
size_t		Sqrl_Version( char *buffer, size_t buffer_len );

/**
SQRL lib version

@return int Major Version number
*/
int 		Sqrl_Version_Major();

/**
SQRL lib version

@return int Minor Version number
*/
int 		Sqrl_Version_Minor();

/**
SQRL lib version

@return int Build number
*/
int 		Sqrl_Version_Build();

/** @} */ // endgroup util





#endif // SQRL_COMMON_H_INCLUDED