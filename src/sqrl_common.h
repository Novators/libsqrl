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

// SQRL_BASE64_PAD_CHAR = 0x3D for = padding.
// SQRL_BASE64_PAD_CHAR = 0x00 for no padding.
#define SQRL_BASE64_PAD_CHAR 				  0x00

#define B56C_GROUP_SEP " "
#define B56C_LINE_SEP "\n"

// Buffer sizes for keys, etc...
#define SQRL_KEY_SIZE 						    32
#define SQRL_SIG_SIZE 						    64

#define SQRL_OPTION_TOKEN_NOIPTEST		"noiptest"
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

/**
A structure to hold information about a parsed SQRL URI
*/
typedef struct Sqrl_Uri {
	/** The entire SQRL URL */
	char *challenge;
	/** The domain + extension */
	char *host;
	/** Internal use */
	char *prefix;
	/** the https url */
	char *url;
	/** Internal use */
	Sqrl_Scheme scheme;
} Sqrl_Uri;

Sqrl_Uri*	sqrl_uri_create_copy( Sqrl_Uri *original );
Sqrl_Uri*	sqrl_uri_parse(const char *);
Sqrl_Uri*	sqrl_uri_free(struct Sqrl_Uri *);

/** @} */ // endgroup URI



typedef enum {
	SQRL_CMD_QUERY,
	SQRL_CMD_IDENT,
	SQRL_CMD_DISABLE,
	SQRL_CMD_ENABLE,
	SQRL_CMD_REMOVE
} Sqrl_Cmd;

typedef enum {
	SQRL_TIF_ID_MATCH 					 = 0x0001,
	SQRL_TIF_PREVIOUS_ID_MATCH 			 = 0x0002,
	SQRL_TIF_IP_MATCH 					 = 0x0004,
	SQRL_TIF_SQRL_DISABLED 				 = 0x0008,
	SQRL_TIF_FUNCTION_NOT_SUPPORTED 	 = 0x0010,
	SQRL_TIF_TRANSIENT_ERROR 			 = 0x0020,
	SQRL_TIF_COMMAND_FAILURE 			 = 0x0040,
	SQRL_TIF_CLIENT_FAILURE 			 = 0x0080
} Sqrl_Tif;

/**
\defgroup encdec Encoding Functions

Functions for encoding and decoding data in various formats.  We use the
[UT_string](http://troydhanson.github.io/uthash/utstring.html) macros by Troy Hanson
for easy string handling.  There are functions for URL-encoding (aka %-encoding) and SQRL's
slightly modified base64url encoding.

@{ */
size_t          sqrl_b56c_validate( UT_string *dest, const char *src, size_t src_len, bool format );
UT_string*      sqrl_b56_encode( UT_string *dest, const uint8_t *src, size_t src_len );
UT_string*      sqrl_b56_encode_append( UT_string *dest, const uint8_t *src, size_t src_len );
UT_string*      sqrl_b56_decode( UT_string *dest, const char *src, size_t src_len );
UT_string*      sqrl_b56_decode_append( UT_string *dest, const char *src, size_t src_len );
UT_string*      sqrl_b56c_encode( UT_string *dest, const char *src, size_t src_len );
UT_string*      sqrl_b56c_encode_append( UT_string *dest, const char *src, size_t src_len );
UT_string*      sqrl_b56c_decode( UT_string *dest, const char *src, size_t src_len );
UT_string*      sqrl_b56c_decode_append( UT_string *dest, const char *src, size_t src_len );

UT_string*	sqrl_b64u_encode( UT_string *dest, const uint8_t *src, size_t src_len );
UT_string*	sqrl_b64u_encode_append( UT_string *dest, const uint8_t *src, size_t src_len );
UT_string*	sqrl_b64u_decode( UT_string * dest, const char *src, size_t src_len );
UT_string*	sqrl_b64u_decode_append( UT_string *dest, const char *src, size_t src_len );

UT_string*	sqrl_urldecode( UT_string *dest, const char *src );
UT_string*	sqrl_urlencode( UT_string *dest, const char *src );
uint32_t	sqrl_hex2uint( const char *hex );
/** @} */ // endgroup encdec

/** \defgroup util Utility Functions

@{ */

int sqrl_init();
int sqrl_stop();

void sqrl_lcstr( char * );

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
