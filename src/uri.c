/** @file uri.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

/**
Creates a copy of a \p Sqrl_Uri object.

\warning Allocates memory for a new \p Sqrl_Uri object!  Free it with \p sqrl_uri_free() when done!

@param original The \p Sqrl_Uri object to copy.
@return An identical copy of \p original.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "sqrl_internal.h"

DLL_PUBLIC
Sqrl_Uri *sqrl_uri_create_copy( Sqrl_Uri *original )
{
	size_t sz;
	if( !original ) return NULL;
	Sqrl_Uri *nuri = calloc( sizeof( Sqrl_Uri ), 1 );
	if( !nuri ) return NULL;
	if( original->challenge ) {
		sz = strlen( original->challenge );
		nuri->challenge = calloc( sz + 1, 1 );
		if( nuri->challenge ) 
			memcpy( nuri->challenge, original->challenge, sz );
	}
	if( original->host ) {
		sz = strlen( original->host );
		nuri->host = calloc( sz + 1, 1 );
		if( nuri->host )
			memcpy( nuri->host, original->host, sz );
	}
	if( original->url ) {
		sz = strlen( original->url );
		nuri->url = calloc( sz + 1, 1 );
		if( nuri->url )
			memcpy( nuri->url, original->url, sz );
	}
	if( original->scheme ) {
		sz = strlen( original->scheme );
		nuri->scheme = calloc( sz + 1, 1 );
		if( nuri->scheme )
			memcpy( nuri->scheme, original->scheme, sz );
	}
	return nuri;
}

/*
 * URL Parsing function borrowed (with modifications) from:
 * 
 * Copyright 2010-2011 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai
 */

static __inline__ int _is_scheme_char(int);

static __inline__ int
_is_scheme_char(int c)
{
	return (!isalpha(c) && '+' != c && '-' != c && '.' != c) ? 0 : 1;
}

static void _fix_divider( char *uri ) {
	char *p = strstr( uri, "//" );
	if( p ) {
		p += 2;
		p = strstr( p, "//" );
	}
	if( p ) {
//		p[0] = '|';
		p++;

		while( *p ) {
			p[0] = p[1];
			p++;
		}
	}
}

/**
Parses a SQRL URL and returns a \p Sqrl_Uri object

\warning Allocates a new \p Sqrl_Uri object!

@param theUrl NULL terminated SQRL URL string
@return A new \p Sqrl_Uri object
*/
DLL_PUBLIC
Sqrl_Uri * sqrl_uri_parse(const char *theUrl)
{
	Sqrl_Uri *puri = NULL;
	const char *tmpstr;
	const char *curstr;
	int len;
	int i;
	int userpass_flag;
	int bracket_flag;
	char *host = NULL, 
		 *port = NULL, 
		 *path = NULL, 
		 *query = NULL, 
		 *fragment = NULL, 
		 *username = NULL, 
		 *password = NULL;
	
	UT_string *prefix = NULL;
	char *uri = malloc( strlen( theUrl ) + 1 );
	strcpy( uri, theUrl );
//	_fix_divider( uri );

	/* Allocate the parsed uri storage */
	puri = calloc(sizeof(Sqrl_Uri),1);
	if( puri == NULL ) goto ERROR;

	curstr = uri;
	
	/*
	 * <scheme>:<scheme-specific-part>
	 * <scheme> := [a-z\+\-\.]+
	 *             upper case = lower case for resiliency
	 */
	/* Read scheme */
	tmpstr = strchr(curstr, ':');
	if ( NULL == tmpstr ) goto ERROR;
	
	/* Get the scheme length */
	len = tmpstr - curstr;
	/* Check restrictions */
	for ( i = 0; i < len; i++ ) {
		if ( !_is_scheme_char(curstr[i]) ) goto ERROR;
	}
	/* Copy the scheme to the storage */
	puri->scheme = malloc(sizeof(char) * (len + 1));
	if ( NULL == puri->scheme ) goto ERROR;
	
	(void)strncpy(puri->scheme, curstr, len);
	puri->scheme[len] = '\0';
	sqrl_lcstr( puri->scheme );
	/* Skip ':' */
	tmpstr++;
	curstr = tmpstr;
	
	/*
	 * //<user>:<password>@<host>:<port>/<uri-path>
	 * Any ":", "@" and "/" must be encoded.
	 */
	/* Eat "//" */
	for ( i = 0; i < 2; i++ ) {
		if ( '/' != *curstr ) goto ERROR;
		curstr++;
	}
	
	/* Check if the user (and password) are specified. */
	userpass_flag = 0;
	tmpstr = curstr;
	while ( '\0' != *tmpstr ) {
		if ( '@' == *tmpstr ) {
			/* Username and password are specified */
			userpass_flag = 1;
			break;
		} else if ( '/' == *tmpstr ) {
			/* End of <host>:<port> specification */
			userpass_flag = 0;
			break;
		}
		tmpstr++;
	}
	
	/* User and password specification */
	tmpstr = curstr;
	if ( userpass_flag ) {
		/* Read username */
		while ( '\0' != *tmpstr && ':' != *tmpstr && '@' != *tmpstr ) {
			tmpstr++;
		}
		len = tmpstr - curstr;
		username = malloc(sizeof(char) * (len + 1));
		if ( NULL == username ) goto ERROR;
		(void)strncpy(username, curstr, len);
		username[len] = '\0';
	/* Proceed current pointer */
	curstr = tmpstr;
	if ( ':' == *curstr ) {
		/* Skip ':' */
		curstr++;
		/* Read password */
		tmpstr = curstr;
		while ( '\0' != *tmpstr && '@' != *tmpstr ) {
			tmpstr++;
		}
		len = tmpstr - curstr;
		password = malloc(sizeof(char) * (len + 1));
		if ( NULL == password ) goto ERROR;
		(void)strncpy(password, curstr, len);
		password[len] = '\0';
	curstr = tmpstr;
	}
	/* Skip '@' */
	if ( '@' != *curstr ) goto ERROR;
	curstr++;
	}
	
	if ( '[' == *curstr ) {
		bracket_flag = 1;
	} else {
		bracket_flag = 0;
	}
	/* Proceed on by delimiters with reading host */
	tmpstr = curstr;
	while ( '\0' != *tmpstr ) {
		if ( bracket_flag && ']' == *tmpstr ) {
			/* End of IPv6 address. */
			tmpstr++;
			break;
		} else if ( !bracket_flag && (':' == *tmpstr || '/' == *tmpstr) ) {
			/* Port number is specified. */
			break;
		}
		tmpstr++;
	}
	len = tmpstr - curstr;
	host = malloc(sizeof(char) * (len + 1));
	if ( NULL == host || len <= 0 ) goto ERROR;
	(void)strncpy(host, curstr, len);
	host[len] = '\0';
	curstr = tmpstr;
	
	/* Is port number specified? */
	if ( ':' == *curstr ) {
		curstr++;
		/* Read port number */
		tmpstr = curstr;
		while ( '\0' != *tmpstr && '/' != *tmpstr ) {
			tmpstr++;
		}
		len = tmpstr - curstr;
		port = malloc(sizeof(char) * (len + 1));
		if ( NULL == port ) goto ERROR;
		(void)strncpy(port, curstr, len);
		port[len] = '\0';
	curstr = tmpstr;
	}
	
	/* End of the string */
	if ( '\0' == *curstr ) {
		goto SQRL;
	}
	
	/* Skip '/' */
	if ( '/' != *curstr ) goto ERROR;
	curstr++;
	
	/* Parse path */
	tmpstr = curstr;
	while ( '\0' != *tmpstr && '#' != *tmpstr  && '?' != *tmpstr ) {
		tmpstr++;
	}
	len = tmpstr - curstr;
	path = malloc(sizeof(char) * (len + 1));
	if ( NULL == path ) goto ERROR;
	
	(void)strncpy(path, curstr, len);
	path[len] = '\0';
	curstr = tmpstr;
	
	/* Is query specified? */
	if ( '?' == *curstr ) {
		/* Skip '?' */
		curstr++;
		/* Read query */
		tmpstr = curstr;
		while ( '\0' != *tmpstr && '#' != *tmpstr ) {
			tmpstr++;
		}
		len = tmpstr - curstr;
		query = malloc(sizeof(char) * (len + 1));
		if ( NULL == query ) goto ERROR;
		
		(void)strncpy(query, curstr, len);
		query[len] = '\0';
	curstr = tmpstr;
	}
	
	/* Is fragment specified? */
	if ( '#' == *curstr ) {
		/* Skip '#' */
		curstr++;
		/* Read fragment */
		tmpstr = curstr;
		while ( '\0' != *tmpstr ) {
			tmpstr++;
		}
		len = tmpstr - curstr;
		fragment = malloc(sizeof(char) * (len + 1));
		if ( NULL == fragment ) goto ERROR;
		
		(void)strncpy(fragment, curstr, len);
		fragment[len] = '\0';
	curstr = tmpstr;
	}
	
	/* SQRL Specific... */
SQRL:
	if( 0 == strcmp( puri->scheme, "sqrl" )) {
		puri->url = (char*) malloc( strlen( uri ) + 2 );
		strcpy( puri->url + 1, theUrl );
		memcpy( puri->url, "https", 5 );
		utstring_new( prefix );
		utstring_bincpy( prefix, "https://", 8 );
	} else if( 0 == strcmp( puri->scheme, "file" )) {
		// File
		puri->url = (char*) malloc( strlen( uri ) - 6 );
		strcpy( puri->url, theUrl + 7 );
		goto END;
	} else {
		// Invalid Scheme
		goto ERROR;
	}
	puri->challenge = (char*) malloc( strlen( uri ) + 1 );
	if( puri->challenge == NULL || puri->url == NULL ) goto ERROR;

	strcpy( puri->challenge, theUrl );

/*
	if( puri->scheme[0] == 's' ) {
		memcpy( puri->url, "https", 5 );
		utstring_bincpy( prefix, "https://", 8 );
	} else if( puri->scheme[0] == 'q' ) {
		memcpy( puri->url, "http", 4 );
		utstring_bincpy( prefix, "http://", 7 );
	} else {
		goto ERROR;
	}
*/
	size_t hl = strlen( host );
	size_t pl = 0;
	size_t ul = hl + 1;
	char *pp = NULL;
	if( path ) {
		pp = strstr( path, "//" );
		if( pp ) {
			pl = pp - path;
		}
	}
	if( pl ) ul += pl + 1;
	puri->host = (char*) calloc( ul, 1 );
	if( puri->host == NULL ) goto ERROR;
	strcpy( puri->host, host );
	utstring_bincpy( prefix, host, strlen( host ));
	if( port ) {
		utstring_printf( prefix, ":%s", port );
	}
	if( pl ) {
		puri->host[hl] = '/';
		strncpy( puri->host + hl + 1, path, pl );
		_fix_divider( puri->url );
	}
	puri->prefix = (char*) malloc( utstring_len( prefix ));
	if( puri->prefix == NULL ) goto ERROR;
	strcpy( puri->prefix, utstring_body( prefix ));
	goto END;

ERROR:
	if( puri ) {
		sqrl_uri_free( puri );
	}
	puri = NULL;
	
END:
	if( host ) free( host );
	if( port ) free( port );
	if( query ) free( query );
	if( fragment ) free( fragment );
	if( username ) free( username );
	if( password ) free( password );
	if( prefix ) utstring_free( prefix );
	if( uri ) free( uri );
	return puri;
}

/**
Frees the memory allocated to a \p Sqrl_Uri object

@param uri the \p Sqrl_Uri object
@return NULL
*/
DLL_PUBLIC
Sqrl_Uri* sqrl_uri_free( Sqrl_Uri *uri )
{
	if ( uri ) {
		if( uri->challenge ) free( uri->challenge );
		if( uri->host ) free( uri->host );
		if( uri->prefix ) free( uri->prefix );
		if( uri->url ) free( uri->url );
		if( uri->scheme ) free( uri->scheme );
		free(uri);
	}
	return NULL;
}
