/** @file url.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

/**
Creates a copy of a \p Sqrl_Url object.

\warning Allocates memory for a new \p Sqrl_Url object!  Free it with \p sqrl_url_free() when done!

@param original The \p Sqrl_Url object to copy.
@return An identical copy of \p original.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "sqrl_internal.h"

DLL_PUBLIC
Sqrl_Url *sqrl_url_create_copy( Sqrl_Url *original )
{
	size_t sz;
	if( !original ) return NULL;
	Sqrl_Url *nurl = calloc( sizeof( Sqrl_Url ), 1 );
	if( !nurl ) return NULL;
	if( original->challenge ) {
		sz = strlen( original->challenge );
		nurl->challenge = calloc( sz + 1, 1 );
		if( nurl->challenge ) 
			memcpy( nurl->challenge, original->challenge, sz );
	}
	if( original->host ) {
		sz = strlen( original->host );
		nurl->host = calloc( sz + 1, 1 );
		if( nurl->host )
			memcpy( nurl->host, original->host, sz );
	}
	if( original->url ) {
		sz = strlen( original->url );
		nurl->url = calloc( sz + 1, 1 );
		if( nurl->url )
			memcpy( nurl->url, original->url, sz );
	}
	if( original->scheme ) {
		sz = strlen( original->scheme );
		nurl->scheme = calloc( sz + 1, 1 );
		if( nurl->scheme )
			memcpy( nurl->scheme, original->scheme, sz );
	}
	return nurl;
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

static void _fix_divider( char *url ) {
	char *p = strstr( url, "//" );
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
Parses a SQRL URL and returns a \p Sqrl_Url object

\warning Allocates a new \p Sqrl_Url object!

@param theUrl NULL terminated SQRL URL string
@return A new \p Sqrl_Url object
*/
DLL_PUBLIC
Sqrl_Url * sqrl_url_parse(const char *theUrl)
{
	Sqrl_Url *purl = NULL;
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
	char *url = malloc( strlen( theUrl ) + 1 );
	strcpy( url, theUrl );
//	_fix_divider( url );

	/* Allocate the parsed url storage */
	purl = calloc(sizeof(Sqrl_Url),1);
	if( purl == NULL ) goto ERROR;

	curstr = url;
	
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
	purl->scheme = malloc(sizeof(char) * (len + 1));
	if ( NULL == purl->scheme ) goto ERROR;
	
	(void)strncpy(purl->scheme, curstr, len);
	purl->scheme[len] = '\0';
	sqrl_lcstr( purl->scheme );
	/* Skip ':' */
	tmpstr++;
	curstr = tmpstr;
	
	/*
	 * //<user>:<password>@<host>:<port>/<url-path>
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
	purl->challenge = (char*) malloc( strlen( url ) + 1 );
	purl->url = (char*) malloc( strlen( url ) + 2 );
	if( purl->challenge == NULL || purl->url == NULL ) goto ERROR;

	utstring_new( prefix );
	if( prefix == NULL ) goto ERROR;

	strcpy( purl->challenge, theUrl );
	strcpy( purl->url + 1, url );

	if( purl->scheme[0] == 's' ) {
		memcpy( purl->url, "https", 5 );
		utstring_bincpy( prefix, "https://", 8 );
	} else if( purl->scheme[0] == 'q' ) {
		memcpy( purl->url, "http", 4 );
		utstring_bincpy( prefix, "http://", 7 );
	} else {
		goto ERROR;
	}

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
	purl->host = (char*) calloc( ul, 1 );
	if( purl->host == NULL ) goto ERROR;
	strcpy( purl->host, host );
	utstring_bincpy( prefix, host, strlen( host ));
	if( port ) {
		utstring_printf( prefix, ":%s", port );
	}
	if( pl ) {
		purl->host[hl] = '/';
		strncpy( purl->host + hl + 1, path, pl );
		_fix_divider( purl->url );
	}
	purl->prefix = (char*) malloc( utstring_len( prefix ));
	if( purl->prefix == NULL ) goto ERROR;
	strcpy( purl->prefix, utstring_body( prefix ));
	goto END;

ERROR:
	if( purl ) {
		sqrl_url_free( purl );
	}
	purl = NULL;
	
END:
	if( host ) free( host );
	if( port ) free( port );
	if( query ) free( query );
	if( fragment ) free( fragment );
	if( username ) free( username );
	if( password ) free( password );
	if( prefix ) utstring_free( prefix );
	if( url ) free( url );
	return purl;
}

/**
Frees the memory allocated to a \p Sqrl_Url object

@param url the \p Sqrl_Url object
@return NULL
*/
DLL_PUBLIC
Sqrl_Url* sqrl_url_free( Sqrl_Url *url )
{
	if ( url ) {
		if( url->challenge ) free( url->challenge );
		if( url->host ) free( url->host );
		if( url->prefix ) free( url->prefix );
		if( url->url ) free( url->url );
		if( url->scheme ) free( url->scheme );
		free(url);
	}
	return NULL;
}
