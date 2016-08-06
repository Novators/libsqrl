/** \file SqrlUri.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include <new>
#include <ctype.h>
#include "sqrl_internal.h"
#include "SqrlUri.h"
#include "SqrlBase64.h"

Sqrl_Scheme SqrlUri::getScheme() {
	return this->scheme;
}
char* SqrlUri::getChallenge() {
	if (this->challenge == NULL) return NULL;
	size_t len = strlen( this->challenge );
	char *ret = (char*)malloc(len + 1);
	if( ret ) {
		memcpy( ret, this->challenge, len );
		ret[len] = 0;
	}
	return ret;
}
void SqrlUri::setChallenge(const char *val) {
	if (this->challenge) free(this->challenge);
	this->challenge = NULL;
	if (val) {
		size_t len = strlen( val );
		this->challenge = (char*)malloc(len + 1);
		if( this->challenge ) {
			memcpy( this->challenge, val, len );
			this->challenge[len] = 0;
		}
	}
}
void SqrlUri::setUrl(const char *val) {
	if (this->url) free(this->url);
	this->url = NULL;
	if (val) {
		size_t len = strlen( val );
		this->url = (char*)malloc(len + 1);
		if( this->url ) {
			memcpy( this->url, val, len );
			this->url[len] = 0;
		}
	}
}
char* SqrlUri::getSiteKey() {
	if (this->siteKey == NULL) return NULL;
	size_t len = strlen( this->siteKey );
	char *ret = (char*)malloc(len + 1);
	if( ret ) {
		memcpy( ret, this->siteKey, len );
		ret[len] = 0;
	}
	return ret;
}
char* SqrlUri::getPrefix() {
	if (this->prefix == NULL) return NULL;
	size_t len = strlen( this->prefix );
	char *ret = (char*)malloc(len + 1);
	if( ret ) {
		memcpy( ret, this->prefix, len );
		ret[len] = 0;
	}
	return ret;
}
char* SqrlUri::getUrl() {
	if (this->url == NULL) return NULL;
	size_t len = strlen( this->url );
	char *ret = (char*)malloc(len + 1);
	if( ret ) {
		memcpy( ret, this->url, len );
		ret[len] = 0;
	}
	return ret;
}
char* SqrlUri::getSFN() {
	if (this->sfn == NULL) return NULL;
	size_t len = strlen( this->sfn );
	char *ret = (char*)malloc(len + 1);
	if( ret ) {
		memcpy( ret, this->sfn, len );
		ret[len] = 0;
	}
	return ret;
}
size_t SqrlUri::getChallengeLength() {
	if (this->challenge == NULL) return 0;
	return strlen(this->challenge);
}
size_t SqrlUri::getSiteKeyLength() {
	if (this->siteKey == NULL) return 0;
	return strlen(this->siteKey);
}
size_t SqrlUri::getPrefixLength() {
	if (this->prefix == NULL) return 0;
	return strlen(this->prefix);
}
size_t SqrlUri::getUrlLength() {
	if (this->url == NULL) return 0;
	return strlen(this->url);
}
size_t SqrlUri::getSFNLength() {
	if (this->sfn == NULL) return 0;
	return strlen(this->sfn);
}

SqrlUri::SqrlUri()
{
	this->challenge = NULL;
	this->siteKey = NULL;
	this->prefix = NULL;
	this->url = NULL;
	this->sfn = NULL;
	this->scheme = SQRL_SCHEME_INVALID;
}

SqrlUri* SqrlUri::copy() {
	SqrlUri *nuri = (SqrlUri*)malloc( sizeof( SqrlUri ) );
	if( nuri ) {
		new (nuri) SqrlUri();

		if( this->challenge ) {
			nuri->challenge = this->getChallenge();
		}
		if( this->siteKey ) {
			nuri->siteKey = this->getSiteKey();
		}
		if( this->prefix ) {
			nuri->prefix = this->getPrefix();
		}
		if( this->url ) {
			nuri->url = this->getUrl();
		}
		if( this->sfn ) {
			nuri->sfn = this->getSFN();
		}
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

static int _is_scheme_char(int);

static int _is_scheme_char(int c)
{
	return (!isalpha(c) && '+' != c && '-' != c && '.' != c) ? 0 : 1;
}

static void sqrl_lcstr( char *str ) {
	int i;
	for( i = 0; str[i] != 0; i++ ) {
		if( str[i] > 64 && str[i] < 91 ) {
			str[i] += 32;
		}
	}
}

/**
Parses a SQRL URL and returns a \p SqrlUri object

\warning Allocates a new \p SqrlUri object!

@param theUrl NULL terminated SQRL URL string
@return A new \p SqrlUri object
*/
SqrlUri *SqrlUri::parse( SqrlString *source ) {
	SqrlUri *theUri = (SqrlUri*)malloc( sizeof( SqrlUri ) );
	new (theUri) SqrlUri();

	const char *tmpstr;
	const char *curstr;
	size_t len;
	size_t i;
	int userpass_flag;
	int bracket_flag;
	char *host = NULL,
		*port = NULL,
		*path = NULL,
		*query = NULL,
		*fragment = NULL,
		*username = NULL,
		*password = NULL,
		*sch = NULL,
		*pp = NULL,
		*ppp = NULL;
	size_t hl;
	long pl;
	size_t ul;

	SqrlString *prefix = NULL;
	SqrlString uri = SqrlString( source );

	curstr = uri.string();

	/*
	* <scheme>:<scheme-specific-part>
	* <scheme> := [a-z\+\-\.]+
	*             upper case = lower case for resiliency
	*/
	/* Read scheme */
	tmpstr = strchr( curstr, ':' );
	if( NULL == tmpstr ) goto ERR;

	/* Get the scheme length */
	len = (int)(tmpstr - curstr);
	/* Check restrictions */
	for( i = 0; i < len; i++ ) {
		if( !_is_scheme_char( curstr[i] ) ) goto ERR;
	}
	/* Copy the scheme to the storage */
	sch = (char*)malloc( len + 1 );
	if( NULL == sch ) goto ERR;
	memcpy( sch, curstr, len );
	sch[len] = 0;
	sqrl_lcstr( sch );
	if( strcmp( sch, "sqrl" ) == 0 ) theUri->scheme = SQRL_SCHEME_SQRL;
	else if( strcmp( sch, "file" ) == 0 ) theUri->scheme = SQRL_SCHEME_FILE;
	else {
		free( sch );
		goto ERR;
	}
	free( sch );

	/* Skip ':' */
	tmpstr++;
	curstr = tmpstr;

	/*
	* //<user>:<password>@<host>:<port>/<uri-path>
	* Any ":", "@" and "/" must be encoded.
	*/
	/* Eat "//" */
	for( i = 0; i < 2; i++ ) {
		if( '/' != *curstr ) goto ERR;
		curstr++;
	}

	/* Check if the user (and password) are specified. */
	userpass_flag = 0;
	tmpstr = curstr;
	while( '\0' != *tmpstr ) {
		if( '@' == *tmpstr ) {
			/* Username and password are specified */
			userpass_flag = 1;
			break;
		} else if( '/' == *tmpstr ) {
			/* End of <host>:<port> specification */
			userpass_flag = 0;
			break;
		}
		tmpstr++;
	}

	/* User and password specification */
	tmpstr = curstr;
	if( userpass_flag ) {
		/* Read username */
		while( '\0' != *tmpstr && ':' != *tmpstr && '@' != *tmpstr ) {
			tmpstr++;
		}
		len = (int)(tmpstr - curstr);
		username = (char*)malloc( len + 1 );
		memcpy( username, curstr, len );
		username[len] = 0;
		/* Proceed current pointer */
		curstr = tmpstr;
		if( ':' == *curstr ) {
			/* Skip ':' */
			curstr++;
			/* Read password */
			tmpstr = curstr;
			while( '\0' != *tmpstr && '@' != *tmpstr ) {
				tmpstr++;
			}
			len = (int)(tmpstr - curstr);
			password = (char*)malloc( len + 1 );
			if( NULL == password ) goto ERR;
			memcpy( password, curstr, len );
			password[len] = '\0';
			curstr = tmpstr;
		}
		/* Skip '@' */
		if( '@' != *curstr ) goto ERR;
		curstr++;
	}

	if( '[' == *curstr ) {
		bracket_flag = 1;
	} else {
		bracket_flag = 0;
	}
	/* Proceed on by delimiters with reading host */
	tmpstr = curstr;
	while( '\0' != *tmpstr ) {
		if( bracket_flag && ']' == *tmpstr ) {
			/* End of IPv6 address. */
			tmpstr++;
			break;
		} else if( !bracket_flag && (':' == *tmpstr || '/' == *tmpstr) ) {
			/* Port number is specified. */
			break;
		}
		tmpstr++;
	}
	len = (int)(tmpstr - curstr);
	if( len ) {
		host = (char*)malloc( len + 1 );
		if( ! host ) goto ERR;
		memcpy( host, curstr, len );
		host[len] = '\0';
	}
	curstr = tmpstr;

	/* Is port number specified? */
	if (':' == *curstr) {
		curstr++;
		/* Read port number */
		tmpstr = curstr;
		while ('\0' != *tmpstr && '/' != *tmpstr) {
			tmpstr++;
		}
		len = (int)(tmpstr - curstr);
		port = (char*)malloc(len+1);
		if (NULL == port) goto ERR;
		memcpy( port, curstr, len );
		port[len] = '\0';
		curstr = tmpstr;
	}

	/* End of the string */
	if ('\0' == *curstr) {
		goto SQRL;
	}

	/* Skip '/' */
	if ('/' != *curstr) goto ERR;
	curstr++;

	/* Parse path */
	tmpstr = curstr;
	while ('\0' != *tmpstr && '#' != *tmpstr  && '?' != *tmpstr) {
		tmpstr++;
	}
	len = (int)(tmpstr - curstr);
	path = (char*)malloc(len+1);
	if (NULL == path) goto ERR;
	memcpy( path, curstr, len );
	path[len] = '\0';
	curstr = tmpstr;

	/* Is query specified? */
	if ('?' == *curstr) {
		/* Skip '?' */
		curstr++;
		/* Read query */
		tmpstr = curstr;
		while ('\0' != *tmpstr && '#' != *tmpstr) {
			tmpstr++;
		}
		len = (int)(tmpstr - curstr);
		query = (char*)malloc(len+1);
		if (NULL == query) goto ERR;
		memcpy( query, curstr, len );
		query[len] = '\0';
		curstr = tmpstr;
	}

	/* Is fragment specified? */
	if ('#' == *curstr) {
		/* Skip '#' */
		curstr++;
		/* Read fragment */
		tmpstr = curstr;
		while ('\0' != *tmpstr) {
			tmpstr++;
		}
		len = (int)(tmpstr - curstr);
		fragment = (char*)malloc(len+1);
		if (NULL == fragment) goto ERR;
		memcpy( fragment, curstr, len );
		fragment[len] = '\0';
	}

	/* SQRL Specific... */
SQRL:
	switch (theUri->scheme) {
	case SQRL_SCHEME_SQRL:
		len = uri.length();
		theUri->url = (char*)malloc(len+2);
		memcpy( theUri->url + 1, uri.string(), len );
		memcpy(theUri->url, "https", 5);
		theUri->url[len+1] = 0;
		prefix = new SqrlString( "https://" );
		break;
	case SQRL_SCHEME_FILE:
		len = uri.length();
		theUri->url = (char*)malloc(len+1);
		if( !theUri->url ) goto ERR;
		memcpy(theUri->url, uri.string(), len);
		theUri->url[len] = 0;
		len -= 7;
		theUri->challenge = (char*)malloc(len+1);
		if( !theUri->challenge ) goto ERR;
		memcpy(theUri->challenge, uri.string() + 7, len);
		theUri->challenge[len] = 0;
		goto END;
	default:
		goto ERR;
	}
	len = source->length();
	theUri->challenge = (char*)malloc(len+1);
	if (theUri->challenge == NULL || theUri->url == NULL) goto ERR;
	memcpy(theUri->challenge, source->string(), len);
	theUri->challenge[len] = 0;

	hl = strlen(host);
	pl = 0;
	ul = hl;
	pp = NULL;
	ppp = NULL;
	if (query) {
		pp = strstr(query, "sfn=");
		if (!pp) {
			goto ERR;
		}
		pp += 4;
		ppp = strchr(pp, '&');
		if (ppp) {
			pl = (int)(ppp - pp);
		} else {
			pl = (long)strlen(pp);
		}
		char *utsfnsrcsrc = (char*)malloc( pl + 1 );
		memcpy( utsfnsrcsrc, pp, pl );
		utsfnsrcsrc[pl] = 0;
		SqrlString *utsfnsrc = new SqrlString( utsfnsrcsrc );
		free( utsfnsrcsrc );
		if( utsfnsrc ) {
			SqrlString *utsfn = SqrlBase64().decode( NULL, utsfnsrc );
			if( utsfn ) {
				theUri->sfn = (char*)calloc( 1, utsfn->length() + 1 );
				memcpy( theUri->sfn, utsfn->cdata(), utsfn->length() );
				delete utsfn;
			}
			delete utsfnsrc;
		}
		pl = 0;
		pp = strstr(query, "x=");
		if (pp) {
			pp += 2;
			pl = strtol(pp, NULL, 10);
		}
	}
	if (pl) ul += pl + 1;
	theUri->siteKey = (char*)malloc(ul+1);
	if (theUri->siteKey == NULL) goto ERR;
	memcpy( theUri->siteKey, host, hl );
	theUri->siteKey[ul] = 0;
	prefix->append( host );
	if (port) {
		prefix->append( ":" );
		prefix->append( port );
	}
	if (pl) {
		theUri->siteKey[hl] = '/';
		strncpy(theUri->siteKey + hl + 1, path, pl);
	}
	len = prefix->length();
	theUri->prefix = (char*)malloc(len + 1);
	if (theUri->prefix == NULL) goto ERR;
	memcpy(theUri->prefix, prefix->cdata(), len);
	theUri->prefix[len] = 0;
	goto END;

ERR:
	theUri->~SqrlUri();
	theUri = NULL;

END:
	if (host) free(host);
	if (port) free(port);
	if (query) free(query);
	if (fragment) free(fragment);
	if (username) free(username);
	if (password) free(password);
	if (path) free(path);
	if (prefix) delete prefix;
	return theUri;
}

/**
Frees the memory allocated to a \p SqrlUri object

@param uri the \p SqrlUri object
@return NULL
*/

SqrlUri::~SqrlUri() {
	if (this->challenge) free(this->challenge);
	if (this->siteKey) free(this->siteKey);
	if (this->prefix) free(this->prefix);
	if (this->url) free(this->url);
	if (this->sfn) free(this->sfn);
	free( this );
}

SqrlUri *SqrlUri::release() {
	this->~SqrlUri();
	return NULL;
}
