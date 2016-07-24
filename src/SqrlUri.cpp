/** @file uri.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
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
	size_t len = strlen( this->challenge ) + 1;
	char *ret = (char*)malloc(len);
	strcpy_s(ret, len, this->challenge);
	return ret;
}
void SqrlUri::setChallenge(const char *val) {
	if (this->challenge) free(this->challenge);
	this->challenge = NULL;
	if (val) {
		size_t len = strlen( val ) + 1;
		this->challenge = (char*)malloc(len);
		strcpy_s(this->challenge, len, val);
	}
}
void SqrlUri::setUrl(const char *val) {
	if (this->url) free(this->url);
	this->url = NULL;
	if (val) {
		size_t len = strlen( val ) + 1;
		this->url = (char*)malloc(len);
		strcpy_s(this->url, len, val);
	}
}
char* SqrlUri::getSiteKeyString() {
	if (this->host == NULL) return NULL;
	size_t len = strlen( this->host ) + 1;
	char *ret = (char*)malloc(len);
	strcpy_s(ret, len, this->host);
	return ret;
}
char* SqrlUri::getPrefix() {
	if (this->prefix == NULL) return NULL;
	size_t len = strlen( this->prefix ) + 1;
	char *ret = (char*)malloc(len);
	strcpy_s(ret, len, this->prefix);
	return ret;
}
char* SqrlUri::getUrl() {
	if (this->url == NULL) return NULL;
	size_t len = strlen( this->url ) + 1;
	char *ret = (char*)malloc(len);
	strcpy_s(ret, len, this->url);
	return ret;
}
char* SqrlUri::getSFN() {
	if (this->sfn == NULL) return NULL;
	size_t len = strlen( this->sfn ) + 1;
	char *ret = (char*)malloc(len);
	strcpy_s(ret, len, this->sfn);
	return ret;
}
size_t SqrlUri::getChallengeLength() {
	if (this->challenge == NULL) return 0;
	return strlen(this->challenge);
}
size_t SqrlUri::getSiteKeyStringLength() {
	if (this->host == NULL) return 0;
	return strlen(this->host);
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
	this->host = NULL;
	this->prefix = NULL;
	this->url = NULL;
	this->sfn = NULL;
	this->scheme = SQRL_SCHEME_INVALID;
}

SqrlUri* SqrlUri::copy() {
	SqrlUri *nuri = (SqrlUri*)malloc( sizeof( SqrlUri ) );
	new (nuri) SqrlUri();
	size_t len;

	if (this->challenge) { 
		len = strlen( this->challenge ) + 1;
		nuri->challenge = (char*)malloc(len);
		strcpy_s(nuri->challenge, len, this->challenge);
	}
	if (this->host) {
		len = strlen( this->challenge ) + 1;
		nuri->host = (char*)malloc( len );
		strcpy_s(nuri->host, len, this->host);
	}
	if (this->prefix) {
		len = strlen( this->challenge ) + 1;
		nuri->prefix = (char*)malloc( len );
		strcpy_s(nuri->prefix, len, this->prefix);
	}
	if (this->url) {
		len = strlen( this->challenge ) + 1;
		nuri->url = (char*)malloc( len );
		strcpy_s(nuri->url, len, this->url);
	}
	if (this->sfn) {
		len = strlen( this->challenge ) + 1;
		nuri->sfn = (char*)malloc( len );
		strcpy_s(nuri->sfn, len, this->sfn);
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

/**
Parses a SQRL URL and returns a \p SqrlUri object

\warning Allocates a new \p SqrlUri object!

@param theUrl NULL terminated SQRL URL string
@return A new \p SqrlUri object
*/
SqrlUri *SqrlUri::parse(const char *source) {
	SqrlUri *theUri = (SqrlUri*)malloc( sizeof( SqrlUri ) );
	new (theUri) SqrlUri();

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
	size_t ln;

	std::string *prefix = NULL;
	ln = strlen( source ) + 1;
	char *uri = (char*)malloc(ln);
	strcpy_s(uri, ln, source);

	curstr = uri;

	/*
	* <scheme>:<scheme-specific-part>
	* <scheme> := [a-z\+\-\.]+
	*             upper case = lower case for resiliency
	*/
	/* Read scheme */
	tmpstr = strchr(curstr, ':');
	if (NULL == tmpstr) goto ERR;

	/* Get the scheme length */
	len = (int)(tmpstr - curstr);
	/* Check restrictions */
	for (i = 0; i < len; i++) {
		if (!_is_scheme_char(curstr[i])) goto ERR;
	}
	/* Copy the scheme to the storage */
	ln = sizeof( char ) * (len + 1);
	char *sch = (char*)malloc(ln);
	if (NULL == sch) goto ERR;

	(void)strncpy_s(sch, ln, curstr, len);
	sch[len] = '\0';
	sqrl_lcstr(sch);
	if (strcmp(sch, "sqrl") == 0) theUri->scheme = SQRL_SCHEME_SQRL;
	else if (strcmp(sch, "file") == 0) theUri->scheme = SQRL_SCHEME_FILE;
	else {
		free(sch);
		goto ERR;
	}
	free(sch);

	/* Skip ':' */
	tmpstr++;
	curstr = tmpstr;

	/*
	* //<user>:<password>@<host>:<port>/<uri-path>
	* Any ":", "@" and "/" must be encoded.
	*/
	/* Eat "//" */
	for (i = 0; i < 2; i++) {
		if ('/' != *curstr) goto ERR;
		curstr++;
	}

	/* Check if the user (and password) are specified. */
	userpass_flag = 0;
	tmpstr = curstr;
	while ('\0' != *tmpstr) {
		if ('@' == *tmpstr) {
			/* Username and password are specified */
			userpass_flag = 1;
			break;
		}
		else if ('/' == *tmpstr) {
			/* End of <host>:<port> specification */
			userpass_flag = 0;
			break;
		}
		tmpstr++;
	}

	/* User and password specification */
	tmpstr = curstr;
	if (userpass_flag) {
		/* Read username */
		while ('\0' != *tmpstr && ':' != *tmpstr && '@' != *tmpstr) {
			tmpstr++;
		}
		len = (int)(tmpstr - curstr);
		ln = sizeof( char ) * (len + 1);
		username = (char*)malloc(ln);
		if (NULL == username) goto ERR;
		(void)strncpy_s(username, ln, curstr, len);
		username[len] = '\0';
		/* Proceed current pointer */
		curstr = tmpstr;
		if (':' == *curstr) {
			/* Skip ':' */
			curstr++;
			/* Read password */
			tmpstr = curstr;
			while ('\0' != *tmpstr && '@' != *tmpstr) {
				tmpstr++;
			}
			len = (int)(tmpstr - curstr);
			ln = sizeof( char ) * (len + 1);
			password = (char*)malloc(ln);
			if (NULL == password) goto ERR;
			(void)strncpy_s(password, ln, curstr, len);
			password[len] = '\0';
			curstr = tmpstr;
		}
		/* Skip '@' */
		if ('@' != *curstr) goto ERR;
		curstr++;
	}

	if ('[' == *curstr) {
		bracket_flag = 1;
	}
	else {
		bracket_flag = 0;
	}
	/* Proceed on by delimiters with reading host */
	tmpstr = curstr;
	while ('\0' != *tmpstr) {
		if (bracket_flag && ']' == *tmpstr) {
			/* End of IPv6 address. */
			tmpstr++;
			break;
		}
		else if (!bracket_flag && (':' == *tmpstr || '/' == *tmpstr)) {
			/* Port number is specified. */
			break;
		}
		tmpstr++;
	}
	len = (int)(tmpstr - curstr);
	ln = sizeof( char ) * (len + 1);
	host = (char*)malloc(ln);
	if (NULL == host || len <= 0) goto ERR;
	(void)strncpy_s(host, ln, curstr, len);
	host[len] = '\0';
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
		ln = sizeof( char ) * (len + 1);
		port = (char*)malloc(ln);
		if (NULL == port) goto ERR;
		(void)strncpy_s(port, ln, curstr, len);
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
	ln = sizeof( char ) * (len + 1);
	path = (char*)malloc(ln);
	if (NULL == path) goto ERR;

	(void)strncpy_s(path, ln, curstr, len);
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
		ln = sizeof( char ) * (len + 1);
		query = (char*)malloc(ln);
		if (NULL == query) goto ERR;

		(void)strncpy_s(query, ln, curstr, len);
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
		ln = sizeof( char ) * (len + 1);
		fragment = (char*)malloc(ln);
		if (NULL == fragment) goto ERR;

		(void)strncpy_s(fragment, ln, curstr, len);
		fragment[len] = '\0';
	}

	/* SQRL Specific... */
SQRL:
	switch (theUri->scheme) {
	case SQRL_SCHEME_SQRL:
		ln = strlen( uri ) + 2;
		theUri->url = (char*)malloc(ln);
		strcpy_s(theUri->url + 1, ln - 1, uri);
		memcpy(theUri->url, "https", 5);
		prefix = new std::string( "https://" );
		break;
	case SQRL_SCHEME_FILE:
		ln = strlen( uri ) + 2;
		theUri->url = (char*)malloc(ln);
		strcpy_s(theUri->url, ln, uri);
		ln -= 8;
		theUri->challenge = (char*)malloc(ln);
		strcpy_s(theUri->challenge, ln, uri + 7);
		goto END;
	default:
		goto ERR;
	}
	ln = strlen( source ) + 1;
	theUri->challenge = (char*)malloc(ln);
	if (theUri->challenge == NULL || theUri->url == NULL) goto ERR;
	strcpy_s(theUri->challenge, ln, source);

	size_t hl = strlen(host);
	long pl = 0;
	size_t ul = hl + 1;
	char *pp = NULL;
	char *ppp = NULL;
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
		std::string *utsfnsrc = new std::string( pp, pl );
		if( utsfnsrc ) {
			std::string *utsfn = SqrlBase64().decode( NULL, utsfnsrc );
			if( utsfn ) {
				theUri->sfn = (char*)calloc( 1, utsfn->length() + 1 );
				memcpy( theUri->sfn, utsfn->data(), utsfn->length() );
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
	theUri->host = (char*)malloc(ul);
	if (theUri->host == NULL) goto ERR;
	strcpy_s(theUri->host, ul, host);
	prefix->append( host );
	if (port) {
		prefix->append( ":" );
		prefix->append( port );
	}
	if (pl) {
		theUri->host[hl] = '/';
		strncpy(theUri->host + hl + 1, path, pl);
	}
	ln = prefix->length() + 1;
	theUri->prefix = (char*)malloc(ln);
	if (theUri->prefix == NULL) goto ERR;
	strcpy_s(theUri->prefix, ln, prefix->data());
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
	if (uri) free(uri);
	return theUri;
}

/**
Frees the memory allocated to a \p SqrlUri object

@param uri the \p SqrlUri object
@return NULL
*/

SqrlUri::~SqrlUri() {
	if (this->challenge) free(this->challenge);
	if (this->host) free(this->host);
	if (this->prefix) free(this->prefix);
	if (this->url) free(this->url);
	if (this->sfn) free(this->sfn);
	free( this );
}

SqrlUri *SqrlUri::release() {
	this->~SqrlUri();
	return NULL;
}