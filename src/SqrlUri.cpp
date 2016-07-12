/** @file uri.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlUri.h"

Sqrl_Scheme SqrlUri::getScheme() {
	return this->scheme;
}
char* SqrlUri::getChallenge() {
	if (this->challenge == NULL) return NULL;
	char *ret = (char*)malloc(strlen(this->challenge)+1);
	strcpy(ret, this->challenge);
	return ret;
}
void SqrlUri::setChallenge(const char *val) {
	if (this->challenge) free(this->challenge);
	this->challenge = NULL;
	if (val) {
		this->challenge = (char*)malloc(strlen(val) + 1);
		strcpy(this->challenge, val);
	}
}
void SqrlUri::setUrl(const char *val) {
	if (this->url) free(this->url);
	this->url = NULL;
	if (val) {
		this->url = (char*)malloc(strlen(val) + 1);
		strcpy(this->url, val);
	}
}
char* SqrlUri::getHost() {
	if (this->host == NULL) return NULL;
	char *ret = (char*)malloc(strlen(this->host)+1);
	strcpy(ret, this->host);
	return ret;
}
char* SqrlUri::getPrefix() {
	if (this->prefix == NULL) return NULL;
	char *ret = (char*)malloc(strlen(this->prefix)+1);
	strcpy(ret, this->prefix);
	return ret;
}
char* SqrlUri::getUrl() {
	if (this->url == NULL) return NULL;
	char *ret = (char*)malloc(strlen(this->url)+1);
	strcpy(ret, this->url);
	return ret;
}
char* SqrlUri::getSFN() {
	if (this->sfn == NULL) return NULL;
	char *ret = (char*)malloc(strlen(this->sfn)+1);
	strcpy(ret, this->sfn);
	return ret;
}
size_t SqrlUri::getChallengeLength() {
	if (this->challenge == NULL) return 0;
	return strlen(this->challenge);
}
size_t SqrlUri::getHostLength() {
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
}

SqrlUri* SqrlUri::copy() {
	SqrlUri *nuri = new SqrlUri();

	if (this->challenge) { 
		nuri->challenge = (char*)malloc(strlen(this->challenge) + 1);
		strcpy(nuri->challenge, this->challenge);
	}
	if (this->host) {
		nuri->host = (char*)malloc(strlen(this->host) + 1);
		strcpy(nuri->host, this->host);
	}
	if (this->prefix) {
		nuri->prefix = (char*)malloc(strlen(this->prefix) + 1);
		strcpy(nuri->prefix, this->prefix);
	}
	if (this->url) {
		nuri->url = (char*)malloc(strlen(this->url) + 1);
		strcpy(nuri->url, this->url);
	}
	if (this->sfn) {
		nuri->sfn = (char*)malloc(strlen(this->sfn) + 1);
		strcpy(nuri->sfn, this->sfn);
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
SqrlUri::SqrlUri(const char *source) {
	this->challenge = NULL;
	this->host = NULL;
	this->prefix = NULL;
	this->url = NULL;
	this->sfn = NULL;
	this->scheme = SQRL_SCHEME_INVALID;

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
	char *uri = (char*)malloc(strlen(source) + 1);
	strcpy(uri, source);

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
	len = tmpstr - curstr;
	/* Check restrictions */
	for (i = 0; i < len; i++) {
		if (!_is_scheme_char(curstr[i])) goto ERR;
	}
	/* Copy the scheme to the storage */
	char *sch = (char*)malloc(sizeof(char) * (len + 1));
	if (NULL == sch) goto ERR;

	(void)strncpy(sch, curstr, len);
	sch[len] = '\0';
	sqrl_lcstr(sch);
	if (strcmp(sch, "sqrl") == 0) this->scheme = SQRL_SCHEME_SQRL;
	else if (strcmp(sch, "file") == 0) this->scheme = SQRL_SCHEME_FILE;
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
		len = tmpstr - curstr;
		username = (char*)malloc(sizeof(char) * (len + 1));
		if (NULL == username) goto ERR;
		(void)strncpy(username, curstr, len);
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
			len = tmpstr - curstr;
			password = (char*)malloc(sizeof(char) * (len + 1));
			if (NULL == password) goto ERR;
			(void)strncpy(password, curstr, len);
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
	len = tmpstr - curstr;
	host = (char*)malloc(sizeof(char) * (len + 1));
	if (NULL == host || len <= 0) goto ERR;
	(void)strncpy(host, curstr, len);
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
		len = tmpstr - curstr;
		port = (char*)malloc(sizeof(char) * (len + 1));
		if (NULL == port) goto ERR;
		(void)strncpy(port, curstr, len);
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
	len = tmpstr - curstr;
	path = (char*)malloc(sizeof(char) * (len + 1));
	if (NULL == path) goto ERR;

	(void)strncpy(path, curstr, len);
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
		len = tmpstr - curstr;
		query = (char*)malloc(sizeof(char) * (len + 1));
		if (NULL == query) goto ERR;

		(void)strncpy(query, curstr, len);
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
		len = tmpstr - curstr;
		fragment = (char*)malloc(sizeof(char) * (len + 1));
		if (NULL == fragment) goto ERR;

		(void)strncpy(fragment, curstr, len);
		fragment[len] = '\0';
	}

	/* SQRL Specific... */
SQRL:
	switch (this->scheme) {
	case SQRL_SCHEME_SQRL:
		this->url = (char*)malloc(strlen(uri) + 2);
		strcpy(this->url + 1, uri);
		memcpy(this->url, "https", 5);
		utstring_new(prefix);
		utstring_bincpy(prefix, "https://", 8);
		break;
	case SQRL_SCHEME_FILE:
		this->url = (char*)malloc(strlen(uri) + 2);
		strcpy(this->url, uri);
		this->challenge = (char*)malloc(strlen(uri) - 6);
		strcpy(this->challenge, uri + 7);
		goto END;
	default:
		goto ERR;
	}
	this->challenge = (char*)malloc(strlen(source) + 1);
	if (this->challenge == NULL || this->url == NULL) goto ERR;
	strcpy(this->challenge, source);

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
			pl = ppp - pp;
		} else {
			pl = strlen(pp);
		}
		UT_string *utsfn = sqrl_b64u_decode(NULL, pp, pl);
		if (utsfn) {
			this->sfn = (char*)calloc(1, utstring_len(utsfn) + 1);
			memcpy(this->sfn, utstring_body(utsfn), utstring_len(utsfn));
			utstring_free(utsfn);
		}
		pl = 0;
		pp = strstr(query, "x=");
		if (pp) {
			pp += 2;
			pl = strtol(pp, NULL, 10);
		}
	}
	if (pl) ul += pl + 1;
	this->host = (char*)malloc(ul);
	if (this->host == NULL) goto ERR;
	strcpy(this->host, host);
	utstring_bincpy(prefix, host, strlen(host));
	if (port) {
		utstring_printf(prefix, ":%s", port);
	}
	if (pl) {
		this->host[hl] = '/';
		strncpy(this->host + hl + 1, path, pl);
	}
	this->prefix = (char*)malloc(utstring_len(prefix) + 1);
	if (this->prefix == NULL) goto ERR;
	strcpy(this->prefix, utstring_body(prefix));
	goto END;

ERR:
	if (this->challenge) free(this->challenge);
	this->challenge = NULL;
	if (this->host) free(this->host);
	this->host = NULL;
	if (this->prefix) free(this->prefix);
	this->prefix = NULL;
	if (this->url) free(this->url);
	this->url = NULL;
	if (this->sfn) free(this->sfn);
	this->sfn = NULL;
	this->scheme = SQRL_SCHEME_INVALID;

END:
	if (host) free(host);
	if (port) free(port);
	if (query) free(query);
	if (fragment) free(fragment);
	if (username) free(username);
	if (password) free(password);
	if (path) free(path);
	if (prefix) utstring_free(prefix);
	if (uri) free(uri);
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
}

