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

#define GETTER( t,i ) \
if( (t) == NULL ) { \
    if( (i) ) (i)->clear(); \
    return NULL; \
} \
if( (i) ) { \
    (i)->clear(); \
    (i)->append( (t) ); \
} else { \
    (i) = new SqrlString( (t) ); \
} \
return (i);

#define SETTER( t, v ) \
if( (v) ) { \
    if( (t) ) { \
        (t)->clear(); \
        (t)->append( (v) ); \
    } else { \
        (t) = new SqrlString( (v) ); \
    } \
} else { \
    delete (t); \
}

#define GETLEN( t ) \
if( (t) == NULL ) {return 0;} else {return (t)->length();}


namespace libsqrl
{

    /// <summary>Default constructor.  Not very useful.</summary>
    SqrlUri::SqrlUri() :
        scheme( SQRL_SCHEME_INVALID ),
        challenge( NULL ),
        siteKey( NULL ),
        prefix( NULL ),
        url( NULL ),
        sfn( NULL ) { }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Construct a copy of a SqrlUri object.</summary>
    ///
    /// <param name="src">[in] If non-null, a SqrlUri object to copy.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    SqrlUri::SqrlUri( const SqrlUri *src ) : SqrlUri::SqrlUri() {
        if( src ) {
            this->scheme = src->scheme;
            if( src->challenge ) this->challenge = new SqrlString( src->challenge );
            if( src->siteKey ) this->siteKey = new SqrlString( src->siteKey );
            if( src->prefix ) this->prefix = new SqrlString( src->prefix );
            if( src->url ) this->url = new SqrlString( src->url );
            if( src->sfn ) this->sfn = new SqrlString( src->sfn );
        }
    }

    SqrlUri::~SqrlUri() {
        if( this->challenge ) delete(this->challenge);
        if( this->siteKey ) delete( this->siteKey );
        if( this->prefix ) delete( this->prefix );
        if( this->url ) delete( this->url );
        if( this->sfn ) delete( this->sfn );
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the scheme.</summary>
    ///
    /// <returns>The scheme.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    Sqrl_Scheme SqrlUri::getScheme() { return this->scheme; }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the challenge.</summary>
    ///
    /// <param name="buf">[out] (Optional) If non-null, a SqrlString to hold the challenge.</param>
    ///
    /// <returns>pointer to a SqrlString containing the challenge, or NULL.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    SqrlString * SqrlUri::getChallenge( SqrlString *buf ) { GETTER( this->challenge, buf ) }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets site key.</summary>
    ///
    /// <param name="buf">[out] (Optional) If non-null, a SqrlString to hold the site key.</param>
    ///
    /// <returns>pointer to SqrlString containing the site key, or NULL.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    SqrlString * SqrlUri::getSiteKey( SqrlString *buf ) { GETTER( this->siteKey, buf ) }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the prefix.</summary>
    ///
    /// <param name="buf">[out] (Optional) If non-null, a SqrlString to hold the prefix.</param>
    ///
    /// <returns>pointer to SqrlString containing the prefix, or NULL.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    SqrlString * SqrlUri::getPrefix( SqrlString *buf ) { GETTER( this->prefix, buf ) }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the URL.</summary>
    ///
    /// <param name="buf">[out] (Optional) If non-null, a SqrlString to hold the url.</param>
    ///
    /// <returns>pointer to SqrlString containing the url, or NULL.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    SqrlString * SqrlUri::getUrl( SqrlString *buf ) { GETTER( this->url, buf ) }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the Server Friendly Name.</summary>
    ///
    /// <param name="buf">[out] (Optional) If non-null, a SqrlString to hold the SFN.</param>
    ///
    /// <returns>pointer to SqrlString containing the SFN, or NULL.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    SqrlString * SqrlUri::getSFN( SqrlString *buf ) { GETTER( this->sfn, buf ) }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the challenge.</summary>
    ///
    /// <param name="val">The new challenge.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    void SqrlUri::setChallenge( const SqrlString *val ) { SETTER( this->challenge, val ) }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the URL.</summary>
    ///
    /// <param name="val">The new URL.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    void SqrlUri::setUrl( const SqrlString *val ) { SETTER( this->url, val ) }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets length of the challenge.</summary>
    ///
    /// <returns>The challenge length.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    size_t SqrlUri::getChallengeLength() { GETLEN( this->challenge ) }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets length of site key.</summary>
    ///
    /// <returns>The site key length.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    size_t SqrlUri::getSiteKeyLength() { GETLEN( this->siteKey ) }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets length of prefix.</summary>
    ///
    /// <returns>The prefix length.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    size_t SqrlUri::getPrefixLength() { GETLEN( this->prefix ) }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets length of URL.</summary>
    ///
    /// <returns>The URL length.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    size_t SqrlUri::getUrlLength() { GETLEN( this->url ) }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets length of SFN.</summary>
    ///
    /// <returns>The SFN length.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    size_t SqrlUri::getSFNLength() { GETLEN( this->sfn ) }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Query if this SqrlUri is valid.</summary>
    ///
    /// <returns>true if valid, false if not.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    bool SqrlUri::isValid() {
        return this->scheme != SQRL_SCHEME_INVALID;
    }

    /*
     * URL Parsing function borrowed (with modifications) from:
     *
     * Copyright 2010-2011 Scyphus Solutions Co. Ltd.  All rights reserved.
     *
     * Authors:
     *      Hirochika Asai
     */

    static int _is_scheme_char( int );

    static int _is_scheme_char( int c ) {
        return (!isalpha( c ) && '+' != c && '-' != c && '.' != c) ? 0 : 1;
    }

    static void sqrl_lcstr( char *str, size_t len ) {
        int i;
        for( i = 0; i < len; i++ ) {
            if( str[i] > 64 && str[i] < 91 ) {
                str[i] += 32;
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Parses a SqrlString to a SqrlUri.</summary>
    ///
    /// <param name="source">Source string.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    SqrlUri::SqrlUri( const SqrlString *source ) : SqrlUri() {
        const char *tmpstr;
        const char *curstr;
        size_t len;
        int userpass_flag;
        char *port = NULL,
            *path = NULL,
            *query = NULL,
            *fragment = NULL,
            *username = NULL,
            *password = NULL,
            *pp = NULL,
            *ppp = NULL;
		char sch[4];
        long pl;

        SqrlString uri = SqrlString( source );
        this->siteKey = new SqrlString();

        curstr = uri.string();

        /*
        * <scheme>:<scheme-specific-part>
        * <scheme> := [a-z\+\-\.]+
        *             upper case = lower case for resiliency
        */
        tmpstr = strchr( curstr, ':' );
		if( tmpstr ) {
			len = (int)(tmpstr - curstr);
			if( len != 4 ) goto ERR;
			memcpy( sch, curstr, len );
			curstr += len;
			/* Skip "://" */
			if( strstr( curstr, "://" ) != curstr ) goto ERR;
			curstr += 3;

			sqrl_lcstr( sch, len );
			if( memcmp( sch, "sqrl", len ) == 0 ) this->scheme = SQRL_SCHEME_SQRL;
			else if( memcmp( sch, "file", len ) == 0 ) this->scheme = SQRL_SCHEME_FILE;
			else goto ERR;
		} else {
			goto ERR;
		}

        /*
        * <user>:<password>@<host>:<port>/<uri-path>
        * Any ":", "@" and "/" must be encoded.
        */

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
                break;
            }
            tmpstr++;
        }

        /* User and password specification */
        tmpstr = curstr;
        if( userpass_flag ) {
            /* Read username */
            while( ':' != *tmpstr && '@' != *tmpstr ) {
                tmpstr++;
            }
            len = (int)(tmpstr - curstr);
            username = new char[len + 1];
            memcpy( username, curstr, len );
            username[len] = 0;
            /* Proceed current pointer */
            curstr = tmpstr;
            if( ':' == *curstr ) {
                /* Skip ':' */
                curstr++;
                /* Read password */
                tmpstr = curstr;
                while( '@' != *tmpstr ) {
                    tmpstr++;
                }
                len = (int)(tmpstr - curstr);
                password = new char[len + 1];
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
			// IPv6 address
			tmpstr = curstr;
			while( '\0' != *tmpstr ) {
				if( ']' == *tmpstr ) {
					// End of IPv6 address.
					tmpstr++;
					break;
				}
				tmpstr++;
			}
			if( '\0' == *tmpstr ) goto ERR;
        } else {
			tmpstr = curstr;
			while( '\0' != *tmpstr ) {
				if( ':' == *tmpstr || '/' == *tmpstr ) {
					break;
				}
				tmpstr++;
			}
        }
        len = (size_t)(tmpstr - curstr);
        if( len ) {
            this->siteKey->append( curstr, len );
        }
        curstr = tmpstr;

        /* Is port number specified? */
        if( ':' == *curstr ) {
            curstr++;
            /* Read port number */
            tmpstr = curstr;
            while( '\0' != *tmpstr && '/' != *tmpstr ) {
                tmpstr++;
            }
            len = (int)(tmpstr - curstr);
            port = new char[len + 1];
            if( NULL == port ) goto ERR;
            memcpy( port, curstr, len );
            port[len] = '\0';
            curstr = tmpstr;
        }

        /* End of the string? */
        if( '\0' == *curstr ) {
            goto SQRL;
        }

        /* Skip '/' */
        if( '/' != *curstr ) goto ERR;
        curstr++;

        /* Parse path */
        tmpstr = curstr;
        while( '\0' != *tmpstr && '#' != *tmpstr  && '?' != *tmpstr ) {
            tmpstr++;
        }
        len = (int)(tmpstr - curstr);
        path = new char[len + 1];
        if( NULL == path ) goto ERR;
        memcpy( path, curstr, len );
        path[len] = '\0';
        curstr = tmpstr;

        /* Is query specified? */
        if( '?' == *curstr ) {
            /* Skip '?' */
            curstr++;
            /* Read query */
            tmpstr = curstr;
            while( '\0' != *tmpstr && '#' != *tmpstr ) {
                tmpstr++;
            }
            len = (int)(tmpstr - curstr);
            query = new char[len + 1];
            if( NULL == query ) goto ERR;
            memcpy( query, curstr, len );
            query[len] = '\0';
            curstr = tmpstr;
        }

        /* Is fragment specified? */
        if( '#' == *curstr ) {
            /* Skip '#' */
            curstr++;
            /* Read fragment */
            tmpstr = curstr;
            while( '\0' != *tmpstr ) {
                tmpstr++;
            }
            len = (int)(tmpstr - curstr);
            fragment = new char[len + 1];
            if( NULL == fragment ) goto ERR;
            memcpy( fragment, curstr, len );
            fragment[len] = '\0';
        }

        /* SQRL Specific... */
    SQRL:
        switch( this->scheme ) {
        case SQRL_SCHEME_SQRL:
            len = uri.length();
			this->prefix = new SqrlString( "https://" );
            this->url = new SqrlString( uri.length() + 1 );
			this->url->append( this->prefix );
			this->url->append( uri.cstring() + 7 );
            break;
        case SQRL_SCHEME_FILE:
            this->url = new SqrlString( &uri );
            this->challenge = new SqrlString();
            this->siteKey->clear();
            uri.substring( this->challenge, 7, uri.length() - 7 );
            goto END;
        default:
            goto ERR;
        }
        len = source->length();
        this->challenge = new SqrlString( source );
        if( this->challenge == NULL || this->url == NULL ) goto ERR;
        
        pl = 0;
        pp = NULL;
        ppp = NULL;
        if( query ) {
            pp = strstr( query, "sfn=" );
            if( !pp ) {
                goto ERR;
            }
            pp += 4;
            ppp = strchr( pp, '&' );
            if( ppp ) {
                pl = (int)(ppp - pp);
            } else {
                pl = (long)strlen( pp );
            }
            SqrlString *utsfnsrc = new SqrlString( pp, pl );
            if( utsfnsrc ) {
                this->sfn = SqrlBase64().decode( NULL, utsfnsrc );
                delete utsfnsrc;
            }
            pl = 0;
            pp = strstr( query, "x=" );
            if( pp ) {
                pp += 2;
                pl = strtol( pp, NULL, 10 );
            }
        }
        this->prefix->append( this->siteKey );
        if( port ) {
            this->prefix->append( ":" );
            this->prefix->append( port );
        }
        if( pl ) {
            this->siteKey->append( "/" );
            this->siteKey->append( path, pl - 1 );
        }
        goto END;

    ERR:
        this->scheme = SQRL_SCHEME_INVALID;

    END:
        if( port ) delete port;
        if( query ) delete query;
        if( fragment ) delete fragment;
        if( username ) delete username;
        if( password ) delete password;
        if( path ) delete path;
    }
}
