/** \file SqrlUri.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLURI_H
#define SQRLURI_H

#include "sqrl.h"
#include "SqrlString.h"

namespace libsqrl
{
    typedef enum
    {
        SQRL_SCHEME_INVALID = 0,
        SQRL_SCHEME_SQRL,
        SQRL_SCHEME_FILE
    } Sqrl_Scheme;

    /// <summary>Parses and stores information about a SQRL URI or file path.</summary>
    class SqrlUri
    {
    public:
        SqrlUri();
        SqrlUri( const SqrlString *source );
        SqrlUri( const SqrlUri *src );
        ~SqrlUri();

        Sqrl_Scheme getScheme();

        /** The Challenge is the full, original URL, or the response body from a previous SQRL action */
        SqrlString *getChallenge( SqrlString *buf = NULL );
        size_t getChallengeLength();
        void setChallenge( const SqrlString *val );

        /** The Hostname (fqdn), and any extension defined by the server.  Used in creating Site Specific Keys */
        SqrlString *getSiteKey( SqrlString *buf = NULL );
        size_t getSiteKeyLength();

        /** The prefix URL.  Combined with a server's qry= parameter, defines where the client should connect for the next loop.
        * Typically, the FQDN, followed by an optional extension.
        */
        SqrlString *getPrefix( SqrlString *buf = NULL );
        size_t getPrefixLength();

        /** The server URL for the next action */
        SqrlString *getUrl( SqrlString *buf = NULL );
        size_t getUrlLength();
        void setUrl( const SqrlString *val );

        SqrlString* getSFN( SqrlString *buf = NULL );
        size_t getSFNLength();

        bool isValid();

    private:
        Sqrl_Scheme scheme;
        SqrlString *challenge;
        SqrlString *siteKey;
        SqrlString *prefix;
        SqrlString *url;
        SqrlString *sfn;
    };
}
#endif // SQRLURI_H
