#pragma once

#include "SqrlUri.fwd.h"

typedef enum
{
	SQRL_SCHEME_INVALID = 0,
	SQRL_SCHEME_SQRL,
	SQRL_SCHEME_FILE
} Sqrl_Scheme;

class DLL_PUBLIC SqrlUri
{
public:
	static SqrlUri *parse( const char *source );
	SqrlUri *release();

	Sqrl_Scheme getScheme();

	/** The Challenge is the full, original URL, or the response body from a previous SQRL transaction */
	char *getChallenge();
	size_t getChallengeLength();
	void setChallenge(const char *val);

	/** The Hostname (fqdn) */
	char *getHost();
	size_t getHostLength();

	/** The portion of the URL that the Site Specific Keys are based on.
	* Typically, the FQDN, followed by an optional extension.
	*/
	char *getPrefix();
	size_t getPrefixLength();

	/** The server URL for the next transaction */
	char *getUrl();
	size_t getUrlLength();
	void setUrl(const char *val);

	/** The 'Server Friendly Name' */
	char* getSFN();
	size_t getSFNLength();

	/** Creates a copy of a SqrlUri object. */
	SqrlUri* copy();

private:
	SqrlUri();
	~SqrlUri();
	Sqrl_Scheme scheme;
	char *challenge;
	char *host;
	char *prefix;
	char *url;
	char *sfn;
};
