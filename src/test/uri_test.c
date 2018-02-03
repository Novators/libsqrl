/* uri_test.c

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/

#include <stdio.h>
#include "../sqrl_internal.h"

#define STREQ(A,B) if( !(A) || !(B) ) { printf( "NULL String\n" ); exit(1); } if( strcmp( A, B ) != 0 ) { printf( "%s != %s\n", A, B ); exit(1); }
#define STRNULL(A) if( A != NULL ) { printf( "%s should be NULL!\n", A ); exit(1); }
#define NUMEQ(A,B) if( A != B ) { printf( "%d != %d\n", A, B ); exit(1); }

void printuri( Sqrl_Uri *uri )
{
	printf( "URL: %s\n", uri->url );
	printf( "cha: %s\n", uri->challenge );
	printf( "hst: %s\n", uri->host );
	printf( "pfx: %s\n", uri->prefix );
	printf( "scm: %s\n", uri->scheme == SQRL_SCHEME_SQRL ? "sqrl" : "file" );
}

int main()
{
	Sqrl_Uri *uri;

	uri = sqrl_uri_parse( "sqrl://sqrlid.com/login?x=6&nut=blah" );
	printuri( uri );
	NUMEQ( uri->scheme, SQRL_SCHEME_SQRL );
	STREQ( uri->host, "sqrlid.com/login" )
	STREQ( uri->challenge, "sqrl://sqrlid.com/login?x=6&nut=blah" )
	STREQ( uri->url, "https://sqrlid.com/login?x=6&nut=blah" )
	STREQ( uri->prefix, "https://sqrlid.com" );
	sqrl_uri_free( uri );

	uri = sqrl_uri_parse( "sqrl://sqrlid.com/login?nut=blah" );
	printuri( uri );
	NUMEQ( uri->scheme, SQRL_SCHEME_SQRL );
	STREQ( uri->host, "sqrlid.com" );
	STREQ( uri->challenge, "sqrl://sqrlid.com/login?nut=blah" );
	STREQ( uri->url, "https://sqrlid.com/login?nut=blah" );
	STREQ( uri->prefix, "https://sqrlid.com" );
	sqrl_uri_free( uri );

	uri = sqrl_uri_parse( "sqrl://sqrlid.com:8080/login?nut=blah" );
	printuri( uri );
	NUMEQ( uri->scheme, SQRL_SCHEME_SQRL );
	STREQ( uri->host, "sqrlid.com" );
	STREQ( uri->challenge, "sqrl://sqrlid.com:8080/login?nut=blah" );
	STREQ( uri->url, "https://sqrlid.com:8080/login?nut=blah" );
	STREQ( uri->prefix, "https://sqrlid.com:8080" );
	sqrl_uri_free( uri );

	uri = sqrl_uri_parse( "file://test1.sqrl" );
	printuri( uri );
	NUMEQ( uri->scheme, SQRL_SCHEME_FILE );
	STRNULL( uri->host );
	STREQ( uri->url, "file://test1.sqrl" );
	STREQ( uri->challenge, "test1.sqrl" );
	STRNULL( uri->prefix );
	sqrl_uri_free( uri );

	uri = sqrl_uri_parse( "http://google.com" );
	if( uri ) {
		printf( "Invalid SQRL URL was accepted as valid: http://google.com\n" );
		exit(1);
	}

	printf( "PASS!\n" );
	exit(0);
}
