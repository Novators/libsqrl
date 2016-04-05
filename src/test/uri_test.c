/* uri_test.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/

#include <stdio.h>
#include "../sqrl_internal.h"

#define STREQ(A,B) if( strcmp( A, B ) != 0 ) { printf( "%s != %s\n", A, B ); exit(1); }
#define STRNULL(A) if( A != NULL ) { printf( "%s should be NULL!\n", A ); exit(1); }

void printuri( Sqrl_Uri *uri )
{
	printf( "URL: %s\n", uri->url );
	printf( "cha: %s\n", uri->challenge );
	printf( "hst: %s\n", uri->host );
	printf( "scm: %s\n\n", uri->scheme );
}

int main() 
{
	Sqrl_Uri *uri;

	uri = sqrl_uri_parse( "sqrl://sqrlid.com/login//nut=blah" );
	STREQ( uri->scheme, "sqrl" )
	STREQ( uri->host, "sqrlid.com/login" )
	STREQ( uri->challenge, "sqrl://sqrlid.com/login//nut=blah" )
	STREQ( uri->url, "https://sqrlid.com/login/nut=blah" )
	STREQ( uri->prefix, "https://sqrlid.com" );
	sqrl_uri_free( uri );

	uri = sqrl_uri_parse( "sqrl://sqrlid.com/login?nut=blah" );
	STREQ( uri->scheme, "sqrl" );
	STREQ( uri->host, "sqrlid.com" );
	STREQ( uri->challenge, "sqrl://sqrlid.com/login?nut=blah" );
	STREQ( uri->url, "https://sqrlid.com/login?nut=blah" );
	STREQ( uri->prefix, "https://sqrlid.com" );
	sqrl_uri_free( uri );

	uri = sqrl_uri_parse( "sqrl://sqrlid.com:8080/login?nut=blah" );
	STREQ( uri->scheme, "sqrl" );
	STREQ( uri->host, "sqrlid.com" );
	STREQ( uri->challenge, "sqrl://sqrlid.com:8080/login?nut=blah" );
	STREQ( uri->url, "https://sqrlid.com:8080/login?nut=blah" );
	STREQ( uri->prefix, "https://sqrlid.com:8080" );
	sqrl_uri_free( uri );

	uri = sqrl_uri_parse( "file://test1.sqrl" );
	if( !uri ) {
		printf( "Failed to parse file:// uri\n" );
		exit(1);
	}
	STREQ( uri->scheme, "file" );
	STRNULL( uri->host );
	STRNULL( uri->challenge );
	STREQ( uri->url, "test1.sqrl" );
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