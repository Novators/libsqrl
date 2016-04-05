/* url_test.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/

#include <stdio.h>
#include "../sqrl_internal.h"

#define STREQ(A,B) if( strcmp( A, B ) != 0 ) { printf( "%s != %s\n", A, B ); exit(1); }
#define STRNULL(A) if( A != NULL ) { printf( "%s should be NULL!\n", A ); exit(1); }

void printurl( Sqrl_Url *url )
{
	printf( "URL: %s\n", url->url );
	printf( "cha: %s\n", url->challenge );
	printf( "hst: %s\n", url->host );
	printf( "scm: %s\n\n", url->scheme );
}

int main() 
{
	Sqrl_Url *url;

	url = sqrl_url_parse( "sqrl://sqrlid.com/login//nut=blah" );
	STREQ( url->scheme, "sqrl" )
	STREQ( url->host, "sqrlid.com/login" )
	STREQ( url->challenge, "sqrl://sqrlid.com/login//nut=blah" )
	STREQ( url->url, "https://sqrlid.com/login/nut=blah" )
	STREQ( url->prefix, "https://sqrlid.com" );
	sqrl_url_free( url );

	url = sqrl_url_parse( "qrl://sqrlid.com/login?nut=blah" );
	STREQ( url->scheme, "qrl" );
	STREQ( url->host, "sqrlid.com" );
	STREQ( url->challenge, "qrl://sqrlid.com/login?nut=blah" );
	STREQ( url->url, "http://sqrlid.com/login?nut=blah" );
	STREQ( url->prefix, "http://sqrlid.com" );
	sqrl_url_free( url );

	url = sqrl_url_parse( "sqrl://sqrlid.com:8080/login?nut=blah" );
	STREQ( url->scheme, "sqrl" );
	STREQ( url->host, "sqrlid.com" );
	STREQ( url->challenge, "sqrl://sqrlid.com:8080/login?nut=blah" );
	STREQ( url->url, "https://sqrlid.com:8080/login?nut=blah" );
	STREQ( url->prefix, "https://sqrlid.com:8080" );
	sqrl_url_free( url );

	url = sqrl_url_parse( "http://google.com" );
	if( url ) {
		printf( "Invalid SQRL URL was accepted as valid: http://google.com\n" );
		exit(1);
	}

	printf( "PASS!\n" );
	exit(0);
}