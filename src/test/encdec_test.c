/* encdec_text.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include <stdio.h>
#include "../sqrl_client.h"

#define NT 10

int main (int argc, char **argv)
{
	const size_t esize[NT] = {
		0, 1, 2, 3, 4, 5, 6, 3, 3, 6
	};
	const char *evector[NT] = {
		"",
		"f",
		"fo",
		"foo",
		"foob",
		"fooba",
		"foobar",
		"\x49\x00\x02",
		"\x00\x08\xa4",
		"\x49\x00\x02\x00\x08\xa4"};
	const char *dvector[NT] = {
		"",
		"Zg",
		"Zm8",
		"Zm9v",
		"Zm9vYg",
		"Zm9vYmE",
		"Zm9vYmFy",
		"SQAC",
		"AAik",
		"SQACAAik"};
	UT_string *s;
	int i;
	utstring_new(s);

	for( i = 0; i < NT; i++ ) {
		printf( "%s\n", dvector[i] );
		sqrl_b64u_encode( s, (uint8_t*)evector[i], esize[i] );
		if( utstring_len(s) != strlen( dvector[i] ) ||
			strcmp( utstring_body(s), dvector[i] )) {
			printf( "ENCODE ERROR (%d): %s\n", i, utstring_body(s) );
			exit(1);
		}
		sqrl_b64u_decode( s, dvector[i], strlen( dvector[i] ));
		if( utstring_len(s) != esize[i] ||
			memcmp( utstring_body(s), evector[i], esize[i] )) {
			printf( "DECODE ERROR (%d): %s\n", i, utstring_body(s) );
			exit(1);
		}
	}
	utstring_free(s);
	exit(0);
}