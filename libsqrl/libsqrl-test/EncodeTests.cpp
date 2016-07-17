#include <cstdlib>
#include "stdafx.h"
#include "CppUnitTest.h"

#include <stdio.h>
#include <stdint.h>
#include "sqrl.h"
#include "SqrlBase64.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std;

namespace libsqrltest
{
	TEST_CLASS( EncodeTests ) {
public:
	TEST_CLASS_INITIALIZE( InitializeSqrl ) {
		sqrl_init();
	}

	void testString( char *a, const char *b ) {
		Assert::AreEqual( a, b );
		if( a ) free( a );
	}

	TEST_METHOD( Base64 ) {
		const int NT = 10;
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
		utstring_new( s );
		SqrlBase64 b64 = SqrlBase64();
		
		for( i = 0; i < NT; i++ ) {
			printf( "%s\n", dvector[i] );
			b64.encode( s, (uint8_t*)evector[i], esize[i] );
			Assert::IsTrue( utstring_len( s ) == strlen( dvector[i] ) );
			Assert::IsTrue( 0 == strcmp( utstring_body( s ), dvector[i] ) );
			b64.decode( s, dvector[i], strlen( dvector[i] ) );
			Assert::IsTrue( utstring_len( s ) == esize[i] );
			Assert::IsTrue( 0 == memcmp( utstring_body( s ), evector[i], esize[i] ) );
		}
		utstring_free( s );
	}
	

	TEST_CLASS_CLEANUP( StopSqrl ) {
		sqrl_stop();
	}
	};
}