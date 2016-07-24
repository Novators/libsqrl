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
		std::string evector[NT] = {
			"",
			"f",
			"fo",
			"foo",
			"foob",
			"fooba",
			"foobar",
			"\x49\x00\x02"s,
			"\x00\x08\xa4"s,
			"\x49\x00\x02\x00\x08\xa4"s};
		std::string dvector[NT] = {
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
		std::string s;
		int i;
		SqrlBase64 b64 = SqrlBase64();
		
		for( i = 0; i < NT; i++ ) {
			printf( "%s\n", dvector[i].data() );
			b64.encode( &s, &(evector[i]) );
			Assert::IsTrue( s.length() == dvector[i].length() );
			Assert::IsTrue( 0 == s.compare( dvector[i] ) );
			b64.decode( &s, &dvector[i] );
			Assert::IsTrue( s.length() == evector[i].length() );
			Assert::IsTrue( 0 == s.compare( evector[i] ) );
		}
	}
	

	TEST_CLASS_CLEANUP( StopSqrl ) {
		sqrl_stop();
	}
	};
}