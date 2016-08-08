#include "catch.hpp"
#include "SqrlBase64.h"
#include "SqrlBase56.h"
#include "SqrlBase56Check.h"

static void testString( char *a, const char *b ) {
	REQUIRE( strcmp( a, b ) == 0 );
	if( a ) free( a );
}

TEST_CASE( "Base56Identity" ) {
	SqrlString idString = SqrlString( "bMaynykbH7ee56McJVfnzqmCCiMw3iu6hbMC9JiWLyMKKiYnAFF5Ygfsw6wx2hUb9W8B7bAW4zbdsfcvhYidGrwviEbRxLrdaZwB5iMXV5F" );
	SqrlString decoded = SqrlString();
	SqrlString encoded = SqrlString();
	SqrlString ss = SqrlString();
	SqrlString cmpStr = SqrlString();
	cmpStr.append( (char)0x49, 1 );
	cmpStr.append( (char)0x00, 1 );
	cmpStr.append( (char)0x02, 1 );
	cmpStr.append( (char)0x00, 1 );

	SqrlBase56Check b56 = SqrlBase56Check();

	REQUIRE( b56.decode( &decoded, &idString ) );

	decoded.substring( &ss, 0, 4 );

	REQUIRE( 0 == ss.compare( &cmpStr ));
	REQUIRE( b56.encode( &encoded, &decoded ) );
	REQUIRE( 0 == encoded.compare( &idString ) );
}

TEST_CASE( "Base56Check" ) {
	const int NT = 7;
	SqrlString evector[NT] = {
		"",
		"f",
		"fo",
		"foo",
		"foob",
		"fooba",
		"foobar"
	};
	SqrlString e = SqrlString();
	SqrlString d = SqrlString();
	int i;
	SqrlBase56Check b56 = SqrlBase56Check();

	for( i = 0; i < NT; i++ ) {
		b56.encode( &e, &(evector[i]) );
		REQUIRE( b56.decode( &d, &e ) );
		REQUIRE( d.compare( &(evector[i]) ) == 0 );
	}

	SqrlString lString = SqrlString( "This is a long sentence used to test Base56Check in a multi-line scenario." );
	b56.encode( &e, &lString );
	uint8_t lineCount = 0;
	REQUIRE( b56.decode( &d, &e ) );
	REQUIRE( d.compare( &lString ) == 0 );
}

TEST_CASE( "Base56" ) {
	const int NT = 7;
	SqrlString evector[NT] = {
		"",
		"f",
		"fo",
		"foo",
		"foob",
		"fooba",
		"foobar"
	};
	SqrlString e = SqrlString();
	SqrlString d = SqrlString();
	int i;
	SqrlBase56 b56 = SqrlBase56();

	for( i = 0; i < NT; i++ ) {
		b56.encode( &e, &(evector[i]) );
		b56.decode( &d, &e );
		REQUIRE( d.compare( &(evector[i]) ) == 0 );
	}
}

TEST_CASE( "Base64" ) {
	const int NT = 10;
	SqrlString evector[NT] = {
		"",
		"f",
		"fo",
		"foo",
		"foob",
		"fooba",
		"foobar",
		"",
		"",
		""};
	evector[7].push_back( (char)0x049 );
	evector[7].push_back( (char)0x00 );
	evector[7].push_back( (char)0x02 );
	evector[8].push_back( (char)0x00 );
	evector[8].push_back( (char)0x08 );
	evector[8].push_back( (char)0xa4 );
	evector[9].push_back( (char)0x49 );
	evector[9].push_back( (char)0x00 );
	evector[9].push_back( (char)0x02 );
	evector[9].push_back( (char)0x00 );
	evector[9].push_back( (char)0x08 );
	evector[9].push_back( (char)0xa4 );

	SqrlString dvector[NT] = {
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
	SqrlString s;
	int i;
	SqrlBase64 b64 = SqrlBase64();

	for( i = 0; i < NT; i++ ) {
		b64.encode( &s, &(evector[i]) );
		REQUIRE( s.length() == dvector[i].length() );
		REQUIRE( 0 == s.compare( &dvector[i] ) );
		b64.decode( &s, &dvector[i] );
		REQUIRE( s.length() == evector[i].length() );
		REQUIRE( 0 == s.compare( &evector[i] ) );
	}
}
