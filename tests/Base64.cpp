#include "catch.hpp"
#include "NullClient.h"
#include "SqrlBase64.h"

static void testString( char *a, const char *b ) {
	REQUIRE( strcmp( a, b ) == 0 );
	if( a ) free( a );
}

TEST_CASE( "Base64" ) {
	NullClient *client = new NullClient();
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
		b64.encode( &s, &(evector[i]) );
		REQUIRE( s.length() == dvector[i].length() );
		REQUIRE( 0 == s.compare( dvector[i] ) );
		b64.decode( &s, &dvector[i] );
		REQUIRE( s.length() == evector[i].length() );
		REQUIRE( 0 == s.compare( evector[i] ) );
	}
	delete client;
}
