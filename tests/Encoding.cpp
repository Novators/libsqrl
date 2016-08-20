#include "catch.hpp"
#include "SqrlEncoder.h"
#include "SqrlBase64.h"
#include "SqrlBase56.h"
#include "SqrlBase56Check.h"
#include "SqrlUrlEncode.h"

using namespace libsqrl;

static void testString( char *a, const char *b ) {
    REQUIRE( strcmp( a, b ) == 0 );
    if( a ) free( a );
}

TEST_CASE( "UrlEncode", "[encode]" ) {
	char src[] = "UrlEncoded: http://blah.com/test?something=somethingElse&a=b";
	SqrlString srcString = SqrlString( src );
	SqrlString cmpString = SqrlString( "UrlEncoded%3A+http%3A%2F%2Fblah%2Ecom%2Ftest%3Fsomething%3DsomethingElse%26a%3Db" );
	SqrlString encoded = SqrlString();
	SqrlString decoded = SqrlString();

	SqrlUrlEncode encoder = SqrlUrlEncode();
	encoder.encode( &encoded, &srcString );
	encoder.decode( &decoded, &encoded );
	REQUIRE( 0 == srcString.compare( &decoded ) );
	REQUIRE( 0 == cmpString.compare( &encoded ) );
}

TEST_CASE( "Base2", "[encode]" ) {
	uint8_t src[] = {0, 1, 0};
	SqrlString srcString = SqrlString( src, 3 );
	SqrlString cmpString = SqrlString( "00000000100000000" );
	SqrlString encoded = SqrlString();
	SqrlString decoded = SqrlString();

	SqrlEncoder encoder = SqrlEncoder( "01" );
	encoder.encode( &encoded, &srcString );
	encoder.decode( &decoded, &encoded );
	REQUIRE( 0 == srcString.compare( &decoded ) );
	REQUIRE( 0 == cmpString.compare( &encoded ) );
}

TEST_CASE( "Base8", "[encode]" ) {
	const int NT = 6;
	SqrlString evector[NT] = {
		"f",
		"fo",
		"foo",
		"foob",
		"fooba",
		"foobar",
	};
	SqrlString dvector[NT*4] = {
		"146",
		"63157",
		"31467557",
		"14633667542",
		"6315733661141",
		"3146755730460562",
		"63000",
		"31467400",
		"14633667400",
		"6315733661000",
		"3146755730460400",
		"1463366754230271000",
		"00063000",
		"00031467400",
		"00014633667400",
		"0006315733661000",
		"0003146755730460400",
		"0001463366754230271000",
		"00000063000",
		"00000031467400",
		"00000014633667400",
		"0000006315733661000",
		"0000003146755730460400",
		"0000001463366754230271000"
	};
	SqrlString encoded = SqrlString();
	SqrlString decoded = SqrlString();
	SqrlEncoder encoder = SqrlEncoder( "01234567" );

	for( int i = 0; i < NT; i++ ) {
		encoder.encode( &encoded, &evector[i] );
		encoder.decode( &decoded, &encoded );
		REQUIRE( 0 == decoded.compare( &evector[i] ) );
		REQUIRE( 0 == encoded.compare( &dvector[i] ) );
		evector[i].append( (char)0, 1 );
		encoder.encode( &encoded, &evector[i] );
		encoder.decode( &decoded, &encoded );
		REQUIRE( 0 == decoded.compare( &evector[i] ) );
		REQUIRE( 0 == encoded.compare( &dvector[i+NT] ) );
		evector[i].insert( 0, 0 );
		encoder.encode( &encoded, &evector[i] );
		encoder.decode( &decoded, &encoded );
		REQUIRE( 0 == encoded.compare( &dvector[i + NT + NT] ) );
		REQUIRE( 0 == decoded.compare( &evector[i] ) );
		evector[i].insert( 0, 0 );
		encoder.encode( &encoded, &evector[i] );
		encoder.decode( &decoded, &encoded );
		REQUIRE( 0 == decoded.compare( &evector[i] ) );
		REQUIRE( 0 == encoded.compare( &dvector[i + NT + NT + NT] ) );
	}
}

TEST_CASE( "Base16", "[encode]" ) {
	const int NT = 18;
	SqrlString evector[NT] = {
		"f",
		"fo",
		"foo",
		"foob",
		"fooba",
		"foobar",
		"foobarf",
		"foobarfo",
		"foobarfoo",
		"foobarfoob",
		"foobarfooba",
		"foobarfoobar",
		"foobarfoobarf",
		"foobarfoobarfo",
		"foobarfoobarfoo",
		"foobarfoobarfoob",
		"foobarfoobarfooba",
		"foobarfoobarfoobar"
	};
	SqrlString dvector[NT] = {
		"66",
		"666f",
		"666f6f",
		"666f6f62",
		"666f6f6261",
		"666f6f626172",
		"666f6f62617266",
		"666f6f626172666f",
		"666f6f626172666f6f",
		"666f6f626172666f6f62",
		"666f6f626172666f6f6261",
		"666f6f626172666f6f626172",
		"666f6f626172666f6f62617266",
		"666f6f626172666f6f626172666f",
		"666f6f626172666f6f626172666f6f",
		"666f6f626172666f6f626172666f6f62",
		"666f6f626172666f6f626172666f6f6261",
		"666f6f626172666f6f626172666f6f626172"
	};

	SqrlString encoded = SqrlString();
	SqrlString decoded = SqrlString();
	SqrlEncoder encoder = SqrlEncoder( "0123456789abcdef" );

	for( int i = 0; i < NT; i++ ) {
		encoder.encode( &encoded, &evector[i] );
		encoder.decode( &decoded, &encoded );
		REQUIRE( 0 == decoded.compare( &evector[i] ) );
		REQUIRE( 0 == encoded.compare( &dvector[i] ) );
		evector[i].append( (char)0, 1 );
		dvector[i].append( "00" );
		encoder.encode( &encoded, &evector[i] );
		encoder.decode( &decoded, &encoded );
		REQUIRE( 0 == decoded.compare( &evector[i] ) );
		REQUIRE( 0 == encoded.compare( &dvector[i] ) );
		evector[i].insert( 0, 0 );
		dvector[i].insert( 0, '0' );
		dvector[i].insert( 0, '0' );
		encoder.encode( &encoded, &evector[i] );
		encoder.decode( &decoded, &encoded );
		REQUIRE( 0 == decoded.compare( &evector[i] ) );
		REQUIRE( 0 == encoded.compare( &dvector[i] ) );
		evector[i].insert( 0, 0 );
		dvector[i].insert( 0, '0' );
		dvector[i].insert( 0, '0' );
		encoder.encode( &encoded, &evector[i] );
		encoder.decode( &decoded, &encoded );
		REQUIRE( 0 == decoded.compare( &evector[i] ) );
		REQUIRE( 0 == encoded.compare( &dvector[i] ) );
	}
}

TEST_CASE( "Base56Identity", "[encode]" ) {
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

    REQUIRE( 0 == ss.compare( &cmpStr ) );
    REQUIRE( b56.encode( &encoded, &decoded ) );
    REQUIRE( 0 == encoded.compare( &idString ) );
}

TEST_CASE( "Base56Check", "[encode]" ) {
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
		if( e.length() ) {
			REQUIRE( b56.decode( &d, &e ) );
		} else {
			b56.decode( &d, &e );
		}
        REQUIRE( d.compare( &(evector[i]) ) == 0 );
    }

    SqrlString lString = SqrlString( "This is a long sentence used to test Base56Check in a multi-line scenario." );
    b56.encode( &e, &lString );
    REQUIRE( b56.decode( &d, &e ) );
    REQUIRE( d.compare( &lString ) == 0 );
}

TEST_CASE( "Base56", "[encode]" ) {
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
		printf( "%s -> %s -> %s\n", evector[i].cstring(), e.cstring(), d.cstring() );
		REQUIRE( d.compare( &(evector[i]) ) == 0 );
    }
}
/*
f -> q3 -> f
fo -> G7B -> fo
foo -> ykaj2 -> foo
foob -> yksvz4 -> foob
fooba -> Q8SEUZF -> fooba
foobar -> y4MpRmpJ3 -> foobar
*/

TEST_CASE( "Base64", "[encode]" ) {
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
