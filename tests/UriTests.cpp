#include "catch.hpp"

#include "sqrl.h"
#include "SqrlUri.h"
#include "SqrlString.h"

using namespace libsqrl;

static void testString( SqrlString *a, const char *b ) {
    if( !a || a->length() == 0 ) {
        REQUIRE( (!b || strlen( b ) == 0) );
    } else {
        REQUIRE( a->compare( b ) == 0 );
    }
    if( a ) {
        delete a;
    }
}


TEST_CASE( "Uri1", "[uri]" ) {
    SqrlString inStr( "sqrl://sqrlid.com/login?x=6&nut=blah&sfn=U1FSTGlk" );
    SqrlUri uri = SqrlUri( &inStr );
    REQUIRE( uri.isValid() );
    REQUIRE( uri.getScheme() == SQRL_SCHEME_SQRL );
    testString( uri.getSiteKey(), "sqrlid.com/login" );
    testString( uri.getChallenge(), "sqrl://sqrlid.com/login?x=6&nut=blah&sfn=U1FSTGlk" );
    testString( uri.getUrl(), "https://sqrlid.com/login?x=6&nut=blah&sfn=U1FSTGlk" );
    testString( uri.getPrefix(), "https://sqrlid.com" );
    testString( uri.getSFN(), "SQRLid" );
}

TEST_CASE( "Uri2", "[uri]" ) {
    SqrlString str( "sqrl://sqrlid.com/login?nut=blah&sfn=U1FSTGlk" );
    SqrlUri uri = SqrlUri( &str );
    REQUIRE( uri.isValid() );
    REQUIRE( uri.getScheme() == SQRL_SCHEME_SQRL );
    testString( uri.getSiteKey(), "sqrlid.com" );
    testString( uri.getChallenge(), "sqrl://sqrlid.com/login?nut=blah&sfn=U1FSTGlk" );
    testString( uri.getUrl(), "https://sqrlid.com/login?nut=blah&sfn=U1FSTGlk" );
    testString( uri.getPrefix(), "https://sqrlid.com" );
    testString( uri.getSFN(), "SQRLid" );
}

TEST_CASE( "Uri3", "[uri]" ) {
    SqrlString str( "sqrl://sqrlid.com:8080/login?sfn=U1FSTGlk&nut=blah" );
    SqrlUri uri = SqrlUri( &str );
    REQUIRE( uri.isValid() );
    REQUIRE( uri.getScheme() == SQRL_SCHEME_SQRL );
    testString( uri.getSiteKey(), "sqrlid.com" );
    testString( uri.getChallenge(), "sqrl://sqrlid.com:8080/login?sfn=U1FSTGlk&nut=blah" );
    testString( uri.getUrl(), "https://sqrlid.com:8080/login?sfn=U1FSTGlk&nut=blah" );
    testString( uri.getPrefix(), "https://sqrlid.com:8080" );
    testString( uri.getSFN(), "SQRLid" );
}

TEST_CASE( "FileUri", "[uri]" ) {
    SqrlString str( "file://test1.sqrl" );
    SqrlUri uri = SqrlUri( &str );
    REQUIRE( uri.isValid() );
    REQUIRE( uri.getScheme() == SQRL_SCHEME_FILE );
    REQUIRE( uri.getSiteKeyLength() == 0 );
    testString( uri.getUrl(), "file://test1.sqrl" );
    testString( uri.getChallenge(), "test1.sqrl" );
    testString( uri.getPrefix(), NULL );
    testString( uri.getSFN(), NULL );
}

TEST_CASE( "SQRLUriWithoutSFN", "[uri]" ) {
    SqrlString str( "sqrl://sqrlid.com:8080/login?nut=blah" );
    SqrlUri uri = SqrlUri( &str );
    REQUIRE( !uri.isValid() );
}

TEST_CASE( "InvalidSQRLUrl", "[uri]" ) {
    SqrlString str( "http://google.com" );
    SqrlUri uri = SqrlUri( &str );
    REQUIRE( !uri.isValid() );
}
