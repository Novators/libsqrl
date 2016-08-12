#include "catch.hpp"

#include "sqrl.h"
#include "SqrlUri.h"
#include "SqrlString.h"
#include "NullClient.h"

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
    new NullClient();
    SqrlString inStr( "sqrl://sqrlid.com/login?x=6&nut=blah&sfn=U1FSTGlk" );
    SqrlUri uri = SqrlUri( &inStr );
    REQUIRE( uri.isValid() );
    REQUIRE( uri.getScheme() == SQRL_SCHEME_SQRL );
    testString( uri.getSiteKey(), "sqrlid.com/login" );
    testString( uri.getChallenge(), "sqrl://sqrlid.com/login?x=6&nut=blah&sfn=U1FSTGlk" );
    testString( uri.getUrl(), "https://sqrlid.com/login?x=6&nut=blah&sfn=U1FSTGlk" );
    testString( uri.getPrefix(), "https://sqrlid.com" );
    testString( uri.getSFN(), "SQRLid" );
    delete (NullClient*)NullClient::getClient();
}

TEST_CASE( "Uri2", "[uri]" ) {
    new NullClient();
    SqrlString str( "sqrl://sqrlid.com/login?nut=blah&sfn=U1FSTGlk" );
    SqrlUri uri = SqrlUri( &str );
    REQUIRE( uri.isValid() );
    REQUIRE( uri.getScheme() == SQRL_SCHEME_SQRL );
    testString( uri.getSiteKey(), "sqrlid.com" );
    testString( uri.getChallenge(), "sqrl://sqrlid.com/login?nut=blah&sfn=U1FSTGlk" );
    testString( uri.getUrl(), "https://sqrlid.com/login?nut=blah&sfn=U1FSTGlk" );
    testString( uri.getPrefix(), "https://sqrlid.com" );
    testString( uri.getSFN(), "SQRLid" );
    delete (NullClient*)NullClient::getClient();
}

TEST_CASE( "Uri3", "[uri]" ) {
    new NullClient();
    SqrlString str( "sqrl://sqrlid.com:8080/login?sfn=U1FSTGlk&nut=blah" );
    SqrlUri uri = SqrlUri( &str );
    REQUIRE( uri.isValid() );
    REQUIRE( uri.getScheme() == SQRL_SCHEME_SQRL );
    testString( uri.getSiteKey(), "sqrlid.com" );
    testString( uri.getChallenge(), "sqrl://sqrlid.com:8080/login?sfn=U1FSTGlk&nut=blah" );
    testString( uri.getUrl(), "https://sqrlid.com:8080/login?sfn=U1FSTGlk&nut=blah" );
    testString( uri.getPrefix(), "https://sqrlid.com:8080" );
    testString( uri.getSFN(), "SQRLid" );
    delete (NullClient*)NullClient::getClient();
}

TEST_CASE( "FileUri", "[uri]" ) {
    new NullClient();
    SqrlString str( "file://test1.sqrl" );
    SqrlUri uri = SqrlUri( &str );
    REQUIRE( uri.isValid() );
    REQUIRE( uri.getScheme() == SQRL_SCHEME_FILE );
    REQUIRE( uri.getSiteKeyLength() == 0 );
    testString( uri.getUrl(), "file://test1.sqrl" );
    testString( uri.getChallenge(), "test1.sqrl" );
    testString( uri.getPrefix(), NULL );
    testString( uri.getSFN(), NULL );
    delete (NullClient*)NullClient::getClient();
}

TEST_CASE( "SQRLUriWithoutSFN", "[uri]" ) {
    new NullClient();
    SqrlString str( "sqrl://sqrlid.com:8080/login?nut=blah" );
    SqrlUri uri = SqrlUri( &str );
    REQUIRE( !uri.isValid() );
    delete (NullClient*)NullClient::getClient();
}

TEST_CASE( "InvalidSQRLUrl", "[uri]" ) {
    new NullClient();
    SqrlString str( "http://google.com" );
    SqrlUri uri = SqrlUri( &str );
    REQUIRE( !uri.isValid() );
    delete (NullClient*)NullClient::getClient();
}
