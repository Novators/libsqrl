#include "catch.hpp"

#include "sqrl.h"
#include "SqrlUri.h"
#include "SqrlString.h"
#include "NullClient.h"

static void testString(char *a, const char *b) {
	if( !a ) {
		REQUIRE( ! b );
	} else {
		REQUIRE( 0 == strcmp( a, b ) );
		free( a );
	}
}

TEST_CASE("Uri1")
{
	new NullClient();
	SqrlString str( "sqrl://sqrlid.com/login?x=6&nut=blah&sfn=U1FSTGlk" );
	SqrlUri *uri = SqrlUri::parse( &str );
	REQUIRE( uri );
	REQUIRE( uri->getScheme() == SQRL_SCHEME_SQRL );
	testString(uri->getSiteKey(), "sqrlid.com/login");
	testString(uri->getChallenge(), "sqrl://sqrlid.com/login?x=6&nut=blah&sfn=U1FSTGlk");
	testString(uri->getUrl(), "https://sqrlid.com/login?x=6&nut=blah&sfn=U1FSTGlk");
	testString(uri->getPrefix(), "https://sqrlid.com");
	testString(uri->getSFN(), "SQRLid");
	uri->release();
	delete (NullClient*)NullClient::getClient();
}
		
TEST_CASE("Uri2")
{
	new NullClient();
	SqrlString str( "sqrl://sqrlid.com/login?nut=blah&sfn=U1FSTGlk" );
	SqrlUri *uri = SqrlUri::parse( &str );
	REQUIRE( uri );
	REQUIRE( uri->getScheme() == SQRL_SCHEME_SQRL );
	testString(uri->getSiteKey(), "sqrlid.com");
	testString(uri->getChallenge(), "sqrl://sqrlid.com/login?nut=blah&sfn=U1FSTGlk");
	testString(uri->getUrl(), "https://sqrlid.com/login?nut=blah&sfn=U1FSTGlk");
	testString(uri->getPrefix(), "https://sqrlid.com");
	testString(uri->getSFN(), "SQRLid");
	uri->release();
	delete (NullClient*)NullClient::getClient();
}
		
TEST_CASE("Uri3")
{
	new NullClient();
	SqrlString str( "sqrl://sqrlid.com:8080/login?sfn=U1FSTGlk&nut=blah" );
	SqrlUri *uri = SqrlUri::parse( &str );
	REQUIRE( uri );
	REQUIRE( uri->getScheme() == SQRL_SCHEME_SQRL );
	testString(uri->getSiteKey(), "sqrlid.com");
	testString(uri->getChallenge(), "sqrl://sqrlid.com:8080/login?sfn=U1FSTGlk&nut=blah");
	testString(uri->getUrl(), "https://sqrlid.com:8080/login?sfn=U1FSTGlk&nut=blah");
	testString(uri->getPrefix(), "https://sqrlid.com:8080");
	testString(uri->getSFN(), "SQRLid");
	uri->release();
	delete (NullClient*)NullClient::getClient();
}
		
TEST_CASE("FileUri")
{
	new NullClient();
	SqrlString str( "file://test1.sqrl" );
	SqrlUri *uri = SqrlUri::parse( &str );
	REQUIRE( uri );
	REQUIRE( uri->getScheme() == SQRL_SCHEME_FILE );
	REQUIRE( uri->getSiteKeyLength() == 0 );
	testString(uri->getUrl(), "file://test1.sqrl");
	testString(uri->getChallenge(), "test1.sqrl");
	testString(uri->getPrefix(), NULL);
	testString(uri->getSFN(), NULL);
	uri->release();
	delete (NullClient*)NullClient::getClient();
}
		
TEST_CASE("SQRLUriWithoutSFN")
{
	new NullClient();
	SqrlString str( "sqrl://sqrlid.com:8080/login?nut=blah" );
	SqrlUri *uri = SqrlUri::parse( &str );
	REQUIRE( ! uri );
	delete (NullClient*)NullClient::getClient();
}
		
TEST_CASE("InvalidSQRLUrl")
{
	new NullClient();
	SqrlString str( "http://google.com" );
	SqrlUri *uri = SqrlUri::parse( &str );
	REQUIRE( ! uri );
	delete (NullClient*)NullClient::getClient();
}
