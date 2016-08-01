#include "catch.hpp"
#include "BaseServer.h"
#include "NullClient.h"

TEST_CASE( "Server Link MAC" ) {
	BaseServer srv = BaseServer( "sqrl://test.sqrlid.com/sqrl?nut=_LIBSQRL_NUT_&sfn=_LIBSQRL_SFN_", "SQRLid", "test", 4 );
	std::string *str = srv.createLink( 0 );
	REQUIRE( srv.tryVerifyMAC( str ) );
	str->erase( str->length() - 4 );
	REQUIRE( !srv.tryVerifyMAC( str ) );
	delete str;
}