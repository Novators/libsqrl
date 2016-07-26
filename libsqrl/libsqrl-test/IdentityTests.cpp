#include <cstdlib>
#include "stdafx.h"
#include "CppUnitTest.h"

#include <Windows.h>
#include "sqrl.h"
#include "SqrlClient.h"
#include "SqrlUser.h"
#include "SqrlActionGenerate.h"
#include "SqrlActionSave.h"
#include "GenClient.h"


using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std;

namespace libsqrltest
{
	TEST_CLASS( IdentityTests ) {
public:
	TEST_CLASS_INITIALIZE( InitializeSqrl ) {
		char v[64];
		Sqrl_Version( v, 64 );
		std::string str( "GenerateTests: " );
		str.append( v );
		Logger::WriteMessage( str.data() );
	}

	TEST_METHOD( GenerateIdentity ) {
		GenClient *client = new GenClient();
		new SqrlActionGenerate();
		while( client->completed < 2 ) {
			Sleep( 100 );
		}
		delete client;
	}

	TEST_CLASS_CLEANUP( StopSqrl ) {
	}
	};

}