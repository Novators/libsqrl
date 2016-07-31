#include "catch.hpp"
#include <cstdlib>

#include <Windows.h>
#include "sqrl.h"
#include "SqrlClient.h"
#include "SqrlUser.h"
#include "SqrlActionGenerate.h"
#include "SqrlActionSave.h"
#include "SqrlEntropy.h"
#include "GenClient.h"


TEST_CASE( "GenerateIdentity" ) {
	GenClient *client = new GenClient();
	new SqrlActionGenerate();
	while( client->completed < 2 ) {
		Sleep( 100 );
	}
	delete client;
}
