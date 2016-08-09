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

using namespace libsqrl;

TEST_CASE( "GenerateIdentity", "[identity]" ) {
    GenClient *client = new GenClient();
    new SqrlActionGenerate();
    while( client->completed < 2 ) {
        Sleep( 100 );
    }
    delete client;
}
