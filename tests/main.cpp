#define CATCH_CONFIG_RUNNER
#include "catch.hpp"
#include "sqrl.h"
#include <iostream>

using namespace std;
using namespace libsqrl;

int main( int argc, char* const argv[] ) {
    // global setup...
    size_t ln = Sqrl_Version( NULL, 0 ) + 1;
    char *ver = (char*)malloc( ln );
    Sqrl_Version( ver, ln );
    cout << "Testing libsqrl " << ver << endl;
    free( ver );

    int result = Catch::Session().run( argc, argv );

    // global clean-up...
    cout << "Press Enter to Finish..." << endl;
    cin.get();

    return result;
}