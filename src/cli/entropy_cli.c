/** @file entropy_cli.c  

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif
#include <sodium.h>
#include <stdint.h>
#include "../sqrl_client.h"
#include "../entropy/rdrand.h"

int main(int argc, char **argv)
{
	if( rdrand_available() ) {
		fprintf( stderr, "rdrand supported.\n" );
	} else {
		fprintf( stderr, "rdrand NOT supported.\n" );
	}
	uint8_t buf[64];
	sodium_mlock( buf, 64 );
	char hex[130];
	char *result;

	while( 1 ) {
		int received_entropy = sqrl_entropy_get_blocking( buf, 64 );
		result = sodium_bin2hex( hex, 129, (unsigned char*)buf, 64 );
		if( result ) {
			printf( "%d: %s\n", received_entropy, result );
		}
#ifdef _WIN32
		Sleep(1000);
#else
		sleep(1);
#endif
	}
	sodium_munlock( buf, crypto_hash_sha512_BYTES );
	
	return 0;
}

