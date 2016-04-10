/* genrandom.c  

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/

#include <stdio.h>
#include <unistd.h>
#include "../sqrl_expert.h"

int main() 
{
	uint8_t rnd[64];
	uint64_t i, j;
	sqrl_init();

//	FILE *fp = fopen( "random.bin", "wb" );
//	if( !fp ) exit(1);
//	for( i = 0; i < 18750000; i++ ) {
	while(1) {
		sqrl_entropy_add( NULL, 0 );
		sqrl_entropy_get( rnd, 1 );
		fwrite( rnd, 32, 2, stdout );
		fflush( stdout );
//		fwrite( rnd, 32, 2, fp );
	}
//	fclose( fp );

	exit(0);
}