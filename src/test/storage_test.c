/* storage.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "../sqrl_internal.h"
#include <unistd.h>

int main() 
{
	bool bError = false;
	Sqrl_Storage storage;
	Sqrl_User user = sqrl_user_create();;
	
	sqrl_init();
	storage = sqrl_storage_create();
	sqrl_storage_load_from_file( storage, "test1.sqrl" );
	if( ! sqrl_storage_block_exists( storage, SQRL_BLOCK_USER )
		|| ! sqrl_storage_block_exists( storage, SQRL_BLOCK_RESCUE )) 
	{
		printf( "Bad Blocks\n" );
		goto ERROR;
	}
	char *pw = sqrl_user_password( user );
	size_t *pwl = sqrl_user_password_length( user );
	strcpy( pw, "the password" );
	*pwl = 12;
	if( SQRL_STATUS_OK != sqrl_user_load_with_password( user, storage, NULL, NULL )) {
		printf( "Load failed\n" );
		goto ERROR;
	}
	goto DONE;

ERROR:
	bError = true;

DONE:
	if( storage ) {
		storage = sqrl_storage_destroy( storage );
	}
	user = sqrl_user_destroy( user );
	if( bError ) {
		printf( "FAIL\n" );
		exit(1);
	} else {
		printf( "PASS\n" );
		exit(0);
	}
}
