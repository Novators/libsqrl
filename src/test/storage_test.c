/* storage.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "../sqrl_internal.h"
#include <unistd.h>

int main() 
{
	sqrl_init();
	bool bError = false;
	Sqrl_Storage storage;
	Sqrl_User user = sqrl_user_create_from_file( "test1.sqrl" );
	
	storage = sqrl_storage_create();
	sqrl_storage_load_from_file( storage, "test1.sqrl" );
	if( ! sqrl_storage_block_exists( storage, SQRL_BLOCK_USER )
		|| ! sqrl_storage_block_exists( storage, SQRL_BLOCK_RESCUE )) 
	{
		printf( "Bad Blocks\n" );
		goto ERROR;
	}
	sqrl_user_set_password( user, "the password", 12 );
	if( SQRL_STATUS_OK != sqrl_user_load_with_password( user, NULL, NULL )) {
		printf( "Load failed\n" );
		goto ERROR;
	} 
	sqrl_user_set_password( user, "asdf", 4 );
	char *buf = sqrl_user_save_to_buffer( user, NULL, SQRL_EXPORT_ALL, SQRL_ENCODING_BASE64 );
	user = sqrl_user_release( user );
	user = NULL; // Make sure...
	user = sqrl_user_create_from_buffer( buf, strlen(buf));
	sqrl_user_set_password( user, "asdf", 4 );
	if( SQRL_STATUS_OK != sqrl_user_load_with_password( user, NULL, NULL )) {
		printf( "New Password failed\n" );
		goto ERROR;
	}
	goto DONE;

ERROR:
	bError = true;

DONE:
	if( storage ) {
		storage = sqrl_storage_destroy( storage );
	}
	user = sqrl_user_release( user );
	if( bError ) {
		printf( "FAIL\n" );
		exit(1);
	} else {
		printf( "PASS\n" );
		exit(0);
	}
}
