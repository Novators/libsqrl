/* storage.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "../sqrl_internal.h"
#include <unistd.h>

char myPassword[32];

bool onAuthenticationRequired(
	Sqrl_Client_Transaction *transaction,
	Sqrl_Credential_Type credentialType )
{
	char *cred = NULL;
	uint8_t len;

	switch( credentialType ) {
	case SQRL_CREDENTIAL_PASSWORD:
		printf( "   REQ: Password\n" );
		cred = malloc( strlen( myPassword ) + 1 );
		strcpy( cred, myPassword );
		break;
	case SQRL_CREDENTIAL_HINT:
		printf( "   REQ: Hint\n" );
		len = sqrl_user_get_hint_length( transaction->user );
		cred = malloc( len + 1 );
		strncpy( cred, myPassword, len );
		break;
	case SQRL_CREDENTIAL_RESCUE_CODE:
		printf( "Rescue Code Requested, but not needed!\n" );
		exit(1);
	default:
		return false;
	}
	sqrl_client_authenticate( transaction, credentialType, cred, strlen( cred ));
	if( cred ) {
		free( cred );
	}
	return true;
}

char transactionType[11][10] = {
	"UNKNWN",
	"IDENT",
	"DISABL",
	"ENABLE",
	"REMOVE",
	"SAVE",
	"RECOVR",
	"REKEY",
	"UNLOCK",
	"LOCK",
	"LOAD"
};
bool showingProgress = false;
int nextProgress = 0;
int onProgress( Sqrl_Client_Transaction *transaction, int p )
{
	if( !showingProgress ) {
		// Transaction type
		showingProgress = true;
		nextProgress = 2;
		printf( "%6s: ", transactionType[transaction->type] );
	}
	const char sym[] = "|****";
	while( p >= nextProgress ) {
		if( nextProgress != 100 ) {
			printf( "%c", sym[nextProgress%5] );
		}
		nextProgress += 2;
	}
	if( p >= 100 ) {
		printf( "\n" );
		showingProgress = false;
	}
	fflush( stdout );
	return 1;

}


int main() 
{
	strcpy( myPassword, "the password" );
	sqrl_init();
	bool bError = false;
	Sqrl_Storage storage = NULL;
	Sqrl_User user = NULL;
	uint8_t *key = NULL;
	
	Sqrl_Client_Transaction t;
	memset( &t, 0, sizeof( Sqrl_Client_Transaction ));

	Sqrl_Client_Callbacks cbs;
	memset( &cbs, 0, sizeof( Sqrl_Client_Callbacks ));
	cbs.onAuthenticationRequired = onAuthenticationRequired;
	cbs.onProgress = onProgress;
	sqrl_client_set_callbacks( &cbs );

	storage = sqrl_storage_create();
	sqrl_storage_load_from_file( storage, "test1.sqrl" );
	if( ! sqrl_storage_block_exists( storage, SQRL_BLOCK_USER )
		|| ! sqrl_storage_block_exists( storage, SQRL_BLOCK_RESCUE )) 
	{
		printf( "Bad Blocks\n" );
		goto ERROR;
	}
	storage = sqrl_storage_destroy( storage );

	user = sqrl_user_create_from_file( "test1.sqrl" );
	t.user = user;
	key = sqrl_user_key( &t, KEY_MK );
	if( !key ) {
		printf( "Load Failed\n" );
		goto ERROR;
	}

	strcpy( myPassword, "asdfjkl" );
	sqrl_user_set_password( user, myPassword, 7 );
	UT_string *buf;
	utstring_new( buf );
	WITH_USER(u,user);
	Sqrl_Client_Transaction transaction;
	memset( &transaction, 0, sizeof( Sqrl_Client_Transaction ));
	transaction.type = SQRL_TRANSACTION_IDENTITY_SAVE;
	transaction.user = user;
	sqrl_user_update_storage( &transaction );
	sqrl_storage_save_to_buffer( u->storage, buf, SQRL_EXPORT_ALL, SQRL_ENCODING_BASE64 );
	END_WITH_USER(u);
	user = sqrl_user_release( user );
	user = NULL; // Make sure...
	user = sqrl_user_create_from_buffer( utstring_body( buf ), utstring_len(buf));
	utstring_free( buf );
	buf = NULL;
	t.user = user;

	key = sqrl_user_key( &t, KEY_MK );
	if( !key ) {
		printf( "New Password Failed\n" );
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
