/* user.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include <unistd.h>
#include <sodium.h>

#include "../sqrl_internal.h"

static int assertions_passed = 0;
#define CHAR_PER_LINE 72

#define ASSERT(m,a) if((a)) { assertions_passed++; } else { printf( "ASSERTION FAILED: %s\n", m ); goto ERROR; }

int main() 
{
	bool bError = false;
	sqrl_init();
	UT_string *buf;
	utstring_new( buf );
	Sqrl_User *user = sqrl_user_create();
	Sqrl_Storage storage = sqrl_storage_create();
	sqrl_user_set_password( user, "the password", 12 );

	/*
	ASSERT( "hintlock_1", !sqrl_user_is_hintlocked( user ) )
	sqrl_user_hintlock( user, NULL, NULL );
	ASSERT( "hintlock_2", sqrl_user_is_hintlocked( user ) )
	sqrl_user_hintunlock( user, "the ", 4, NULL, NULL );
	ASSERT( "hintlock_3", !sqrl_user_is_hintlocked( user ) )
	printf( "HNTLCK: PASS\n" );
	*/
	printf( "    PW: the password\n" );
	uint8_t saved[SQRL_KEY_SIZE*7];
	uint8_t loaded[SQRL_KEY_SIZE*7];
	uint8_t *sPointer = saved;
	char savedRC[25];
	uint8_t *key;

	char str[128];
	for( int i = 4; i > 0; i-- ) {
		sqrl_user_rekey( user );
		key = sqrl_user_key( user, KEY_IUK );
		memcpy( sPointer, key, SQRL_KEY_SIZE );
		sPointer += SQRL_KEY_SIZE;
		sodium_bin2hex( str, 128, key, SQRL_KEY_SIZE );
		printf( " PIUK%d: %s\n", i, str );
	}

	sqrl_user_rekey( user );
	key = sqrl_user_key( user, KEY_IUK );
	memcpy( sPointer, key, SQRL_KEY_SIZE );
	sPointer += SQRL_KEY_SIZE;
	sodium_bin2hex( str, 128, key, SQRL_KEY_SIZE );
	printf( "   IUK: %s\n", str );
	key = sqrl_user_key( user, KEY_ILK );
	memcpy( sPointer, key, SQRL_KEY_SIZE );
	sPointer += SQRL_KEY_SIZE;
	sodium_bin2hex( str, 128, key, SQRL_KEY_SIZE );
	printf( "   ILK: %s\n", str );
	key = sqrl_user_key( user, KEY_MK );
	memcpy( sPointer, key, SQRL_KEY_SIZE );
	sodium_bin2hex( str, 128, key, SQRL_KEY_SIZE );
	printf( "    MK: %s\n", str );
	strcpy( savedRC, sqrl_user_get_rescue_code( user ));
	printf( "    RC: %s\n", savedRC );

	sqrl_user_save( user, storage, NULL, NULL );
	sqrl_storage_save_to_buffer( storage, buf, SQRL_EXPORT_ALL, SQRL_ENCODING_BASE64 );
	ASSERT( "export_len", utstring_len( buf ) == 470 )
	printf( "EXPORT: PASS\n" );

	user = sqrl_user_destroy( user );
	user = sqrl_user_create();
	sqrl_user_set_password( user, "the password", 12 );

	sqrl_user_load_with_password( user, storage, NULL, NULL );
	key = sqrl_user_key( user, KEY_MK );
	ASSERT( "load_mk", 0 == sodium_memcmp( key, saved + (SQRL_KEY_SIZE * 6), SQRL_KEY_SIZE ));
	key = sqrl_user_key( user, KEY_ILK );
	ASSERT( "load_ilk", 0 == sodium_memcmp( key, saved + (SQRL_KEY_SIZE * 5), SQRL_KEY_SIZE ));
	key = sqrl_user_key( user, KEY_PIUK0 );
	ASSERT( "load_piuk1", 0 == sodium_memcmp( key, saved + (SQRL_KEY_SIZE * 3), SQRL_KEY_SIZE ));
	key = sqrl_user_key( user, KEY_PIUK1 );
	ASSERT( "load_piuk2", 0 == sodium_memcmp( key, saved + (SQRL_KEY_SIZE * 2), SQRL_KEY_SIZE ));
	key = sqrl_user_key( user, KEY_PIUK2 );
	ASSERT( "load_piuk3", 0 == sodium_memcmp( key, saved + (SQRL_KEY_SIZE * 1), SQRL_KEY_SIZE ));
	key = sqrl_user_key( user, KEY_PIUK3 );
	ASSERT( "load_piuk4", 0 == sodium_memcmp( key, saved, SQRL_KEY_SIZE ));
	printf( "PW_IMP: PASS\n" );

	user = sqrl_user_destroy( user );
	user = sqrl_user_create();
	sqrl_user_set_rescue_code( user, savedRC );
	sqrl_user_load_with_rescue_code( user, storage, NULL, NULL );
	sPointer = loaded;
	int keys[] = { KEY_PIUK3, KEY_PIUK2, KEY_PIUK1, KEY_PIUK0, KEY_IUK, KEY_ILK, KEY_MK };
	char names[][6] = { "PIUK4", "PIUK3", "PIUK2", "PIUK1", "  IUK", "  ILK", "   MK" };
	for( int i = 0; i < 7; i++ ) {
		key = sqrl_user_key( user, keys[i] );
		memcpy( sPointer, key, SQRL_KEY_SIZE );
		sPointer += SQRL_KEY_SIZE;
	}
	ASSERT( "load_rc", 0 == sodium_memcmp( loaded, saved, SQRL_KEY_SIZE * 7 ));
	printf( "RC_IMP: PASS\n" );

	char *start = utstring_body( buf );
	char *line = utstring_body( buf );
	char tmp[CHAR_PER_LINE + 1];
	size_t total = utstring_len( buf );
	printf( "  DATA:\n" );
	while( (line - start) < total ) {
		strncpy( tmp, line, CHAR_PER_LINE );
		printf( "%s\n", tmp );
		line += CHAR_PER_LINE;
	}

	utstring_free( buf );
	//sqrl_storage_save_to_file( storage, "test1.sqrl", SQRL_EXPORT_ALL, SQRL_ENCODING_BINARY );

	goto DONE;

ERROR:
	bError = true;

DONE:
	//pool = sqrl_entropy_destroy( pool );
	user = sqrl_user_destroy( user );
	storage = sqrl_storage_destroy( storage );
	printf( "\nPASSED %d tests.\n", assertions_passed );
	if( bError ) {
		printf( "\nFAILED test %d\n", assertions_passed + 1 );
		exit(1);
	}
	exit(0);
}
