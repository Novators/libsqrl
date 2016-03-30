/** @file user.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/
#include <stdlib.h>
#include <stdio.h>
#include "sqrl_internal.h"


int sqrl_user_enscrypt_callback( int percent, void *data )
{
	struct sqrl_user_callback_data *cbdata = (struct sqrl_user_callback_data*)data;
	if( cbdata->cbfn ) {
		int progress = cbdata->adder + (percent / cbdata->divisor);
		if( progress > 100 ) progress = 100;
		if( progress < 0 ) progress = 0;
		return (cbdata->cbfn)( SQRL_STATUS_OK, progress, cbdata->cbdata );
	} else {
		return 1;
	}
}

void sqrl_user_ensure_keys_allocated( Sqrl_User u )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return;
	if( user->keys == NULL ) {
		user->keys = sodium_malloc( sizeof( struct Sqrl_Keys ));
		BIT_UNSET( user->flags, USER_FLAG_MEMLOCKED );
	}
}

/**
Creates an empty \p Sqrl_User, ready to generate or load identity data.

@return Pointer to new \p Sqrl_User
*/
DLL_PUBLIC
Sqrl_User sqrl_user_create()
{
	struct Sqrl_User *user = calloc( 1, sizeof( struct Sqrl_User ));
	sqrl_user_default_options( &user->options );
	return (Sqrl_User)user;
}

/**
Securely erases and frees memory of a \p Sqrl_User

@param u A \p Sqrl_User
@return NULL
*/
DLL_PUBLIC
Sqrl_User sqrl_user_destroy( Sqrl_User u )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return NULL;
	if( user->keys != NULL ) {
		sodium_mprotect_readwrite( user->keys );
		sodium_free( user->keys );
	}
	sodium_memzero( user, sizeof( Sqrl_User ));
	free( user );
	return NULL;
}

bool sqrl_user_is_memlocked( Sqrl_User u ) {
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return false;
	if( BIT_CHECK( user->flags, USER_FLAG_MEMLOCKED )) {
		return true;
	}
	return false;
}

void sqrl_user_memlock( Sqrl_User u ) {
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return;
	if( user->keys != NULL ) {
		sodium_mprotect_noaccess( user->keys );
	}
	BIT_SET( user->flags, USER_FLAG_MEMLOCKED );
}

void sqrl_user_memunlock( Sqrl_User u )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return;
	if( user->keys != NULL ) {
		sodium_mprotect_readwrite( user->keys );
	}
	BIT_UNSET( user->flags, USER_FLAG_MEMLOCKED );
}

/**
Checks to see if a \p Sqrl_User has been encrypted with a hint

@param u A \p Sqrl_User
@return true if user is Hint Locked
*/
DLL_PUBLIC
bool sqrl_user_is_hintlocked( Sqrl_User u )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return false;
	if( user->hint_iterations == 0 ) return false;
	return true;
}

/**
Encrypts the memory of a \p Sqrl_User using a hint (truncated password).
The length of the hint is specified in the user's \p Sqrl_User_Options.

@param u A \p Sqrl_User
@param callback Function to call during decryption
@param callback_data Data for \p callback
*/
DLL_PUBLIC
void sqrl_user_hintlock( Sqrl_User u, 
				sqrl_status_fn callback, 
				void *callback_data )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return;
	if( sqrl_user_is_hintlocked( user )) return;
	RELOCK_START(user,relock);
	sqrl_user_memunlock( user );
	struct sqrl_user_callback_data cbdata;
	cbdata.cbfn = callback;
	cbdata.cbdata = callback_data;
	cbdata.adder = 0;
	cbdata.divisor = 1;

	Sqrl_Crypt_Context sctx;
	uint8_t iv[12] = {0};
	sctx.plain_text = user->keys->keys[0];
	sctx.text_len = sizeof( struct Sqrl_Keys ) - KEY_SCRATCH_SIZE;
	sctx.salt = user->keys->scratch;
	sctx.iv = iv;
	sctx.tag = user->keys->scratch + 16;
	sctx.cipher_text = user->keys->scratch + 64;
	sctx.add = NULL;
	sctx.add_len = 0;
	sctx.nFactor = SQRL_DEFAULT_N_FACTOR;
	sctx.count = user->options.enscryptSeconds * SQRL_MILLIS_PER_SECOND;
	sctx.flags = SQRL_ENCRYPT | SQRL_MILLIS;

	randombytes_buf( sctx.salt, 16 );
	uint8_t *key = user->keys->scratch + 32;
	size_t password_len = user->options.hintLength;
	if( password_len == 0 || user->keys->password_len < password_len ) {
		password_len = user->keys->password_len;
	}

	user->hint_iterations = sqrl_crypt_enscrypt( 
		&sctx, 
		key, 
		user->keys->password, 
		password_len,
		sqrl_user_enscrypt_callback,
		&cbdata );
	if( user->hint_iterations <= 0 ||
		!sqrl_crypt_gcm( &sctx, key )) {
		// Encryption failed!
		user->hint_iterations = 0;
		sodium_memzero( user->keys->scratch, KEY_SCRATCH_SIZE );
		RELOCK_END(user,relock);
		return;
	}

	sodium_memzero( sctx.plain_text, sctx.text_len );
	sodium_memzero( key, SQRL_KEY_SIZE );
	RELOCK_END(user,relock);
}

/**
Decrypts the memory of a \p Sqrl_User using a hint (truncated password)

@param u A \p Sqrl_User
@param hint The password hint
@param length Length of \p hint
@param callback Function to call during decryption
@param callback_data Data for \p callback
*/
DLL_PUBLIC
void sqrl_user_hintunlock( Sqrl_User u, 
				char *hint, 
				size_t length, 
				sqrl_status_fn callback, 
				void *callback_data )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return;
	if( !sqrl_user_is_hintlocked( user )) return;

	RELOCK_START(user,relock);
	struct sqrl_user_callback_data cbdata;
	cbdata.cbfn = callback;
	cbdata.cbdata = callback_data;
	cbdata.adder = 0;
	cbdata.divisor = 1;

	Sqrl_Crypt_Context sctx;
	uint8_t iv[12] = {0};
	sctx.plain_text = user->keys->keys[0];
	sctx.text_len = sizeof( struct Sqrl_Keys ) - KEY_SCRATCH_SIZE;
	sctx.salt = user->keys->scratch;
	sctx.iv = iv;
	sctx.tag = user->keys->scratch + 16;
	sctx.cipher_text = user->keys->scratch + 64;
	sctx.add = NULL;
	sctx.add_len = 0;
	sctx.nFactor = SQRL_DEFAULT_N_FACTOR;
	sctx.count = user->hint_iterations;
	sctx.flags = SQRL_DECRYPT | SQRL_ITERATIONS;

	uint8_t *key = user->keys->scratch + 32;
	sqrl_crypt_enscrypt( &sctx, key, hint, length, sqrl_user_enscrypt_callback, &cbdata );
	if( !sqrl_crypt_gcm( &sctx, key )) {
		sodium_memzero( sctx.plain_text, sctx.text_len );
		sodium_memzero( key, SQRL_KEY_SIZE );
		RELOCK_END(user,relock);
		return;
	}
	user->hint_iterations = 0;
	sodium_memzero( user->keys->scratch, KEY_SCRATCH_SIZE );
	RELOCK_END(user,relock);
}

bool _su_keygen( Sqrl_User u, int key_type, uint8_t *key )
{
	SQRL_CAST_USER(user,u);
	int i;
	uint8_t *temp[4];
	int keys[] = {KEY_PIUK0, KEY_PIUK1, KEY_PIUK2, KEY_PIUK3};
	switch( key_type ) {
	case KEY_IUK:
		for( i = 0; i < 4; i++ ) {
			if( sqrl_user_has_key( u, keys[i] )) {
				temp[i] = sqrl_user_key( u, keys[i] );
			} else {
				temp[i] = sqrl_user_new_key( u, keys[i] );
			}
		}
		memcpy( temp[3], temp[2], SQRL_KEY_SIZE );
		memcpy( temp[2], temp[1], SQRL_KEY_SIZE );
		memcpy( temp[1], temp[0], SQRL_KEY_SIZE );
		memcpy( temp[0], key, SQRL_KEY_SIZE );
		sqrl_entropy_bytes( key, SQRL_KEY_SIZE );
		return true;
	case KEY_MK:
		temp[0] = sqrl_user_key( u, KEY_IUK );
		if( temp[0] ) {
			sqrl_gen_mk( key, temp[0] );
			return true;
		}
		break;
	case KEY_ILK:
		temp[0] = sqrl_user_key( u, KEY_IUK );
		if( temp[0] ) {
			sqrl_gen_ilk( key, temp[0] );
			return true;
		}
		break;
	case KEY_LOCAL:
		temp[0] = sqrl_user_key( u, KEY_MK );
		if( temp[0] ) {
			sqrl_gen_local( key, temp[0] );
			return true;
		}
		break;
	case KEY_RESCUE_CODE:
		temp[0] = malloc( 512 );
		if( temp[0] ) {
			memset( key, 0, SQRL_KEY_SIZE );
			sodium_mlock( temp[0], 512 );
			sqrl_entropy_get_blocking( temp[0], SQRL_ENTROPY_NEEDED );
			bin2rc( (char*)key, temp[0] );
			sodium_munlock( temp[0], 512 );
			free( temp[0] );
			temp[0] = NULL;
			return true;
		}
		break;
	}
	return false;
}

bool sqrl_user_regen_keys( Sqrl_User u )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return NULL;
	RELOCK_START(user,relock);
	uint8_t *key;
	int keys[] = { KEY_MK, KEY_ILK, KEY_LOCAL };
	for( int i = 0; i < 3; i++ ) {
		key = sqrl_user_key( u, keys[i] );
		_su_keygen( u, keys[i], key );
	}
	RELOCK_END(user,relock);
	return true;
}

bool sqrl_user_rekey( Sqrl_User u )
{
	bool retVal = true;
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return NULL;
	RELOCK_START(user,relock);
	uint8_t *key;
	if( sqrl_user_has_key( u, KEY_IUK )) {
		key = sqrl_user_key( u, KEY_IUK );
	} else {
		key = sqrl_user_new_key( u, KEY_IUK );
	}
	if( ! _su_keygen( u, KEY_IUK, key )) {
		goto ERROR;
	}
	key = sqrl_user_new_key( u, KEY_RESCUE_CODE );
	if( ! _su_keygen( u, KEY_RESCUE_CODE, key )) {
		goto ERROR;
	}
	if( ! sqrl_user_regen_keys( u )) {
		goto ERROR;
	}
	goto DONE;

ERROR:
	retVal = false;

DONE:
	RELOCK_END(user,relock);
	return retVal;
}

uint8_t *sqrl_user_new_key( Sqrl_User u, int key_type )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return NULL;
	RELOCK_START(user,relock);
	int offset = -1;
	int empty = -1;
	for( int i = 0; i < USER_MAX_KEYS; i++ ) {
		if( user->lookup[i] == key_type ) {
			offset = i;
		}
		if( user->lookup[i] == 0 ) {
			empty = i;
		}
	}
	if( offset == -1 ) {
		// Not Found
		if( empty > -1 ) {
			// Create new slot
			user->lookup[empty] = key_type;
			offset = empty;
		}
	}
	if( offset ) {
		uint8_t *key = user->keys->keys[offset];
		sodium_memzero( key, SQRL_KEY_SIZE );
		RELOCK_END(user,relock);
		return key;
	}
	RELOCK_END(user,relock);
	return NULL;
}

uint8_t *sqrl_user_key( Sqrl_User u, int key_type )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return NULL;
	RELOCK_START(user,relock);
	int offset = -1;
	int empty = -1;
	for( int i = 0; i < USER_MAX_KEYS; i++ ) {
		if( user->lookup[i] == key_type ) {
			offset = i;
			break;
		}
		if( user->lookup[i] == 0 ) {
			empty = i;
		}
	}
	if( offset > -1 ) {
		RELOCK_END(user,relock);
		return user->keys->keys[offset];
	} else {
		// Not Found
		if( key_type == KEY_IUK || key_type == KEY_RESCUE_CODE ) {
			RELOCK_END(user,relock);
			// These types will not be auto-generated...
			return NULL;
		}
		if( empty > -1 ) {
			// Create new slot
			offset = empty;
			uint8_t *key = user->keys->keys[offset];
			if( _su_keygen( u, key_type, key )) {
				user->lookup[empty] = key_type;
				RELOCK_END(user,relock);
				return key;
			}
		}
	}
	RELOCK_END(user,relock);
	return NULL;
}

bool sqrl_user_has_key( Sqrl_User u, int key_type )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return false;
	for( int i = 0; i < USER_MAX_KEYS; i++ ) {
		if( user->lookup[i] == key_type ) {
			return true;
		}
	}
	return false;
}

void sqrl_user_remove_key( Sqrl_User u, int key_type )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return;
	int offset = -1;
	for( int i = 0; i < USER_MAX_KEYS; i++ ) {
		if( user->lookup[i] == key_type ) {
			offset = i;
		}
	}
	if( offset > -1 ) {
		RELOCK_START(user,relock);
		sodium_memzero( user->keys->keys[offset], SQRL_KEY_SIZE );
		RELOCK_END(user,relock);
		user->lookup[offset] = 0;
	}
}

/**
Gets the Rescue Code for a \p Sqrl_User.  This is only available after rekeying an identity.

@param u A \p Sqrl_User
@return Pointer to 24 character string
@return NULL if Rescue Code is not available
*/
DLL_PUBLIC
char *sqrl_user_get_rescue_code( Sqrl_User u )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return NULL;
	if( ! sqrl_user_has_key( u, KEY_RESCUE_CODE )) {
		return NULL;
	}
	sqrl_user_ensure_keys_allocated( u );
	if( sqrl_user_is_memlocked( u )) {
		sqrl_user_memunlock( u );
	}
	return (char*)(sqrl_user_key( u, KEY_RESCUE_CODE ));
}

/**
Sets the Rescue Code for a \p Sqrl_User.  This should only be used when recovering an identity.

@param u A \p Sqrl_User
@param rc A 24 character null terminated string.  All characters must be digits (0-9)
@return true on success
*/
DLL_PUBLIC
bool sqrl_user_set_rescue_code( Sqrl_User u, char *rc )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return false;
	if( strlen( rc ) != 24 ) return false;
	for( int i = 0; i < SQRL_RESCUE_CODE_LENGTH; i++ ) {
		if( rc[i] < '0' || rc[i] > '9' ) {
			return false;
		}
	}
	RELOCK_START(user,relock);
	uint8_t *key = sqrl_user_new_key( u, KEY_RESCUE_CODE );
	memcpy( key, rc, SQRL_RESCUE_CODE_LENGTH );
	RELOCK_END(user,relock);
	return true;
}

/**
Sets the password for a \p User. Passwords longer than 512 characters are truncated.

@param u A \p Sqrl_User
@param password A new password
@param password_len Length of \p password
@return true on success
*/
DLL_PUBLIC
bool sqrl_user_set_password( Sqrl_User u, char *password, size_t password_len )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return false;
	RELOCK_START(user,relock);
	char *p = sqrl_user_password( u );
	size_t *l = sqrl_user_password_length( u );
	if( !p || !l ) return false;
	sodium_memzero( p, KEY_PASSWORD_MAX_LEN );
	if( password_len > KEY_PASSWORD_MAX_LEN ) password_len = KEY_PASSWORD_MAX_LEN;
	memcpy( p, password, password_len );
	if( *l > 0 ) {
		// 	Changing password
		BIT_SET(user->flags, USER_FLAG_T1_CHANGED);
	}
	*l = password_len;
	RELOCK_END(user,relock);
	return true;
}

/**
Gets a user's password.

\warning Do not exceed 512 characters!

@param u A \p Sqrl_User
@return Pointer to char
*/
DLL_PUBLIC
char *sqrl_user_password( Sqrl_User u )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return NULL;
	sqrl_user_ensure_keys_allocated( user );
	if( sqrl_user_is_memlocked( u )) {
		sqrl_user_memunlock( u );
	}
	return user->keys->password;
}

/**
Gets the length of a user's password

\warning The maximum password length is 512!

@param u A \p Sqrl_User
@return Pointer to size_t
*/
DLL_PUBLIC
size_t *sqrl_user_password_length( Sqrl_User u )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return NULL;
	sqrl_user_ensure_keys_allocated( user );
	if( sqrl_user_is_memlocked( u )) {
		sqrl_user_memunlock( u );
	}
	return &user->keys->password_len;
}

uint8_t *sqrl_user_scratch( Sqrl_User u )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return NULL;
	sqrl_user_ensure_keys_allocated( user );
	if( sqrl_user_is_memlocked( u )) {
		sqrl_user_memunlock( u );
	}
	return user->keys->scratch;
}

/**
Gets \p Sqrl_User_Options for a \p Sqrl_User

@param u A \p Sqrl_User
@return Number of characters to use as a password hint
*/
DLL_PUBLIC
uint8_t sqrl_user_get_hint_length( Sqrl_User u )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return 0;
	return user->options.hintLength;
}

/**
Gets \p Sqrl_User_Options for a \p Sqrl_User

@param u A \p Sqrl_User
@return Seconds to run EnScrypt when encrypting the identity
*/
DLL_PUBLIC
uint8_t sqrl_user_get_enscrypt_seconds( Sqrl_User u )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return 0;
	return user->options.enscryptSeconds;
}

/**
Gets \p Sqrl_User_Options for a \p Sqrl_User

@param u A \p Sqrl_User
@return Minutes to retain hint data when computer is idle
*/
DLL_PUBLIC
uint16_t sqrl_user_get_timeout_minutes( Sqrl_User u )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return 0;
	return user->options.timeoutMinutes;
}

/**
Sets \p Sqrl_User_Options for a \p Sqrl_User

@param u A \p Sqrl_User
@param length The number of characters to use as a password hint
*/
DLL_PUBLIC
void sqrl_user_set_hint_length( Sqrl_User u, uint8_t length )
{
	SQRL_CAST_USER(user,u);
	if( user != NULL ) {
		user->options.hintLength = length;
		BIT_SET( user->flags, USER_FLAG_T1_CHANGED );
	}
}

/**
Sets \p Sqrl_User_Options for a \p Sqrl_User

@param u A \p Sqrl_User
@param seconds The number of seconds to run EnScrypt when encrypting the Identity
*/
DLL_PUBLIC
void sqrl_user_set_enscrypt_seconds( Sqrl_User u, uint8_t seconds )
{
	SQRL_CAST_USER(user,u);
	if( user != NULL ) {
		user->options.enscryptSeconds = seconds;
		BIT_SET( user->flags, USER_FLAG_T1_CHANGED );
	}
}

/**
Sets \p Sqrl_User_Options for a \p Sqrl_User

@param u A \p Sqrl_User
@param minutes Clear hint data after \p minutes
*/
DLL_PUBLIC
void sqrl_user_set_timeout_minutes( Sqrl_User u, uint16_t minutes )
{
	SQRL_CAST_USER(user,u);
	if( user != NULL ) {
		user->options.timeoutMinutes = minutes;
		BIT_SET( user->flags, USER_FLAG_T1_CHANGED );
	}
}

/**
Helper to check a user's options flags

@param u A \p Sqrl_User
@param flags The Option flags to check
@return uint16_t containing the user's option values for the flags selected.
*/
DLL_PUBLIC
uint16_t sqrl_user_check_flags( Sqrl_User u, uint16_t flags )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) {
		return 0;
	}
	return user->options.flags & flags;
}

/**
Helper to set a user's option flags

@param u A \p Sqrl_User
@param flags The Option flags to set
*/
DLL_PUBLIC
void sqrl_user_set_flags( Sqrl_User u, uint16_t flags )
{
	SQRL_CAST_USER(user,u);
	if( user != NULL ) {
		if( sqrl_user_check_flags(u,flags) == flags ) {
			// No change
			return;
		}
		user->options.flags |= flags;
		BIT_SET( user->flags, USER_FLAG_T1_CHANGED );
	}
}

/**
Helper to clear a user's option flags

@param u A \p Sqrl_User
@param flags The Option flags to clear
*/
DLL_PUBLIC
void sqrl_user_clear_flags( Sqrl_User u, uint16_t flags )
{
	SQRL_CAST_USER(user,u);
	if( user != NULL ) {
		if( sqrl_user_check_flags(u,flags) == 0 ) {
			// No change
			return;
		}
		user->options.flags &= ~flags;
		BIT_SET( user->flags, USER_FLAG_T1_CHANGED );
	}
}

/**
Populates a \p Sqrl_User_Options struct with the default options.

@param options Pointer to a \p Sqrl_User_Options struct
*/
DLL_PUBLIC
void sqrl_user_default_options( Sqrl_User_Options *options ) {
	options->flags = SQRL_DEFAULT_FLAGS;
	options->hintLength = SQRL_DEFAULT_HINT_LENGTH;
	options->enscryptSeconds = SQRL_DEFAULT_ENSCRYPT_SECONDS;
	options->timeoutMinutes = SQRL_DEFAULT_TIMEOUT_MINUTES;
}


/**
Gets a string of length \p SQRL_UNIQUE_ID_LENGTH uniquely identifying a user id.

@param storage A \p Sqrl_Storage object
@param uid Pointer to a \p char buffer of \p SQRL_UNIQUE_ID_LENGTH to hold the unique id
@return TRUE success
@return FALSE \p storage does not contain a type 2 block
*/
DLL_PUBLIC
bool sqrl_user_unique_id( Sqrl_Storage storage, char *uid ) {
	if( !storage ) return false;
	Sqrl_Block *block = calloc( sizeof(Sqrl_Block), 1);
	if( !sqrl_storage_block_get( storage, block, SQRL_BLOCK_RESCUE )) {
		free( block );
		return false;
	}
	UT_string *str;
	utstring_new( str );
	sqrl_b64u_encode( str, block->data + 25, 32 );
	memcpy( uid, utstring_body(str), SQRL_UNIQUE_ID_LENGTH);
	utstring_free( str );
	sqrl_block_free( block ); free( block );
	return true;
}
