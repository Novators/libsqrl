/** @file user.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/
#include <stdlib.h>
#include <stdio.h>
#include "sqrl_internal.h"

struct Sqrl_User_List *SQRL_USER_LIST;

int sqrl_user_enscrypt_callback( int percent, void *data )
{
	struct sqrl_user_callback_data *cbdata = (struct sqrl_user_callback_data*)data;
	if( cbdata ) {
		int progress = cbdata->adder + (percent * cbdata->multiplier);
		if( progress > 100 ) progress = 100;
		if( progress < 0 ) progress = 0;
		if( percent == 100 && progress >= 99 ) progress = 100;
		return sqrl_client_call_progress( cbdata->transaction, progress );
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
		memset( user->keys, 0, sizeof( struct Sqrl_Keys ));
		BIT_UNSET( user->flags, USER_FLAG_MEMLOCKED );
	}
}

#if defined(DEBUG) && DEBUG_PRINT_REFERENCE_COUNT==1
#define PRINT_USER_COUNT(tag) \
int _pucI = 0;\
struct Sqrl_User_List *_pucC = SQRL_USER_LIST;\
while( _pucC ) {\
	_pucI++;\
	_pucC = _pucC->next;\
}\
printf( "%s: %d Users\n", tag, _pucI )
#else
#define PRINT_USER_COUNT(tag)
#endif

/**
Finds a previously allocated \p Sqrl_User.  Be sure to release your reference
with \p sqrl_user_release when you are finished with the \p Sqrl_User.

@param unique_id A string of length \p SQRL_UNIQUE_ID_LENGTH identifying the \p Sqrl_User.
@return Sqrl_User A \p Sqrl_User object, or NULL if not available.
*/
DLL_PUBLIC
Sqrl_User sqrl_user_find( const char *unique_id )
{
	Sqrl_User user = NULL;
	struct Sqrl_User_List *l;
	sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.user );
	l = SQRL_USER_LIST;
	while( l ) {
		if( l->user && sqrl_user_unique_id_match( l->user, unique_id )) {
			user = l->user;
			sqrl_user_hold( user );
			break;
		}
		l = l->next;
	}
	sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.user );
	return user;
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
	user->referenceCount = 1;
	user->referenceCountMutex = sqrl_mutex_create();
	struct Sqrl_User_List *l = calloc( 1, sizeof( struct Sqrl_User_List ));
	l->user = user;
	sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.user );

	struct Sqrl_User_List *list = SQRL_USER_LIST;
	if( list == NULL ) {
		SQRL_USER_LIST = l;
	} else {
		while( 1 ) {
			if( list->next == NULL ) {
				list->next = l;
				break;
			}
			list = list->next;
		}
	}
	PRINT_USER_COUNT("sqrl_user_create");
	sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.user );
	return (Sqrl_User)user;
}

/** 
Holds a \p Sqrl_User in memory.
*/
DLL_PUBLIC
bool sqrl_user_hold( Sqrl_User u )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return false;
	sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.user );
	// Make sure the user is still in active memory...
	struct Sqrl_User_List *c = SQRL_USER_LIST;
	while( c ) {
		if( c->user == user ) {
			break;
		}
		c = c->next;
	}
	if( !c ) {
		sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.user );
		return false;
	}
	sqrl_mutex_enter( user->referenceCountMutex );
	user->referenceCount++;
	sqrl_mutex_leave( user->referenceCountMutex );
	sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.user );
	return true;
}

/**
Securely erases and frees memory of a \p Sqrl_User

@param u A \p Sqrl_User
@return NULL
*/
DLL_PUBLIC
Sqrl_User sqrl_user_release( Sqrl_User u )
{
	SQRL_CAST_USER(user,u);
	if( user == NULL ) return NULL;

	sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.user );
	struct Sqrl_User_List *list = SQRL_USER_LIST;
	if( list == NULL ) {
		sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.user );
		return NULL;
	}
	struct Sqrl_User_List *prev;
	if( list->user == user ) {
		prev = NULL;
	} else {
		prev = list;
		list = NULL;
		while( prev ) {
			if( prev->next && prev->next->user == user ) {
				list = prev->next;
				break;
			}
			prev = prev->next;
		}
	}
	if( list == NULL ) {
		sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.user );
		return NULL;
	}
	sqrl_mutex_enter( user->referenceCountMutex );
	user->referenceCount--;
	if( user->referenceCount > 0 ) {
		sqrl_mutex_leave( user->referenceCountMutex );
		sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.user );
		return NULL;
	}
	if( user->keys != NULL ) {
		sodium_mprotect_readwrite( user->keys );
		sodium_free( user->keys );
	}
	sqrl_mutex_destroy( user->referenceCountMutex );
	sodium_memzero( user, sizeof( Sqrl_User ));

	if( prev == NULL ) {
		SQRL_USER_LIST = list->next;
	} else {
		prev->next = list->next;
	}
	free( list );
	PRINT_USER_COUNT( "sqrl_user_release" );
	sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.user );
	free( user );
	return NULL;
}

/**
Gets a \p Sqrl_User from memory.

\warning \p sqrl_user_release the \p Sqrl_User when finished!

@param unique_id A unique id to match
@return Sqrl_User the matched user, or NULL if not found
*/
DLL_PUBLIC
Sqrl_User sqrl_get_user( const char *unique_id )
{
	Sqrl_User retVal = NULL;
	sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.user );
	struct Sqrl_User_List *list = SQRL_USER_LIST;
	while( list ) {
		if( sqrl_user_unique_id_match( list->user, unique_id )) {
			retVal = list->user;
			break;
		}
	}
	sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.user );
	if( sqrl_user_hold( retVal )) {
		return retVal;
	}
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
void sqrl_user_hintlock( Sqrl_User u )
{
	if( sqrl_user_is_hintlocked( u )) return;
	WITH_USER(user,u);
	if( user == NULL ) return;
	if( user->keys->password_len == 0 ) {
		END_WITH_USER(user);
		return;
	}
	Sqrl_Client_Transaction transaction;
	transaction.type = SQRL_TRANSACTION_IDENTITY_LOCK;
	transaction.user = u;
	struct sqrl_user_callback_data cbdata;
	cbdata.transaction = &transaction;
	cbdata.adder = 0;
	cbdata.multiplier = 1;

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
		goto DONE;
	}

	sodium_memzero( sctx.plain_text, sctx.text_len );
	sodium_memzero( key, SQRL_KEY_SIZE );

DONE:
	END_WITH_USER(user);
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
void sqrl_user_hintunlock( Sqrl_Client_Transaction *transaction, 
				char *hint, 
				size_t length )
{
	if( !transaction ) return;
	Sqrl_User u = transaction->user;
	if( !u ) return;
	if( !sqrl_user_is_hintlocked( u )) return;
	if( hint == NULL || length == 0 ) {
		sqrl_client_require_hint( transaction );
		return;
	}
	WITH_USER(user,u);
	if( user == NULL ) return;

	struct sqrl_user_callback_data cbdata;
	cbdata.transaction = transaction;
	cbdata.adder = 0;
	cbdata.multiplier = 1;

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
	}
	user->hint_iterations = 0;
	sodium_memzero( key, SQRL_KEY_SIZE );
	sodium_memzero( user->keys->scratch, KEY_SCRATCH_SIZE );

DONE:
	END_WITH_USER(user);
}

bool _su_keygen( Sqrl_User u, int key_type, uint8_t *key )
{
	WITH_USER(user,u);
	if( !user ) return false;
	bool retVal = false;
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
		retVal = true;
		break;
	case KEY_MK:
		if( sqrl_user_has_key( u, KEY_IUK )) {
			temp[0] = sqrl_user_key( u, KEY_IUK );
			if( temp[0] ) {
				sqrl_gen_mk( key, temp[0] );
				retVal = true;
			}
		}
		break;
	case KEY_ILK:
		temp[0] = sqrl_user_key( u, KEY_IUK );
		if( temp[0] ) {
			sqrl_gen_ilk( key, temp[0] );
			retVal = true;
		}
		break;
	case KEY_LOCAL:
		temp[0] = sqrl_user_key( u, KEY_MK );
		if( temp[0] ) {
			sqrl_gen_local( key, temp[0] );
			retVal = true;
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
			retVal = true;
		}
		break;
	}
	END_WITH_USER(user);
	return retVal;
}

bool sqrl_user_regen_keys( Sqrl_User u )
{
	WITH_USER(user,u);
	if( user == NULL ) return false;
	uint8_t *key;
	int keys[] = { KEY_MK, KEY_ILK, KEY_LOCAL };
	int i;
	for( i = 0; i < 3; i++ ) {
		key = sqrl_user_new_key( u, keys[i] );
		_su_keygen( u, keys[i], key );
	}
	END_WITH_USER(user);
	return true;
}

bool sqrl_user_rekey( Sqrl_User u )
{
	bool retVal = true;
	WITH_USER(user,u);
	if( user == NULL ) return false;
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
	user->flags |= (USER_FLAG_T1_CHANGED | USER_FLAG_T2_CHANGED);
	goto DONE;

ERROR:
	retVal = false;

DONE:
	END_WITH_USER(user);
	return retVal;
}

uint8_t *sqrl_user_new_key( Sqrl_User u, int key_type )
{
	WITH_USER(user,u);
	if( user == NULL ) return NULL;
	int offset = -1;
	int empty = -1;
	int i = 0;
	for( i = 0; i < USER_MAX_KEYS; i++ ) {
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
		END_WITH_USER(user);
		return key;
	}
	END_WITH_USER(user);
	return NULL;
}

uint8_t *sqrl_user_key( Sqrl_User u, int key_type )
{
	WITH_USER(user,u);
	if( user == NULL ) return NULL;
	int offset, empty, i;
	int loop = -1;
	uint8_t *key;
LOOP:
	loop++;
	if( loop == 3 ) {
		goto DONE;
	}
	offset = -1;
	empty = -1;
	for( i = 0; i < USER_MAX_KEYS; i++ ) {
		if( user->lookup[i] == key_type ) {
			offset = i;
			break;
		}
		if( user->lookup[i] == 0 ) {
			empty = i;
		}
	}
	if( offset > -1 ) {
		key = user->keys->keys[offset];
		END_WITH_USER(user);
		return key;
	} else {
		// Not Found!
		switch( key_type ) {
		case KEY_RESCUE_CODE:
			// We cannot regenerate this key!
			END_WITH_USER(user);
			return NULL;
		case KEY_IUK:
			sqrl_user_try_load_rescue( u, true );
			goto LOOP;
			break;
		case KEY_MK:
		case KEY_ILK:
		case KEY_PIUK0:
		case KEY_PIUK1:
		case KEY_PIUK2:
		case KEY_PIUK3:
			sqrl_user_try_load_password( u, true );
			goto LOOP;
			break;
		}
	}

DONE:
	END_WITH_USER(user);
	return NULL;
}

bool sqrl_user_has_key( Sqrl_User u, int key_type )
{
	WITH_USER(user,u);
	if( user == NULL ) return false;
	int i;
	for( i = 0; i < USER_MAX_KEYS; i++ ) {
		if( user->lookup[i] == key_type ) {
			END_WITH_USER(user);
			return true;
		}
	}
	END_WITH_USER(user);
	return false;
}

void sqrl_user_remove_key( Sqrl_User u, int key_type )
{
	WITH_USER(user,u);
	if( user == NULL ) return;
	int offset = -1;
	int i;
	for( i = 0; i < USER_MAX_KEYS; i++ ) {
		if( user->lookup[i] == key_type ) {
			offset = i;
		}
	}
	if( offset > -1 ) {
		sodium_memzero( user->keys->keys[offset], SQRL_KEY_SIZE );
		user->lookup[offset] = 0;
	}
	END_WITH_USER(user);
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
	WITH_USER(user,u);
	if( user == NULL ) return false;
	if( strlen( rc ) != 24 ) return false;
	int i;
	for( i = 0; i < SQRL_RESCUE_CODE_LENGTH; i++ ) {
		if( rc[i] < '0' || rc[i] > '9' ) {
			return false;
		}
	}
	uint8_t *key = sqrl_user_new_key( u, KEY_RESCUE_CODE );
	memcpy( key, rc, SQRL_RESCUE_CODE_LENGTH );
	END_WITH_USER(user);
	return true;
}

bool sqrl_user_force_decrypt( Sqrl_User u )
{
	if( sqrl_user_key( u, KEY_MK )) {
		return true;
	}
	return false;
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
	if( sqrl_user_is_hintlocked( u )) return false;
	WITH_USER(user,u);
	if( user == NULL ) return false;
	char *p = user->keys->password;
	size_t *l = &user->keys->password_len;
	if( !p || !l ) {
		END_WITH_USER(user);
		return false;
	}
	sodium_memzero( p, KEY_PASSWORD_MAX_LEN );
	if( password_len > KEY_PASSWORD_MAX_LEN ) password_len = KEY_PASSWORD_MAX_LEN;
	memcpy( p, password, password_len );
	if( *l > 0 ) {
		// 	Changing password
		BIT_SET(user->flags, USER_FLAG_T1_CHANGED);
	}
	*l = password_len;
	END_WITH_USER(user);
	return true;
}

uint8_t *sqrl_user_scratch( Sqrl_User u )
{
	uint8_t *retVal = NULL;
	WITH_USER(user,u);
	if( user == NULL ) return NULL;
	retVal = user->keys->scratch;
	END_WITH_USER(user);
	return retVal;
}

/**
Gets \p Sqrl_User_Options for a \p Sqrl_User

@param u A \p Sqrl_User
@return Number of characters to use as a password hint
*/
DLL_PUBLIC
uint8_t sqrl_user_get_hint_length( Sqrl_User u )
{
	uint8_t retVal = 0;
	WITH_USER(user,u);
	if( user == NULL ) return 0;
	retVal = user->options.hintLength;
	END_WITH_USER(user);
	return retVal;
}

/**
Gets \p Sqrl_User_Options for a \p Sqrl_User

@param u A \p Sqrl_User
@return Seconds to run EnScrypt when encrypting the identity
*/
DLL_PUBLIC
uint8_t sqrl_user_get_enscrypt_seconds( Sqrl_User u )
{
	uint8_t retVal = 0;
	WITH_USER(user,u);
	if( user == NULL ) return 0;
	retVal = user->options.enscryptSeconds;
	END_WITH_USER(user);
	return retVal;
}

/**
Gets \p Sqrl_User_Options for a \p Sqrl_User

@param u A \p Sqrl_User
@return Minutes to retain hint data when computer is idle
*/
DLL_PUBLIC
uint16_t sqrl_user_get_timeout_minutes( Sqrl_User u )
{
	uint16_t retVal = 0;
	WITH_USER(user,u);
	if( user == NULL ) return 0;
	retVal = user->options.timeoutMinutes;
	END_WITH_USER(user);
	return retVal;
}

/**
Sets \p Sqrl_User_Options for a \p Sqrl_User

@param u A \p Sqrl_User
@param length The number of characters to use as a password hint
*/
DLL_PUBLIC
void sqrl_user_set_hint_length( Sqrl_User u, uint8_t length )
{
	WITH_USER(user,u);
	if( user == NULL ) return;
	user->options.hintLength = length;
	BIT_SET( user->flags, USER_FLAG_T1_CHANGED );
	END_WITH_USER(user);
}

/**
Sets \p Sqrl_User_Options for a \p Sqrl_User

@param u A \p Sqrl_User
@param seconds The number of seconds to run EnScrypt when encrypting the Identity
*/
DLL_PUBLIC
void sqrl_user_set_enscrypt_seconds( Sqrl_User u, uint8_t seconds )
{
	WITH_USER(user,u);
	if( user == NULL ) return;
	user->options.enscryptSeconds = seconds;
	BIT_SET( user->flags, USER_FLAG_T1_CHANGED );
	END_WITH_USER(user);
}

/**
Sets \p Sqrl_User_Options for a \p Sqrl_User

@param u A \p Sqrl_User
@param minutes Clear hint data after \p minutes
*/
DLL_PUBLIC
void sqrl_user_set_timeout_minutes( Sqrl_User u, uint16_t minutes )
{
	WITH_USER(user,u);
	if( user == NULL ) return;
	user->options.timeoutMinutes = minutes;
	BIT_SET( user->flags, USER_FLAG_T1_CHANGED );
	END_WITH_USER(user);
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
	uint16_t retVal = 0;
	WITH_USER(user,u);
	if( user == NULL ) return 0;
	retVal = user->options.flags & flags;
	END_WITH_USER(user);
	return retVal;
}

/**
Helper to set a user's option flags

@param u A \p Sqrl_User
@param flags The Option flags to set
*/
DLL_PUBLIC
void sqrl_user_set_flags( Sqrl_User u, uint16_t flags )
{
	WITH_USER(user,u);
	if( user == NULL ) return;
	if( (user->options.flags & flags) != flags ) {
		user->options.flags |= flags;
		BIT_SET( user->flags, USER_FLAG_T1_CHANGED );
	}
	END_WITH_USER(user);
}

/**
Helper to clear a user's option flags

@param u A \p Sqrl_User
@param flags The Option flags to clear
*/
DLL_PUBLIC
void sqrl_user_clear_flags( Sqrl_User u, uint16_t flags )
{
	WITH_USER(user,u);
	if( user == NULL ) return;
	if( (user->flags & flags) != 0 ) {
		user->options.flags &= ~flags;
		BIT_SET( user->flags, USER_FLAG_T1_CHANGED );
	}
	END_WITH_USER(user);
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
Retrieves a unique identifier for a \p Sqrl_User.  The unique identifier is
simply an encoded version of the encrypted IUK (from the Rescue Code Block).
Note that the ID will change when a user rekeys.  If a type 2 block is not
available, \p buffer will be an empty string.

@param u A \p Sqrl_User
@param buffer An allocated block of at length (\p SQRL_UNIQUE_ID_LENGTH + 1)
or more to receive the unique id
@return bool true on success, false on invalid parameters
*/
DLL_PUBLIC
bool sqrl_user_unique_id( Sqrl_User u, char *buffer )
{
	if( !buffer ) return false;
	WITH_USER(user,u);
	if( user == NULL ) return false;
	strncpy( buffer, user->unique_id, SQRL_UNIQUE_ID_LENGTH );
	END_WITH_USER(user);
	return true;
}

/**
Compares a \p Sqrl_User's unique identifier to the provided string

@param u A \p Sqrl_User
@param unique_id a NULL-terminated string to compare
@return bool true if identifiers match
*/
DLL_PUBLIC
bool sqrl_user_unique_id_match( Sqrl_User u, const char *unique_id )
{
	bool retVal = false;
	WITH_USER(user,u);
	if( user == NULL ) return false;
	if( unique_id == NULL ) {
		if( user->unique_id[0] == 0 ) {
			retVal = true;
		}
	} else {
		if( 0 == strcmp( unique_id, user->unique_id )) {
			retVal = true;
		}
	}
	END_WITH_USER(user);
	return retVal;
}

