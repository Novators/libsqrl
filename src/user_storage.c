/** @file user_storage.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/
#include <stdlib.h>
#include <stdio.h>
#include "sqrl_internal.h"

bool su_init_t2( 
	Sqrl_User u, 
	Sqrl_Crypt_Context *sctx, 
	Sqrl_Block *block,
	bool forSaving )
{
	SQRL_CAST_USER( user, u );
	sctx->plain_text = user->keys->scratch;
	if( forSaving ) {
		if( !sqrl_block_init( block, 2, 73 )) {
			return false;
		}
		sqrl_block_write_int16( block, 73 );
		sqrl_block_write_int16( block, 2 );
		sqrl_entropy_bytes( block->data + 4, 16 );
		sqrl_block_seek( block, 20 );
		sctx->nFactor = SQRL_DEFAULT_N_FACTOR;
		sqrl_block_write_int8( block, SQRL_DEFAULT_N_FACTOR );
		memcpy( sctx->plain_text, sqrl_user_key( u, KEY_IUK ), SQRL_KEY_SIZE );
		sctx->flags = SQRL_ENCRYPT | SQRL_MILLIS;
		sctx->count = SQRL_RESCUE_ENSCRYPT_SECONDS * SQRL_MILLIS_PER_SECOND;
	} else {
		sqrl_block_seek( block, 0 );
		if( 73 != sqrl_block_read_int16( block ) ||
				2 != sqrl_block_read_int16( block )) {
			return false;
		}
		sqrl_block_seek( block, 20 );
		sctx->nFactor = sqrl_block_read_int8( block );
		sctx->flags = SQRL_DECRYPT | SQRL_ITERATIONS;
	}
	sctx->add = block->data;
	sctx->add_len = 25;
	sctx->iv = NULL;
	sctx->salt = block->data + 4;
	sctx->text_len = SQRL_KEY_SIZE;
	sctx->cipher_text = block->data + sctx->add_len;
	sctx->tag = sctx->cipher_text + sctx->text_len;
	return true;
}

bool sul_block_2( Sqrl_User u, Sqrl_Block *block, struct sqrl_user_callback_data cbdata )
{
	SQRL_CAST_USER(user,u);
	bool retVal = false;
	Sqrl_Crypt_Context sctx;
	bool relock;
	if( ! sqrl_user_has_key( u, KEY_RESCUE_CODE )) {
		return false;
	}
	
	if( !su_init_t2( u, &sctx, block, false )) {
		goto ERROR;
	}

	uint8_t *key = user->keys->scratch + sctx.text_len;
	char *rc = (char*)sqrl_user_key( u, KEY_RESCUE_CODE );
	sqrl_block_seek( block, 21 );
	sctx.count = sqrl_block_read_int32( block );
	sctx.flags = SQRL_DECRYPT | SQRL_ITERATIONS;
	if( sqrl_crypt_enscrypt( 
			&sctx, 
			key, 
			rc, 
			SQRL_RESCUE_CODE_LENGTH, 
			sqrl_user_enscrypt_callback, 
			&cbdata ) > 0 ) {
		if( sqrl_crypt_gcm( &sctx, key )) {
			uint8_t *iuk = sqrl_user_new_key( u, KEY_IUK );
			memcpy( iuk, sctx.plain_text, SQRL_KEY_SIZE );
			retVal = true;
			goto DONE;
		}
	}

ERROR:
	retVal = false;

DONE:
	sodium_memzero( user->keys->scratch, sctx.text_len + SQRL_KEY_SIZE );
	return retVal;

}

bool sus_block_2( Sqrl_User u, Sqrl_Storage storage, Sqrl_Block *block, struct sqrl_user_callback_data cbdata )
{
	SQRL_CAST_USER(user,u);
	bool retVal = true;
	Sqrl_Crypt_Context sctx;
	bool relock;
	if( ! sqrl_user_has_key( u, KEY_IUK )
		|| ! sqrl_user_has_key( u, KEY_RESCUE_CODE )) {
		return false;
	}
	
	if( !su_init_t2( u, &sctx, block, true )) {
		goto ERROR;
	}

	uint8_t *key = user->keys->scratch + sctx.text_len;
	char *rc = (char*)sqrl_user_key( u, KEY_RESCUE_CODE );
	uint32_t iterations = sqrl_crypt_enscrypt( &sctx, key, rc, SQRL_RESCUE_CODE_LENGTH, sqrl_user_enscrypt_callback, &cbdata );
	sqrl_block_seek( block, 21 );
	sqrl_block_write_int32( block, sctx.count );

	// Cipher Text
	sctx.flags = SQRL_ENCRYPT | SQRL_ITERATIONS;
	uint8_t *iuk = sqrl_user_key( u, KEY_IUK );
	memcpy( sctx.plain_text, iuk, sctx.text_len );
	if( !sqrl_crypt_gcm( &sctx, key )) {
		goto ERROR;
	}
	// Save unique id
	UT_string *str;
	utstring_new( str );
	sqrl_b64u_encode( str, sctx.cipher_text, SQRL_KEY_SIZE );
	strcpy( user->unique_id, utstring_body(str));
	utstring_free( str );

	goto DONE;

ERROR:
	retVal = false;

DONE:
	sodium_memzero( user->keys->scratch, sctx.text_len + SQRL_KEY_SIZE );
	return retVal;
}

bool sul_block_3( Sqrl_User u, Sqrl_Block *block, struct sqrl_user_callback_data cbdata )
{
	SQRL_CAST_USER(user,u);
	bool retVal = true;
	int i;
	Sqrl_Crypt_Context sctx;
	uint8_t *keyPointer;
	block->cur = 0;
	sctx.add = block->data;
	sctx.add_len = 4;
	if( sqrl_block_read_int16( block ) != 148 ||
		sqrl_block_read_int16( block ) != 3 ) {
		return false;
	}
	sctx.text_len = SQRL_KEY_SIZE * 4;
	sctx.cipher_text = block->data + 4;
	sctx.tag = sctx.cipher_text + (SQRL_KEY_SIZE * 4);
	sctx.plain_text = user->keys->scratch;
	sctx.iv = sctx.plain_text + sctx.text_len;
	memset( sctx.iv, 0, 12 );
	keyPointer = sqrl_user_key( u, KEY_MK );
	sctx.flags = SQRL_DECRYPT | SQRL_ITERATIONS;
	if( !sqrl_crypt_gcm( &sctx, keyPointer )) {
		goto ERROR;
	}

	int pt_offset = 0;
	int piuks[] = { KEY_PIUK0, KEY_PIUK1, KEY_PIUK2, KEY_PIUK3 };
	for( i = 0; i < 4; i++ ) {
		keyPointer = sqrl_user_new_key( u, piuks[i] );
		memcpy( keyPointer, sctx.plain_text + pt_offset, SQRL_KEY_SIZE );
		pt_offset += SQRL_KEY_SIZE;
	}
	goto DONE;

ERROR:
	retVal = false;

DONE:
	sodium_memzero( user->keys->scratch, sctx.text_len );
	return retVal;

}

bool sus_block_3( Sqrl_User u, Sqrl_Block *block, struct sqrl_user_callback_data cbdata )
{
	SQRL_CAST_USER(user,u);
	bool retVal = true;
	int i;
	Sqrl_Crypt_Context sctx;
	uint8_t *keyPointer;
	sqrl_block_init( block, 3, 148 );
	sctx.add = block->data;
	sctx.add_len = 4;
	sqrl_block_write_int16( block, 148 );
	sqrl_block_write_int16( block, 3 );
	sctx.text_len = SQRL_KEY_SIZE * 4;
	sctx.cipher_text = block->data + 4;
	sctx.tag = sctx.cipher_text + (SQRL_KEY_SIZE * 4);
	sctx.plain_text = user->keys->scratch;

	int pt_offset = 0;
	int piuks[] = { KEY_PIUK0, KEY_PIUK1, KEY_PIUK2, KEY_PIUK3 };
	for( i = 0; i < 4; i++ ) {
		if( sqrl_user_has_key( u, piuks[i] )) {
			keyPointer = sqrl_user_key( u, piuks[i] );
			memcpy( sctx.plain_text + pt_offset, keyPointer, SQRL_KEY_SIZE );
		} else {
			memset( sctx.plain_text + pt_offset, 0, SQRL_KEY_SIZE );
		}
		pt_offset += SQRL_KEY_SIZE;
	}
	sctx.iv = sctx.plain_text + pt_offset;
	memset( sctx.iv, 0, 12 );
	keyPointer = sqrl_user_key( u, KEY_MK );
	sctx.count = 100;
	sctx.flags = SQRL_ENCRYPT | SQRL_MILLIS;
	if( !sqrl_crypt_gcm( &sctx, keyPointer )) {
		goto ERROR;
	}
	goto DONE;

ERROR:
	retVal = false;

DONE:
	sodium_memzero( user->keys->scratch, sctx.text_len );
	return retVal;
}

bool sul_block_1( Sqrl_User u, Sqrl_Block *block, struct sqrl_user_callback_data cbdata )
{
	WITH_USER(user,u);
	if( !user ) return false;
	bool retVal = true;
	Sqrl_Crypt_Context sctx;
	uint8_t *keyPointer;

	if( sqrl_block_read_int16( block ) != 125 ) {
		goto ERROR;
	}
	
	block->cur = 0;

	// ADD
	sctx.add = block->data;
	sqrl_block_seek( block, 4 );
	sctx.add_len = sqrl_block_read_int16( block );
	if( sctx.add_len != 45 ) {
		goto ERROR;
	}
	// IV and Salt
	sctx.iv = block->data + block->cur;
	block->cur += 12;
	sctx.salt = block->data + block->cur;
	block->cur += 16;
	// N Factor
	sctx.nFactor = sqrl_block_read_int8( block );
	// Iteration Count
	sctx.count = sqrl_block_read_int32( block );
	// Options
	user->options.flags = sqrl_block_read_int16( block );
	user->options.hintLength = sqrl_block_read_int8( block );
	user->options.enscryptSeconds = sqrl_block_read_int8( block );
	user->options.timeoutMinutes = sqrl_block_read_int16( block );
	// Cipher Text
	sctx.text_len = SQRL_KEY_SIZE * 2;
	sctx.cipher_text = block->data + block->cur;
	// Verification Tag
	sctx.tag = sctx.cipher_text + sctx.text_len;
	// Plain Text
	sctx.plain_text = user->keys->scratch;

	// Iteration Count
	uint8_t *key = sctx.plain_text + sctx.text_len;
	sctx.flags = SQRL_DECRYPT | SQRL_ITERATIONS;
	if( sqrl_crypt_enscrypt( 
			&sctx, 
			key, 
			user->keys->password, 
			user->keys->password_len,
			sqrl_user_enscrypt_callback, 
			&cbdata ) > 0 ) {
		if( sqrl_crypt_gcm( &sctx, key )) {
			key = sqrl_user_new_key( u, KEY_MK );
			memcpy( key, sctx.plain_text, SQRL_KEY_SIZE );
			key = sqrl_user_new_key( u, KEY_ILK );
			memcpy( key, sctx.plain_text + SQRL_KEY_SIZE, SQRL_KEY_SIZE );
			goto DONE;
		}
	}

ERROR:
	retVal = false;

DONE:
	sodium_memzero( user->keys->scratch, sctx.text_len + SQRL_KEY_SIZE );
	END_WITH_USER(user);
	return retVal;
}

bool sus_block_1( Sqrl_User u, Sqrl_Block *block, struct sqrl_user_callback_data cbdata )
{
	WITH_USER(user,u);
	if( !user ) return false;
	bool retVal = true;
	Sqrl_Crypt_Context sctx;
	if( !sqrl_client_require_password( cbdata.transaction )) {
		END_WITH_USER(user);
		return false;
	}
	uint8_t *keyPointer;
	sqrl_block_init( block, 1, 125 );
	// Block Length
	sqrl_block_write_int16( block, 125 );
	// Block Type
	sqrl_block_write_int16( block, 1 );
	// ADD
	sctx.add = block->data;
	sctx.add_len = 45;
	sqrl_block_write_int16( block, 45 );
	// IV and Salt
	sctx.iv = block->data + block->cur;
	sctx.salt = block->data + block->cur + 12;
	sqrl_entropy_bytes( block->data + block->cur, 28 );
	// N Factor
	block->cur += 16 + 12; // salt and iv length
	sctx.nFactor = SQRL_DEFAULT_N_FACTOR;
	sqrl_block_write_int8( block, SQRL_DEFAULT_N_FACTOR );
	// Options
	sqrl_block_seek( block, 39 );
	sqrl_block_write_int16( block, user->options.flags );
	sqrl_block_write_int8( block, user->options.hintLength );
	sqrl_block_write_int8( block, user->options.enscryptSeconds );
	sqrl_block_write_int16( block, user->options.timeoutMinutes );
	// Cipher Text
	sctx.text_len = SQRL_KEY_SIZE * 2;
	sctx.cipher_text = block->data + block->cur;
	// Verification Tag
	sctx.tag = block->data + block->cur + sctx.text_len;
	// Plain Text
	sctx.plain_text = user->keys->scratch;
	if( sqrl_user_has_key( (Sqrl_User)user, KEY_MK )) {
		keyPointer = sqrl_user_key( (Sqrl_User)user, KEY_MK );
		memcpy( sctx.plain_text, keyPointer, SQRL_KEY_SIZE );
	} else {
		memset( sctx.plain_text, 0, SQRL_KEY_SIZE );
	}
	if( sqrl_user_has_key( (Sqrl_User)user, KEY_ILK )) {
		keyPointer = sqrl_user_key( (Sqrl_User)user, KEY_ILK );
		memcpy( sctx.plain_text + SQRL_KEY_SIZE, keyPointer, SQRL_KEY_SIZE );
	} else {
		memset( sctx.plain_text + SQRL_KEY_SIZE, 0, SQRL_KEY_SIZE );
	}

	// Iteration Count
	uint8_t *key = sctx.plain_text + sctx.text_len;
	sctx.flags = SQRL_ENCRYPT | SQRL_MILLIS;
	sctx.count = user->options.enscryptSeconds * SQRL_MILLIS_PER_SECOND;
	uint32_t iterations = sqrl_crypt_enscrypt( &sctx, key, user->keys->password, user->keys->password_len, sqrl_user_enscrypt_callback, &cbdata );
	sqrl_block_seek( block, 35 );
	sqrl_block_write_int32( block, sctx.count );

	// Cipher Text
	sctx.flags = SQRL_ENCRYPT | SQRL_ITERATIONS;
	if( !sqrl_crypt_gcm( &sctx, key )) {
		goto ERROR;
	}
	goto DONE;

ERROR:
	retVal = false;

DONE:
	sodium_memzero( user->keys->scratch, sctx.text_len + SQRL_KEY_SIZE );
	END_WITH_USER(user);
	return retVal;
}

bool sqrl_user_update_storage( Sqrl_User u ) 
{
	WITH_USER(user,u);
	if( !user ) return false;
	if( user->storage == NULL ) {
		user->storage = sqrl_storage_create();
	}

	struct sqrl_user_callback_data cbdata;
	Sqrl_Block block;
	sqrl_block_clear( &block );
	Sqrl_Crypt_Context sctx;
	bool retVal = true;

	Sqrl_Client_Transaction transaction;
	transaction.type = SQRL_TRANSACTION_IDENTITY_SAVE;
	transaction.user = u;
	cbdata.transaction = &transaction;
	cbdata.adder = 0;
	cbdata.divisor = 1;

	if( (user->flags & USER_FLAG_T1_CHANGED) == USER_FLAG_T1_CHANGED ||
		! sqrl_storage_block_exists( user->storage, SQRL_BLOCK_USER )) 
	{
		if( sus_block_1( u, &block, cbdata )) {
			sqrl_storage_block_put( user->storage, &block );
		}
		sqrl_block_free( &block );
	}

	if( (user->flags & USER_FLAG_T2_CHANGED) == USER_FLAG_T2_CHANGED ||
		! sqrl_storage_block_exists( user->storage, SQRL_BLOCK_RESCUE ))
	{
		if( sus_block_2( u, user->storage, &block, cbdata )) {
			sqrl_storage_block_put( user->storage, &block );
		}
		sqrl_block_free( &block );
	}

	if( (user->flags & USER_FLAG_T2_CHANGED) == USER_FLAG_T2_CHANGED ||
		! sqrl_storage_block_exists( user->storage, SQRL_BLOCK_PREVIOUS ))
	{
		if( sus_block_3( u, &block, cbdata )) {
			sqrl_storage_block_put( user->storage, &block );
		}
		sqrl_block_free( &block );
	}

DONE:
	END_WITH_USER(user);
	return retVal;
}

static void _suc_load_unique_id( struct Sqrl_User *user )
{
	if( !user ) return;
	sqrl_storage_unique_id( user->storage, user->unique_id );
}

Sqrl_User sqrl_user_create_from_file( const char *filename )
{
	Sqrl_User u = NULL;
	Sqrl_Storage storage = sqrl_storage_create();
	if( !sqrl_storage_load_from_file( storage, filename )) {
		goto ERROR;
	}
	u = sqrl_user_create();
	WITH_USER(user,u);
	if( user == NULL ) {
		goto ERROR;
	}
	user->filename = malloc( strlen( filename ) + 1 );
	if( !user->filename ) {
		END_WITH_USER(user);
		goto ERROR;
	}
	strcpy( user->filename, filename );
	user->storage = storage;
	_suc_load_unique_id( user );
	END_WITH_USER(user);
	return u;

ERROR:
	if( user ) {
		END_WITH_USER(user);
		sqrl_user_release(u);
	}
	if( storage ) {
		sqrl_storage_destroy(storage);
	}
	return NULL;
}

Sqrl_User sqrl_user_create_from_buffer( const char *buffer, size_t buffer_len )
{
	Sqrl_User u = NULL;
	Sqrl_Storage storage = sqrl_storage_create();
	UT_string *buf;
	utstring_new( buf );
	utstring_printf( buf, buffer, buffer_len );
	if( sqrl_storage_load_from_buffer( storage, buf )) {
		u = sqrl_user_create();
		WITH_USER(user,u);
		user->storage = storage;
		_suc_load_unique_id( user );
		END_WITH_USER(user);
	} else {
		storage = sqrl_storage_destroy( storage );
	}
	return u;
}

bool sqrl_user_save( Sqrl_User u, const char *filename, Sqrl_Export exportType, Sqrl_Encoding encoding )
{
	if( filename == NULL ) return false;
	WITH_USER(user,u);
	if( user == NULL ) return false;
	if( sqrl_user_update_storage( u )) {
		if( sqrl_storage_save_to_file( user->storage, filename, exportType, encoding ) > 0 ) {
			END_WITH_USER(user);
			return true;
		}
	}
	END_WITH_USER(user);
	return false;
}

char *sqrl_user_save_to_buffer( Sqrl_User u, size_t *buffer_len, Sqrl_Export exportType, Sqrl_Encoding encoding )
{
	WITH_USER(user,u);
	if( !user ) return NULL;
	char *retVal = NULL;
	UT_string *buf;
	utstring_new( buf );
	Sqrl_Client_Transaction transaction;
	transaction.type = SQRL_TRANSACTION_IDENTITY_SAVE;
	transaction.user = u;
	struct sqrl_user_callback_data cbdata;
	cbdata.transaction = &transaction;
	cbdata.adder = 0;
	cbdata.divisor = 1;

	if( sqrl_user_update_storage( u )) {
		if( sqrl_storage_save_to_buffer( user->storage, buf, exportType, encoding )) {
			retVal = malloc( utstring_len(buf) + 1 );
			if( !retVal ) goto ERROR;
			memcpy( retVal, utstring_body(buf), utstring_len(buf));
			retVal[utstring_len(buf)] = 0x00;
			if( buffer_len ) {
				*buffer_len = utstring_len(buf);
			}
			goto DONE;
		}
	}

ERROR:
	if( retVal ) {
		free( retVal );
		retVal = NULL;
	}

DONE:
	if( buf ) {
		utstring_free(buf);
	}
	END_WITH_USER(user);
	return retVal;
}

bool sqrl_user_try_load_password( Sqrl_User u, bool retry )
{
	WITH_USER(user,u);
	if( !user ) return false;
	bool retVal = false;
	Sqrl_Block block;
	Sqrl_Client_Transaction transaction;
	transaction.type = SQRL_TRANSACTION_IDENTITY_LOAD;
	transaction.user = u;
	struct sqrl_user_callback_data cbdata;
	cbdata.transaction = &transaction;
	cbdata.adder = 0;
	cbdata.divisor = 1;
LOOP:
	if( !sqrl_storage_block_exists( user->storage, SQRL_BLOCK_USER )) {
		retVal = sqrl_user_try_load_rescue( u, retry );
		goto DONE;
	}
	if( user->keys->password_len == 0 ) {
		goto NEEDAUTH;
	}

	memset( &block, 0, sizeof( Sqrl_Block ));
	sqrl_storage_block_get( user->storage, &block, SQRL_BLOCK_USER );
	if( ! sul_block_1( u, &block, cbdata )) {
		sqrl_block_free( &block );
		goto NEEDAUTH;
	}
	sqrl_block_free( &block );
	//sqrl_user_regen_keys( u );
	if( sqrl_storage_block_exists( user->storage, SQRL_BLOCK_PREVIOUS ) &&
		sqrl_storage_block_get( user->storage, &block, SQRL_BLOCK_PREVIOUS ))
	{
		sul_block_3( u, &block, cbdata );
		sqrl_block_free( &block );
	}
	retVal = true;
	goto DONE;

NEEDAUTH:
	if( retry ) {
		retry = false;
		sqrl_client_call_authentication_required( &transaction, SQRL_CREDENTIAL_PASSWORD );
		goto LOOP;
	}

DONE:
	END_WITH_USER(user);
	return retVal;
}

bool sqrl_user_try_load_rescue( Sqrl_User u, bool retry )
{
	WITH_USER(user,u);
	if( !user ) return false;
	bool retVal = false;
	Sqrl_Client_Transaction transaction;
	transaction.type = SQRL_TRANSACTION_IDENTITY_RESCUE;
	transaction.user = u;
	struct sqrl_user_callback_data cbdata;
	cbdata.transaction = &transaction;
	cbdata.adder = 0;
	cbdata.divisor = 1;

LOOP:
	if( !sqrl_storage_block_exists( user->storage, SQRL_BLOCK_RESCUE )) {
		goto DONE;
	}
	if( !sqrl_user_has_key( u, KEY_RESCUE_CODE ) ) {
		goto NEEDAUTH;
	}

	Sqrl_Block block;
	memset( &block, 0, sizeof( Sqrl_Block ));
	sqrl_storage_block_get( user->storage, &block, SQRL_BLOCK_RESCUE );
	if( ! sul_block_2( u, &block, cbdata )) {
		sqrl_block_free( &block );
		goto NEEDAUTH;
	}
	sqrl_block_free( &block );
	sqrl_user_regen_keys( u );
	if( sqrl_storage_block_exists( user->storage, SQRL_BLOCK_PREVIOUS ) &&
		sqrl_storage_block_get( user->storage, &block, SQRL_BLOCK_PREVIOUS ))
	{
		sul_block_3( u, &block, cbdata );
		sqrl_block_free( &block );
	}
	goto DONE;

NEEDAUTH:
	if( retry ) {
		retry = false;
		sqrl_client_call_authentication_required( &transaction, SQRL_CREDENTIAL_RESCUE_CODE );
		goto LOOP;
	}

DONE:
	END_WITH_USER(user);
	return retVal;
}


