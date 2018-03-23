/** @file user_storage.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/
#include <stdlib.h>
#include <stdio.h>
#include "sqrl_internal.h"

bool su_init_t2( 
	struct Sqrl_Transaction *transaction, 
	Sqrl_Crypt_Context *sctx, 
	Sqrl_Block *block,
	bool forSaving )
{
	SQRL_CAST_USER( user, transaction->user );
	sctx->plain_text = user->keys->scratch;
    sctx->text_len = SQRL_KEY_SIZE;
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
		memcpy( sctx->plain_text, sqrl_user_key( (Sqrl_Transaction)transaction, KEY_IUK ), SQRL_KEY_SIZE );
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
	sctx->cipher_text = block->data + sctx->add_len;
	sctx->tag = sctx->cipher_text + sctx->text_len;
	return true;
}

bool sul_block_2( struct Sqrl_Transaction *transaction, Sqrl_Block *block, struct sqrl_user_callback_data cbdata )
{
	SQRL_CAST_USER(user,transaction->user);
	bool retVal = false;
	Sqrl_Crypt_Context sctx;
	if( ! sqrl_user_has_key( transaction->user, KEY_RESCUE_CODE )) {
		return false;
	}
	
	if( !su_init_t2( transaction, &sctx, block, false )) {
		goto ERROR;
	}

	uint8_t *key = user->keys->scratch + sctx.text_len;
	char *rc = (char*)sqrl_user_key( transaction, KEY_RESCUE_CODE );
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
			uint8_t *iuk = sqrl_user_new_key( transaction->user, KEY_IUK );
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

bool sus_block_2( struct Sqrl_Transaction *transaction, Sqrl_Storage storage, Sqrl_Block *block, struct sqrl_user_callback_data cbdata )
{
	SQRL_CAST_USER(user,transaction->user);
	bool retVal = true;
	Sqrl_Crypt_Context sctx;
	if( ! sqrl_user_has_key( transaction->user, KEY_IUK )
		|| ! sqrl_user_has_key( transaction->user, KEY_RESCUE_CODE )) {
		return false;
	}
	
	if( !su_init_t2( transaction, &sctx, block, true )) {
		goto ERROR;
	}

	uint8_t *key = user->keys->scratch + sctx.text_len;
	char *rc = (char*)sqrl_user_key( transaction, KEY_RESCUE_CODE );
	sqrl_crypt_enscrypt( &sctx, key, rc, SQRL_RESCUE_CODE_LENGTH, sqrl_user_enscrypt_callback, &cbdata );
	sqrl_block_seek( block, 21 );
	sqrl_block_write_int32( block, sctx.count );

	// Cipher Text
	sctx.flags = SQRL_ENCRYPT | SQRL_ITERATIONS;
	uint8_t *iuk = sqrl_user_key( transaction, KEY_IUK );
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

bool sul_block_3( struct Sqrl_Transaction *transaction, Sqrl_Block *block, struct sqrl_user_callback_data cbdata )
{
	SQRL_CAST_USER(user,transaction->user);
	bool retVal = true;
	int i;
	size_t num_keys;
	Sqrl_Crypt_Context sctx;
	uint8_t *keyPointer;
	block->cur = 0;
	sctx.add = block->data;
	sctx.add_len = 6;
	num_keys = sqrl_block_read_int16( block ) - 22;
	i = num_keys % 32;
	num_keys /= 32;
	if( i != 0 || num_keys > 4 || num_keys < 1 || 
		sqrl_block_read_int16( block ) != 3 ) {
			return false;
	}
	sctx.text_len = SQRL_KEY_SIZE * num_keys;
	sctx.cipher_text = block->data + 6;
	sctx.tag = sctx.cipher_text + sctx.text_len;
	sctx.plain_text = user->keys->scratch;
	sctx.iv = sctx.plain_text + sctx.text_len;
	memset( sctx.iv, 0, 12 );
	keyPointer = sqrl_user_key( transaction, KEY_MK );
	sctx.flags = SQRL_DECRYPT | SQRL_ITERATIONS;
	if( !sqrl_crypt_gcm( &sctx, keyPointer )) {
		goto ERROR;
	}

	user->edition = sqrl_block_read_int16( block );
	
	int pt_offset = 0;
	int piuks[] = { KEY_PIUK0, KEY_PIUK1, KEY_PIUK2, KEY_PIUK3 };
	for( i = 0; i < num_keys; i++ ) {
		keyPointer = sqrl_user_new_key( transaction->user, piuks[i] );
		if( i < num_keys ) {
			memcpy( keyPointer, sctx.plain_text + pt_offset, SQRL_KEY_SIZE );
			pt_offset += SQRL_KEY_SIZE;
		}
	}
	goto DONE;

ERROR:
	retVal = false;

DONE:
	sodium_memzero( user->keys->scratch, sctx.text_len );
	return retVal;

}

bool sus_block_3( struct Sqrl_Transaction *transaction, Sqrl_Block *block, struct sqrl_user_callback_data cbdata )
{
	SQRL_CAST_USER(user,transaction->user);
	if( user->edition == 0 ) return false;
	bool retVal = true;
	int i;
	size_t block_size, num_keys;
	Sqrl_Crypt_Context sctx;
	uint8_t *keyPointer;
	num_keys = user->edition;
	if( num_keys > 4 ) num_keys = 4;
	block_size = 22 + ( SQRL_KEY_SIZE * num_keys );
	
	sqrl_block_init( block, 3, block_size );
	sctx.add = block->data;
	sctx.add_len = 6;
	sqrl_block_write_int16( block, block_size );
	sqrl_block_write_int16( block, 3 );
	sqrl_block_write_int16( block, user->edition );
	
	sctx.text_len = SQRL_KEY_SIZE * num_keys;
	sctx.cipher_text = block->data + 6;
	sctx.tag = sctx.cipher_text + (SQRL_KEY_SIZE * num_keys);
	sctx.plain_text = user->keys->scratch;

	int pt_offset = 0;
	int piuks[] = { KEY_PIUK0, KEY_PIUK1, KEY_PIUK2, KEY_PIUK3 };
	for( i = 0; i < num_keys; i++ ) {
		if( sqrl_user_has_key( transaction->user, piuks[i] )) {
			keyPointer = sqrl_user_key( transaction, piuks[i] );
			memcpy( sctx.plain_text + pt_offset, keyPointer, SQRL_KEY_SIZE );
			pt_offset += SQRL_KEY_SIZE;
		}
	}
	sctx.iv = sctx.plain_text + pt_offset;
	memset( sctx.iv, 0, 12 );
	keyPointer = sqrl_user_key( transaction, KEY_MK );
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

bool sul_block_1( struct Sqrl_Transaction *transaction, Sqrl_Block *block, struct sqrl_user_callback_data cbdata )
{
	WITH_USER(user,transaction->user);
	if( !user ) return false;
	bool retVal = true;
	Sqrl_Crypt_Context sctx;
    sctx.text_len = SQRL_KEY_SIZE * 2;

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
			key = sqrl_user_new_key( transaction->user, KEY_MK );
			memcpy( key, sctx.plain_text, SQRL_KEY_SIZE );
			key = sqrl_user_new_key( transaction->user, KEY_ILK );
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

bool sus_block_1( struct Sqrl_Transaction *transaction, Sqrl_Block *block, struct sqrl_user_callback_data cbdata )
{
	WITH_USER(user,transaction->user);
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
		keyPointer = sqrl_user_key( transaction, KEY_MK );
		memcpy( sctx.plain_text, keyPointer, SQRL_KEY_SIZE );
	} else {
		memset( sctx.plain_text, 0, SQRL_KEY_SIZE );
	}
	if( sqrl_user_has_key( (Sqrl_User)user, KEY_ILK )) {
		keyPointer = sqrl_user_key( transaction, KEY_ILK );
		memcpy( sctx.plain_text + SQRL_KEY_SIZE, keyPointer, SQRL_KEY_SIZE );
	} else {
		memset( sctx.plain_text + SQRL_KEY_SIZE, 0, SQRL_KEY_SIZE );
	}

	// Iteration Count
	uint8_t *key = sctx.plain_text + sctx.text_len;
	sctx.flags = SQRL_ENCRYPT | SQRL_MILLIS;
	sctx.count = user->options.enscryptSeconds * SQRL_MILLIS_PER_SECOND;
	sqrl_crypt_enscrypt( &sctx, key, user->keys->password, user->keys->password_len, sqrl_user_enscrypt_callback, &cbdata );
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

void sqrl_user_save_callback_data( struct sqrl_user_callback_data *cbdata )
{
	SQRL_CAST_TRANSACTION(transaction,cbdata->transaction);
	WITH_USER(user,transaction->user);
	cbdata->adder = 0;
	cbdata->multiplier = 1;
	cbdata->total = 0;
	cbdata->t1 = 0;
	cbdata->t2 = 0;
	int eS = (int)sqrl_user_get_enscrypt_seconds( transaction->user );
	bool t1 = (user->flags & USER_FLAG_T1_CHANGED) == USER_FLAG_T1_CHANGED;
	bool t2 = (user->flags & USER_FLAG_T2_CHANGED) == USER_FLAG_T2_CHANGED;
	if( t1 ) {
		cbdata->t1 = eS * SQRL_MILLIS_PER_SECOND;
		cbdata->total += cbdata->t1;
	}
	if( t2 ) {
		cbdata->t2 = SQRL_RESCUE_ENSCRYPT_SECONDS * SQRL_MILLIS_PER_SECOND;
		cbdata->total += cbdata->t2;
	}
	if( cbdata->total > cbdata->t1 ) {
		cbdata->multiplier = (cbdata->t1 / (double)cbdata->total);
	} else {
		cbdata->multiplier = 1;
	}
	END_WITH_USER(user);
}

bool sqrl_user_update_storage( Sqrl_Transaction t ) 
{
	WITH_TRANSACTION(transaction,t);
	if( !transaction ) return false;
	WITH_USER(user,transaction->user);
	if( !user ) {
		END_WITH_TRANSACTION(transaction);
		return false;
	}
	if( user->storage == NULL ) {
		user->storage = sqrl_storage_create();
	}
	struct sqrl_user_callback_data cbdata;
	memset( &cbdata, 0, sizeof( struct sqrl_user_callback_data ));
	cbdata.transaction = t;
	sqrl_user_save_callback_data( &cbdata );

	Sqrl_Block block;
	sqrl_block_clear( &block );
	bool retVal = true;

	if( (user->flags & USER_FLAG_T1_CHANGED) == USER_FLAG_T1_CHANGED ||
		! sqrl_storage_block_exists( user->storage, SQRL_BLOCK_USER )) 
	{
		if( sus_block_1( transaction, &block, cbdata )) {
			sqrl_storage_block_put( user->storage, &block );
		}
		sqrl_block_free( &block );
	}

	if( (user->flags & USER_FLAG_T2_CHANGED) == USER_FLAG_T2_CHANGED ||
		! sqrl_storage_block_exists( user->storage, SQRL_BLOCK_RESCUE ))
	{
		cbdata.adder = cbdata.t1;
		if( cbdata.total > cbdata.t2 ) {
			cbdata.adder = (cbdata.t1 * 100 / cbdata.total);
			cbdata.multiplier = (cbdata.t2 / (double)cbdata.total);
		} else {
			cbdata.multiplier = 1;
		}
		if( sus_block_2( transaction, user->storage, &block, cbdata )) {
			sqrl_storage_block_put( user->storage, &block );
		}
		sqrl_block_free( &block );
	}

	if( (user->flags & USER_FLAG_T2_CHANGED) == USER_FLAG_T2_CHANGED ||
		! sqrl_storage_block_exists( user->storage, SQRL_BLOCK_PREVIOUS ))
	{
		if( sus_block_3( transaction, &block, cbdata )) {
			sqrl_storage_block_put( user->storage, &block );
		}
		sqrl_block_free( &block );
	}

	END_WITH_USER(user);
	END_WITH_TRANSACTION(transaction);
	return retVal;
}

static void _suc_load_unique_id( struct Sqrl_User *user )
{
	if( !user ) return;
	sqrl_storage_unique_id( user->storage, user->unique_id );
}

Sqrl_User sqrl_user_create_from_file( const char *filename )
{
	DEBUG_PRINTF( "sqrl_user_create_from_file( %s )\n", filename );
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
	user->storage = storage;
	_suc_load_unique_id( user );
	END_WITH_USER(user);
	return u;

ERROR:
	if( u ) {
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
		sqrl_storage_destroy( storage );
	}
	utstring_free( buf );
	return u;
}

bool sqrl_user_save( Sqrl_Transaction t )
{
	WITH_TRANSACTION(transaction,t);
	if( !transaction ) return false;

	if( !transaction->uri || 
		(transaction->uri->scheme != SQRL_SCHEME_FILE )) {
		END_WITH_TRANSACTION(transaction);
		return false;
	}
	char *filename = transaction->uri->challenge;
	if( filename == NULL ) return false;
	Sqrl_Encoding encoding = transaction->encodingType;
	Sqrl_Export exportType = transaction->exportType;

	WITH_USER(user,transaction->user);
	if( user == NULL ) {
		END_WITH_TRANSACTION(transaction);
		return false;
	}
	if( sqrl_user_update_storage( t )) {
		if( sqrl_storage_save_to_file( user->storage, filename, exportType, encoding ) > 0 ) {
			END_WITH_USER(user);
			END_WITH_TRANSACTION(transaction);
			return true;
		}
	}
	END_WITH_USER(user);
	END_WITH_TRANSACTION(transaction);
	return false;
}

bool sqrl_user_save_to_buffer( Sqrl_Transaction t )
{
	WITH_TRANSACTION(transaction,t);
	if( !transaction ) return false;
	WITH_USER(user,transaction->user);
	if( !user ) {
		END_WITH_TRANSACTION(transaction);
		return false;
	}
	Sqrl_Encoding encoding = transaction->encodingType;
	Sqrl_Export exportType = transaction->exportType;
	bool retVal = true;
	UT_string *buf;
	utstring_new( buf );
	struct sqrl_user_callback_data cbdata;
	cbdata.transaction = transaction;
	cbdata.adder = 0;
	cbdata.multiplier = 1;

	if( sqrl_user_update_storage( t )) {
		if( sqrl_storage_save_to_buffer( user->storage, buf, exportType, encoding )) {
			if( transaction->string ) free( transaction->string );
			transaction->string = malloc( utstring_len(buf) + 1 );
			if( !transaction->string ) goto ERROR;
			memcpy( transaction->string, utstring_body(buf), utstring_len(buf));
			transaction->string[utstring_len(buf)] = 0x00;
			transaction->string_len = utstring_len( buf );
			goto DONE;
		}
	}

ERROR:
	if( transaction->string ) {
		free( transaction->string );
		transaction->string = NULL;
		transaction->string_len = 0;
	}
	retVal = false;

DONE:
	if( buf ) {
		utstring_free(buf);
	}
	END_WITH_USER(user);
	END_WITH_TRANSACTION(transaction);
	return retVal;
}

bool sqrl_user_try_load_password( Sqrl_Transaction t, bool retry )
{
	WITH_TRANSACTION(transaction,t);
	if( !transaction ) return false;
	WITH_USER(user,transaction->user);
	if( !user ) {
		END_WITH_TRANSACTION(transaction);
		return false;
	}
	bool retVal = false;
	Sqrl_Block block;
	struct sqrl_user_callback_data cbdata;
	cbdata.transaction = t;
	cbdata.adder = 0;
	cbdata.multiplier = 1;
LOOP:
	if( !sqrl_storage_block_exists( user->storage, SQRL_BLOCK_USER )) {
		retVal = sqrl_user_try_load_rescue( t, retry );
		goto DONE;
	}
	if( user->keys->password_len == 0 ) {
		goto NEEDAUTH;
	}

	memset( &block, 0, sizeof( Sqrl_Block ));
	sqrl_storage_block_get( user->storage, &block, SQRL_BLOCK_USER );
	if( ! sul_block_1( transaction, &block, cbdata )) {
		sqrl_block_free( &block );
		goto NEEDAUTH;
	}
	sqrl_block_free( &block );
	if( sqrl_storage_block_exists( user->storage, SQRL_BLOCK_PREVIOUS ) &&
		sqrl_storage_block_get( user->storage, &block, SQRL_BLOCK_PREVIOUS ))
	{
		sul_block_3( transaction, &block, cbdata );
		sqrl_block_free( &block );
	} else {
		sqrl_user_new_key( transaction->user, KEY_PIUK0 );
		sqrl_user_new_key( transaction->user, KEY_PIUK1 );
		sqrl_user_new_key( transaction->user, KEY_PIUK2 );
		sqrl_user_new_key( transaction->user, KEY_PIUK3 );
	}
	retVal = true;
	goto DONE;

NEEDAUTH:
	if( retry ) {
		retry = false;
		sqrl_client_call_authentication_required( t, SQRL_CREDENTIAL_PASSWORD );
		goto LOOP;
	}

DONE:
	END_WITH_USER(user);
	END_WITH_TRANSACTION(transaction);
	return retVal;
}

bool sqrl_user_try_load_rescue( Sqrl_Transaction t, bool retry )
{
	WITH_TRANSACTION(transaction,t);
	if( !transaction ) return false;
	WITH_USER(user,transaction->user);
	if( !user ) {
		END_WITH_TRANSACTION(transaction);
		return false;
	}
	bool retVal = false;
	struct sqrl_user_callback_data cbdata;
	cbdata.transaction = t;
	cbdata.adder = 0;
	cbdata.multiplier = 1;

LOOP:
	if( !sqrl_storage_block_exists( user->storage, SQRL_BLOCK_RESCUE )) {
		goto DONE;
	}
	if( !sqrl_user_has_key( transaction->user, KEY_RESCUE_CODE ) ) {
		goto NEEDAUTH;
	}

	Sqrl_Block block;
	memset( &block, 0, sizeof( Sqrl_Block ));
	sqrl_storage_block_get( user->storage, &block, SQRL_BLOCK_RESCUE );
	if( ! sul_block_2( transaction, &block, cbdata )) {
		sqrl_block_free( &block );
		goto NEEDAUTH;
	}
	sqrl_block_free( &block );
	sqrl_user_regen_keys( transaction );
	if( sqrl_storage_block_exists( user->storage, SQRL_BLOCK_PREVIOUS ) &&
		sqrl_storage_block_get( user->storage, &block, SQRL_BLOCK_PREVIOUS ))
	{
		sul_block_3( transaction, &block, cbdata );
		sqrl_block_free( &block );
	}
	goto DONE;

NEEDAUTH:
	if( retry ) {
		retry = false;
		sqrl_client_call_authentication_required( t, SQRL_CREDENTIAL_RESCUE_CODE );
		goto LOOP;
	}

DONE:
	END_WITH_USER(user);
	END_WITH_TRANSACTION(transaction);
	return retVal;
}


