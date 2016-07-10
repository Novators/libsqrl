/** @file user_storage.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/
#include <stdlib.h>
#include <stdio.h>
#include "sqrl_internal.h"

bool su_init_t2( 
	struct Sqrl_Transaction_s *transaction, 
	Sqrl_Crypt_Context *sctx, 
	SqrlBlock *block,
	bool forSaving )
{
	SQRL_CAST_USER( user, transaction->user );
	sctx->plain_text = user->keys->scratch;
    sctx->text_len = SQRL_KEY_SIZE;
	if( forSaving ) {
		if( !block->init( 2, 73 )) {
			return false;
		}
		block->writeInt16( 73 );
		block->writeInt16( 2 );
		uint8_t ent[16];
		sqrl_entropy_bytes(ent, 16);
		block->write(ent, 16);
		sctx->nFactor = SQRL_DEFAULT_N_FACTOR;
		block->writeInt8( SQRL_DEFAULT_N_FACTOR );
		memcpy( sctx->plain_text, sqrl_user_key( (Sqrl_Transaction)transaction, KEY_IUK ), SQRL_KEY_SIZE );
		sctx->flags = SQRL_ENCRYPT | SQRL_MILLIS;
		sctx->count = SQRL_RESCUE_ENSCRYPT_SECONDS * SQRL_MILLIS_PER_SECOND;
	} else {
		block->seek( 0 );
		if( 73 != block->readInt16() ||
				2 != block->readInt16()) {
			return false;
		}
		block->seek( 20 );
		sctx->nFactor = block->readInt8();
		sctx->flags = SQRL_DECRYPT | SQRL_ITERATIONS;
	}
	sctx->add = block->getDataPointer();
	sctx->add_len = 25;
	sctx->iv = NULL;
	sctx->salt = sctx->add + 4;
	sctx->cipher_text = sctx->add + sctx->add_len;
	sctx->tag = sctx->cipher_text + sctx->text_len;
	return true;
}

bool sul_block_2( struct Sqrl_Transaction_s *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
{
	SQRL_CAST_USER(user,transaction->user);
	bool retVal = false;
	Sqrl_Crypt_Context sctx;
	if( ! sqrl_user_has_key( transaction->user, KEY_RESCUE_CODE )) {
		return false;
	}
	
	if( !su_init_t2( transaction, &sctx, block, false )) {
		goto ERR;
	}

	uint8_t *key = user->keys->scratch + sctx.text_len;
	char *rc = (char*)sqrl_user_key( transaction, KEY_RESCUE_CODE );
	block->seek( 21 );
	sctx.count = block->readInt32();
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

ERR:
	retVal = false;

DONE:
	sodium_memzero( user->keys->scratch, sctx.text_len + SQRL_KEY_SIZE );
	return retVal;

}

bool sus_block_2( struct Sqrl_Transaction_s *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
{
	SQRL_CAST_USER(user,transaction->user);
	bool retVal = true;
	Sqrl_Crypt_Context sctx;
	if( ! sqrl_user_has_key( transaction->user, KEY_IUK )
		|| ! sqrl_user_has_key( transaction->user, KEY_RESCUE_CODE )) {
		return false;
	}
	
	if( !su_init_t2( transaction, &sctx, block, true )) {
		goto ERR;
	}

	uint8_t *key = user->keys->scratch + sctx.text_len;
	char *rc = (char*)sqrl_user_key( transaction, KEY_RESCUE_CODE );
	sqrl_crypt_enscrypt( &sctx, key, rc, SQRL_RESCUE_CODE_LENGTH, sqrl_user_enscrypt_callback, &cbdata );
	block->seek( 21 );
	block->writeInt32( sctx.count );

	// Cipher Text
	sctx.flags = SQRL_ENCRYPT | SQRL_ITERATIONS;
	uint8_t *iuk = sqrl_user_key( transaction, KEY_IUK );
	memcpy( sctx.plain_text, iuk, sctx.text_len );
	if( !sqrl_crypt_gcm( &sctx, key )) {
		goto ERR;
	}
	// Save unique id
	UT_string *str;
	utstring_new( str );
	sqrl_b64u_encode( str, sctx.cipher_text, SQRL_KEY_SIZE );
	strcpy( user->unique_id, utstring_body(str));
	utstring_free( str );

	goto DONE;

ERR:
	retVal = false;

DONE:
	sodium_memzero( user->keys->scratch, sctx.text_len + SQRL_KEY_SIZE );
	return retVal;
}

bool sul_block_3( struct Sqrl_Transaction_s *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
{
	SQRL_CAST_USER(user,transaction->user);
	bool retVal = true;
	int i;
	Sqrl_Crypt_Context sctx;
	uint8_t *keyPointer;
	block->seek(0);
	sctx.add = block->getDataPointer();
	sctx.add_len = 4;
	if( block->readInt16() != 148 ||
		block->readInt16() != 3 ) {
		return false;
	}
	sctx.text_len = SQRL_KEY_SIZE * 4;
	sctx.cipher_text = sctx.add + 4;
	sctx.tag = sctx.cipher_text + (SQRL_KEY_SIZE * 4);
	sctx.plain_text = user->keys->scratch;
	sctx.iv = sctx.plain_text + sctx.text_len;
	memset( sctx.iv, 0, 12 );
	keyPointer = sqrl_user_key( transaction, KEY_MK );
	sctx.flags = SQRL_DECRYPT | SQRL_ITERATIONS;
	if( !sqrl_crypt_gcm( &sctx, keyPointer )) {
		goto ERR;
	}

	int pt_offset = 0;
	int piuks[] = { KEY_PIUK0, KEY_PIUK1, KEY_PIUK2, KEY_PIUK3 };
	for( i = 0; i < 4; i++ ) {
		keyPointer = sqrl_user_new_key( transaction->user, piuks[i] );
		memcpy( keyPointer, sctx.plain_text + pt_offset, SQRL_KEY_SIZE );
		pt_offset += SQRL_KEY_SIZE;
	}
	goto DONE;

ERR:
	retVal = false;

DONE:
	sodium_memzero( user->keys->scratch, sctx.text_len );
	return retVal;

}

bool sus_block_3( struct Sqrl_Transaction_s *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
{
	SQRL_CAST_USER(user,transaction->user);
	bool retVal = true;
	int i;
	Sqrl_Crypt_Context sctx;
	uint8_t *keyPointer;
	block->init( 3, 148 );
	sctx.add = block->getDataPointer();
	sctx.add_len = 4;
	block->writeInt16( 148 );
	block->writeInt16( 3 );
	sctx.text_len = SQRL_KEY_SIZE * 4;
	sctx.cipher_text = sctx.add + 4;
	sctx.tag = sctx.cipher_text + (SQRL_KEY_SIZE * 4);
	sctx.plain_text = user->keys->scratch;

	int pt_offset = 0;
	int piuks[] = { KEY_PIUK0, KEY_PIUK1, KEY_PIUK2, KEY_PIUK3 };
	for( i = 0; i < 4; i++ ) {
		if( sqrl_user_has_key( transaction->user, piuks[i] )) {
			keyPointer = sqrl_user_key( transaction, piuks[i] );
			memcpy( sctx.plain_text + pt_offset, keyPointer, SQRL_KEY_SIZE );
		} else {
			memset( sctx.plain_text + pt_offset, 0, SQRL_KEY_SIZE );
		}
		pt_offset += SQRL_KEY_SIZE;
	}
	sctx.iv = sctx.plain_text + pt_offset;
	memset( sctx.iv, 0, 12 );
	keyPointer = sqrl_user_key( transaction, KEY_MK );
	sctx.count = 100;
	sctx.flags = SQRL_ENCRYPT | SQRL_MILLIS;
	if( !sqrl_crypt_gcm( &sctx, keyPointer )) {
		goto ERR;
	}
	goto DONE;

ERR:
	retVal = false;

DONE:
	sodium_memzero( user->keys->scratch, sctx.text_len );
	return retVal;
}

bool sul_block_1( struct Sqrl_Transaction_s *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
{
	WITH_USER(user,transaction->user);
	if( !user ) return false;
	bool retVal = true;
	Sqrl_Crypt_Context sctx;
    sctx.text_len = SQRL_KEY_SIZE * 2;

	block->seek(0);
	if( block->readInt16() != 125 ) {
		goto ERR;
	}

	// ADD
	sctx.add = block->getDataPointer();
	block->seek( 4 );
	sctx.add_len = block->readInt16();
	if( sctx.add_len != 45 ) {
		goto ERR;
	}
	// IV and Salt
	sctx.iv = block->getDataPointer(true);
	block->seek(12, true);
	sctx.salt = block->getDataPointer(true);
	block->seek(16, true);
	// N Factor
	sctx.nFactor = block->readInt8();
	// Iteration Count
	sctx.count = block->readInt32();
	// Options
	user->options.flags = block->readInt16();
	user->options.hintLength = block->readInt8();
	user->options.enscryptSeconds = block->readInt8();
	user->options.timeoutMinutes = block->readInt16();
	// Cipher Text
	sctx.cipher_text = block->getDataPointer(true);
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

ERR:
	retVal = false;

DONE:
	sodium_memzero( user->keys->scratch, sctx.text_len + SQRL_KEY_SIZE );
	END_WITH_USER(user);
	return retVal;
}

bool sus_block_1( struct Sqrl_Transaction_s *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
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
	block->init( 1, 125 );
	// Block Length
	block->writeInt16( 125 );
	// Block Type
	block->writeInt16( 1 );
	// ADD
	sctx.add = block->getDataPointer();
	sctx.add_len = 45;
	block->writeInt16( 45 );
	// IV and Salt
	uint8_t ent[28];
	sqrl_entropy_bytes(ent, 28);
	block->write(ent, 28);
	block->seekBack(28, true);
	sctx.iv = block->getDataPointer(true);
	block->seek(12, true);
	sctx.salt = block->getDataPointer(true);
	block->seek(16, true);
	// N Factor
	sctx.nFactor = SQRL_DEFAULT_N_FACTOR;
	block->writeInt8( sctx.nFactor );
	// Options
	block->seek( 39 );
	block->writeInt16( user->options.flags );
	block->writeInt8( user->options.hintLength );
	block->writeInt8( user->options.enscryptSeconds );
	block->writeInt16( user->options.timeoutMinutes );
	// Cipher Text
	sctx.text_len = SQRL_KEY_SIZE * 2;
	sctx.cipher_text = block->getDataPointer(true);
	// Verification Tag
	block->seek(sctx.text_len, true);
	sctx.tag = block->getDataPointer(true);
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
	block->seek( 35 );
	block->writeInt32( sctx.count );

	// Cipher Text
	sctx.flags = SQRL_ENCRYPT | SQRL_ITERATIONS;
	if( !sqrl_crypt_gcm( &sctx, key )) {
		goto ERR;
	}
	goto DONE;

ERR:
	retVal = false;

DONE:
	sodium_memzero( user->keys->scratch, sctx.text_len + SQRL_KEY_SIZE );
	END_WITH_USER(user);
	return retVal;
}

void sqrl_user_save_callback_data( struct Sqrl_User_s_callback_data *cbdata )
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
		user->storage = new SqrlStorage();
	}
	struct Sqrl_User_s_callback_data cbdata;
	memset( &cbdata, 0, sizeof( struct Sqrl_User_s_callback_data ));
	cbdata.transaction = t;
	sqrl_user_save_callback_data( &cbdata );

	SqrlBlock block = SqrlBlock();
	bool retVal = true;

	if( (user->flags & USER_FLAG_T1_CHANGED) == USER_FLAG_T1_CHANGED ||
		! user->storage->hasBlock( SQRL_BLOCK_USER )) 
	{
		if( sus_block_1( transaction, &block, cbdata )) {
			user->storage->putBlock(&block);
		}
	}

	if( (user->flags & USER_FLAG_T2_CHANGED) == USER_FLAG_T2_CHANGED ||
		! user->storage->hasBlock( SQRL_BLOCK_RESCUE ))
	{
		cbdata.adder = cbdata.t1;
		if( cbdata.total > cbdata.t2 ) {
			cbdata.adder = (cbdata.t1 * 100 / cbdata.total);
			cbdata.multiplier = (cbdata.t2 / (double)cbdata.total);
		} else {
			cbdata.multiplier = 1;
		}
		if( sus_block_2( transaction, &block, cbdata )) {
			user->storage->putBlock(&block);
		}
	}

	if( (user->flags & USER_FLAG_T2_CHANGED) == USER_FLAG_T2_CHANGED ||
		! user->storage->hasBlock( SQRL_BLOCK_PREVIOUS ))
	{
		if( sus_block_3( transaction, &block, cbdata )) {
			user->storage->putBlock( &block );
		}
	}

	END_WITH_USER(user);
	END_WITH_TRANSACTION(transaction);
	return retVal;
}

static void _suc_load_unique_id( struct Sqrl_User_s *user )
{
	if( !user ) return;
	user->storage->getUniqueId(user->unique_id);
}

Sqrl_User sqrl_user_create_from_file( const char *filename )
{
	DEBUG_PRINTF( "sqrl_user_create_from_file( %s )\n", filename );
	Sqrl_User u = NULL;
	SqrlUri uri = SqrlUri(filename);
	if (uri.getScheme() != SQRL_SCHEME_FILE) {
		return NULL;
	}
	SqrlStorage *storage = new SqrlStorage();
	if( !storage->load( &uri )) {
		delete(storage);
		return NULL;
	}
	u = sqrl_user_create();
	WITH_USER(user,u);
	if( user == NULL ) {
		goto ERR;
	}
	user->storage = storage;
	_suc_load_unique_id( user );
	END_WITH_USER(user);
	return u;

ERR:
	if( u ) {
		END_WITH_USER(user);
		sqrl_user_release(u);
	}
	if( storage ) {
		delete(storage);
	}
	return NULL;
}

Sqrl_User sqrl_user_create_from_buffer( const char *buffer, size_t buffer_len )
{
	Sqrl_User u = NULL;
	UT_string *buf;
	utstring_new( buf );
	utstring_printf( buf, buffer, buffer_len );
	SqrlStorage *storage = new SqrlStorage();
	if( storage->load( buf )) {
		u = sqrl_user_create();
		WITH_USER(user,u);
		user->storage = storage;
		_suc_load_unique_id( user );
		END_WITH_USER(user);
	} else {
		delete(storage);
	}
	utstring_free( buf );
	return u;
}

bool sqrl_user_save( Sqrl_Transaction t )
{
	WITH_TRANSACTION(transaction,t);
	if( !transaction ) return false;

	if( !transaction->uri || 
		(transaction->uri->getScheme() != SQRL_SCHEME_FILE )) {
		END_WITH_TRANSACTION(transaction);
		return false;
	}
	char *filename = transaction->uri->getChallenge();
	if( filename == NULL ) return false;
	Sqrl_Encoding encoding = transaction->encodingType;
	Sqrl_Export exportType = transaction->exportType;

	WITH_USER(user,transaction->user);
	if( user == NULL ) {
		END_WITH_TRANSACTION(transaction);
		return false;
	}
	if( sqrl_user_update_storage( t )) {
		SqrlUri uri = SqrlUri(filename);
		if( user->storage->save( &uri, exportType, encoding )) {
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
	struct Sqrl_User_s_callback_data cbdata;
	cbdata.transaction = transaction;
	cbdata.adder = 0;
	cbdata.multiplier = 1;

	if( sqrl_user_update_storage( t )) {
		if( user->storage->save( buf, exportType, encoding )) {
			if( transaction->string ) free( transaction->string );
			transaction->string = (char*)malloc( utstring_len(buf) + 1 );
			if( !transaction->string ) goto ERR;
			memcpy( transaction->string, utstring_body(buf), utstring_len(buf));
			transaction->string[utstring_len(buf)] = 0x00;
			transaction->string_len = utstring_len( buf );
			goto DONE;
		}
	}

ERR:
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
	SqrlBlock block = SqrlBlock();
	struct Sqrl_User_s_callback_data cbdata;
	cbdata.transaction = t;
	cbdata.adder = 0;
	cbdata.multiplier = 1;
LOOP:
	if( ! user->storage->hasBlock( SQRL_BLOCK_USER )) {
		retVal = sqrl_user_try_load_rescue( t, retry );
		goto DONE;
	}
	if( user->keys->password_len == 0 ) {
		goto NEEDAUTH;
	}

	user->storage->getBlock( &block, SQRL_BLOCK_USER );
	if( ! sul_block_1( transaction, &block, cbdata )) {
		goto NEEDAUTH;
	}
	if( user->storage->hasBlock( SQRL_BLOCK_PREVIOUS ) &&
		user->storage->getBlock( &block, SQRL_BLOCK_PREVIOUS ))
	{
		sul_block_3( transaction, &block, cbdata );
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
	struct Sqrl_User_s_callback_data cbdata;
	cbdata.transaction = t;
	cbdata.adder = 0;
	cbdata.multiplier = 1;
	SqrlBlock block = SqrlBlock();

LOOP:
	if( !user->storage->hasBlock( SQRL_BLOCK_RESCUE )) {
		goto DONE;
	}
	if( !sqrl_user_has_key( transaction->user, KEY_RESCUE_CODE ) ) {
		goto NEEDAUTH;
	}

	user->storage->getBlock( &block, SQRL_BLOCK_RESCUE );
	if( ! sul_block_2( transaction, &block, cbdata )) {
		goto NEEDAUTH;
	}
	sqrl_user_regen_keys( transaction );
	if( user->storage->hasBlock( SQRL_BLOCK_PREVIOUS ) &&
		user->storage->getBlock( &block, SQRL_BLOCK_PREVIOUS ))
	{
		sul_block_3( transaction, &block, cbdata );
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


