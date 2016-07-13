/** @file user_storage.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/
#include "sqrl_internal.h"
#include "sqrl.h"
#include "SqrlUser.h"
#include "SqrlTransaction.h"
#include "SqrlBlock.h"
#include "SqrlStorage.h"
#include "SqrlUri.h"
#include "SqrlClient.h"

bool SqrlUser::_init_t2( 
	SqrlTransaction *transaction, 
	Sqrl_Crypt_Context *sctx, 
	SqrlBlock *block,
	bool forSaving )
{
	if (transaction->getUser() != this) return false;
	sctx->plain_text = this->scratch();
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
		memcpy( sctx->plain_text, this->key( transaction, KEY_IUK ), SQRL_KEY_SIZE );
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

bool SqrlUser::sul_block_2( SqrlTransaction *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
{
	if (transaction->getUser() != this) return false;
	bool retVal = false;
	Sqrl_Crypt_Context sctx;
	if( ! this->hasKey( KEY_RESCUE_CODE )) {
		return false;
	}
	
	if( !this->_init_t2( transaction, &sctx, block, false )) {
		goto ERR;
	}

	uint8_t *key = this->scratch() + sctx.text_len;
	char *rc = (char*)this->key( transaction, KEY_RESCUE_CODE );
	block->seek( 21 );
	sctx.count = block->readInt32();
	sctx.flags = SQRL_DECRYPT | SQRL_ITERATIONS;
	if( sqrl_crypt_enscrypt( 
			&sctx, 
			key, 
			rc, 
			SQRL_RESCUE_CODE_LENGTH, 
			SqrlUser::enscryptCallback, 
			&cbdata ) > 0 ) {
		if( sqrl_crypt_gcm( &sctx, key )) {
			uint8_t *iuk = this->newKey( KEY_IUK );
			memcpy( iuk, sctx.plain_text, SQRL_KEY_SIZE );
			retVal = true;
			goto DONE;
		}
	}

ERR:
	retVal = false;

DONE:
	sodium_memzero( this->keys->scratch, sctx.text_len + SQRL_KEY_SIZE );
	return retVal;

}

bool SqrlUser::sus_block_2( SqrlTransaction *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
{
	if (transaction->getUser() != this) return false;
	bool retVal = true;
	Sqrl_Crypt_Context sctx;
	if( ! this->hasKey( KEY_IUK )
		|| ! this->hasKey( KEY_RESCUE_CODE )) {
		return false;
	}
	
	if( ! this->_init_t2( transaction, &sctx, block, true )) {
		goto ERR;
	}

	uint8_t *key = this->scratch() + sctx.text_len;
	char *rc = (char*)this->key( transaction, KEY_RESCUE_CODE );
	sqrl_crypt_enscrypt( &sctx, key, rc, SQRL_RESCUE_CODE_LENGTH, SqrlUser::enscryptCallback, &cbdata );
	block->seek( 21 );
	block->writeInt32( sctx.count );

	// Cipher Text
	sctx.flags = SQRL_ENCRYPT | SQRL_ITERATIONS;
	uint8_t *iuk = this->key( transaction, KEY_IUK );
	memcpy( sctx.plain_text, iuk, sctx.text_len );
	if( !sqrl_crypt_gcm( &sctx, key )) {
		goto ERR;
	}
	// Save unique id
	UT_string *str;
	utstring_new( str );
	sqrl_b64u_encode( str, sctx.cipher_text, SQRL_KEY_SIZE );
	strcpy( this->uniqueId, utstring_body(str));
	utstring_free( str );

	goto DONE;

ERR:
	retVal = false;

DONE:
	sodium_memzero( this->keys->scratch, sctx.text_len + SQRL_KEY_SIZE );
	return retVal;
}

bool SqrlUser::sul_block_3( SqrlTransaction *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
{
	if (transaction->getUser() != this) return false;
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
	sctx.plain_text = this->keys->scratch;
	sctx.iv = sctx.plain_text + sctx.text_len;
	memset( sctx.iv, 0, 12 );
	keyPointer = this->key( transaction, KEY_MK );
	sctx.flags = SQRL_DECRYPT | SQRL_ITERATIONS;
	if( !sqrl_crypt_gcm( &sctx, keyPointer )) {
		goto ERR;
	}

	int pt_offset = 0;
	int piuks[] = { KEY_PIUK0, KEY_PIUK1, KEY_PIUK2, KEY_PIUK3 };
	for( i = 0; i < 4; i++ ) {
		keyPointer = this->newKey( piuks[i] );
		memcpy( keyPointer, sctx.plain_text + pt_offset, SQRL_KEY_SIZE );
		pt_offset += SQRL_KEY_SIZE;
	}
	goto DONE;

ERR:
	retVal = false;

DONE:
	sodium_memzero( this->keys->scratch, sctx.text_len );
	return retVal;

}

bool SqrlUser::sus_block_3( SqrlTransaction *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
{
	if (transaction->getUser() != this) return false;
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
	sctx.plain_text = this->keys->scratch;

	int pt_offset = 0;
	int piuks[] = { KEY_PIUK0, KEY_PIUK1, KEY_PIUK2, KEY_PIUK3 };
	for( i = 0; i < 4; i++ ) {
		if( this->hasKey( piuks[i] )) {
			keyPointer = this->key( transaction, piuks[i] );
			memcpy( sctx.plain_text + pt_offset, keyPointer, SQRL_KEY_SIZE );
		} else {
			memset( sctx.plain_text + pt_offset, 0, SQRL_KEY_SIZE );
		}
		pt_offset += SQRL_KEY_SIZE;
	}
	sctx.iv = sctx.plain_text + pt_offset;
	memset( sctx.iv, 0, 12 );
	keyPointer = this->key( transaction, KEY_MK );
	sctx.count = 100;
	sctx.flags = SQRL_ENCRYPT | SQRL_MILLIS;
	if( !sqrl_crypt_gcm( &sctx, keyPointer )) {
		goto ERR;
	}
	goto DONE;

ERR:
	retVal = false;

DONE:
	sodium_memzero( this->keys->scratch, sctx.text_len );
	return retVal;
}

bool SqrlUser::sul_block_1( SqrlTransaction *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
{
	if (transaction->getUser() != this) return false;
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
	this->options.flags = block->readInt16();
	this->options.hintLength = block->readInt8();
	this->options.enscryptSeconds = block->readInt8();
	this->options.timeoutMinutes = block->readInt16();
	// Cipher Text
	sctx.cipher_text = block->getDataPointer(true);
	// Verification Tag
	sctx.tag = sctx.cipher_text + sctx.text_len;
	// Plain Text
	sctx.plain_text = this->keys->scratch;

	// Iteration Count
	uint8_t *key = sctx.plain_text + sctx.text_len;
	sctx.flags = SQRL_DECRYPT | SQRL_ITERATIONS;
	if( sqrl_crypt_enscrypt( 
			&sctx, 
			key, 
			this->keys->password, 
			this->keys->password_len,
			SqrlUser::enscryptCallback, 
			&cbdata ) > 0 ) {
		if( sqrl_crypt_gcm( &sctx, key )) {
			key = this->newKey( KEY_MK );
			memcpy( key, sctx.plain_text, SQRL_KEY_SIZE );
			key = this->newKey( KEY_ILK );
			memcpy( key, sctx.plain_text + SQRL_KEY_SIZE, SQRL_KEY_SIZE );
			goto DONE;
		}
	}

ERR:
	retVal = false;

DONE:
	sodium_memzero( this->keys->scratch, sctx.text_len + SQRL_KEY_SIZE );
	return retVal;
}

bool SqrlUser::sus_block_1( SqrlTransaction *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
{
	if (transaction->getUser() != this) return false;
	bool retVal = true;
	Sqrl_Crypt_Context sctx;
	SqrlClient::getClient()->callAuthenticationRequired( cbdata.transaction, SQRL_CREDENTIAL_PASSWORD );
	// TODO: Verify Password obtained

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
	block->writeInt16( this->options.flags );
	block->writeInt8( this->options.hintLength );
	block->writeInt8( this->options.enscryptSeconds );
	block->writeInt16( this->options.timeoutMinutes );
	// Cipher Text
	sctx.text_len = SQRL_KEY_SIZE * 2;
	sctx.cipher_text = block->getDataPointer(true);
	// Verification Tag
	block->seek(sctx.text_len, true);
	sctx.tag = block->getDataPointer(true);
	// Plain Text
	sctx.plain_text = this->keys->scratch;
	if( this->hasKey( KEY_MK )) {
		keyPointer = this->key( transaction, KEY_MK );
		memcpy( sctx.plain_text, keyPointer, SQRL_KEY_SIZE );
	} else {
		memset( sctx.plain_text, 0, SQRL_KEY_SIZE );
	}
	if( this->hasKey( KEY_ILK )) {
		keyPointer = this->key( transaction, KEY_ILK );
		memcpy( sctx.plain_text + SQRL_KEY_SIZE, keyPointer, SQRL_KEY_SIZE );
	} else {
		memset( sctx.plain_text + SQRL_KEY_SIZE, 0, SQRL_KEY_SIZE );
	}

	// Iteration Count
	uint8_t *key = sctx.plain_text + sctx.text_len;
	sctx.flags = SQRL_ENCRYPT | SQRL_MILLIS;
	sctx.count = this->options.enscryptSeconds * SQRL_MILLIS_PER_SECOND;
	sqrl_crypt_enscrypt( &sctx, key, this->keys->password, this->keys->password_len, SqrlUser::enscryptCallback, &cbdata );
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
	sodium_memzero( this->keys->scratch, sctx.text_len + SQRL_KEY_SIZE );
	return retVal;
}

void SqrlUser::saveCallbackData( struct Sqrl_User_s_callback_data *cbdata )
{
	SqrlUser *user = cbdata->transaction->getUser();
	if (!user) return;
	cbdata->adder = 0;
	cbdata->multiplier = 1;
	cbdata->total = 0;
	cbdata->t1 = 0;
	cbdata->t2 = 0;
	int eS = (int)user->getEnscryptSeconds();
	bool t1 = user->checkFlags(USER_FLAG_T1_CHANGED) == USER_FLAG_T1_CHANGED;
	bool t2 = user->checkFlags(USER_FLAG_T2_CHANGED) == USER_FLAG_T2_CHANGED;
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
}

bool SqrlUser::updateStorage( SqrlTransaction *transaction )
{
	if (!transaction) return false;
	if( transaction->getUser() != this ) {
		return false;
	}
	if( this->storage == NULL ) {
		this->storage = SqrlStorage::empty();
	}
	struct Sqrl_User_s_callback_data cbdata;
	memset( &cbdata, 0, sizeof( struct Sqrl_User_s_callback_data ));
	cbdata.transaction = transaction;
	this->saveCallbackData( &cbdata );

	SqrlBlock *block = SqrlBlock::create();
	bool retVal = true;

	if( (this->flags & USER_FLAG_T1_CHANGED) == USER_FLAG_T1_CHANGED ||
		! this->storage->hasBlock( SQRL_BLOCK_USER )) 
	{
		if( sus_block_1( transaction, block, cbdata )) {
			this->storage->putBlock(block);
		}
	}

	if( (this->flags & USER_FLAG_T2_CHANGED) == USER_FLAG_T2_CHANGED ||
		! this->storage->hasBlock( SQRL_BLOCK_RESCUE ))
	{
		cbdata.adder = cbdata.t1;
		if( cbdata.total > cbdata.t2 ) {
			cbdata.adder = (cbdata.t1 * 100 / cbdata.total);
			cbdata.multiplier = (cbdata.t2 / (double)cbdata.total);
		} else {
			cbdata.multiplier = 1;
		}
		if( sus_block_2( transaction, block, cbdata )) {
			this->storage->putBlock(block);
		}
	}

	if( (this->flags & USER_FLAG_T2_CHANGED) == USER_FLAG_T2_CHANGED ||
		! this->storage->hasBlock( SQRL_BLOCK_PREVIOUS ))
	{
		if( sus_block_3( transaction, block, cbdata )) {
			this->storage->putBlock( block );
		}
	}
	block->release();
	return retVal;
}

void SqrlUser::_load_unique_id()
{
	if (this->storage) {
		this->storage->getUniqueId(this->uniqueId);
	}
}

SqrlUser::SqrlUser( SqrlUri *uri )
{
	this->initialize();
	if (uri->getScheme() != SQRL_SCHEME_FILE) {
		return;
	}
	this->storage = SqrlStorage::from( uri );
	if( this->storage ) {
		this->_load_unique_id();
		// TODO: Load Options
	}
}

SqrlUser::SqrlUser( const char *buffer, size_t buffer_len )
{
	this->initialize();
	UT_string *buf;
	utstring_new( buf );
	utstring_bincpy(buf, buffer, buffer_len);
	this->storage = SqrlStorage::from( buf );
	if( this->storage ) {
		this->_load_unique_id();
	}
	utstring_free( buf );
}

bool SqrlUser::save( SqrlTransaction *transaction )
{
	if( !transaction ) return false;

	SqrlUri *uri = transaction->getUri();
	if( !uri || (uri->getScheme() != SQRL_SCHEME_FILE )) {
		return false;
	}
	if (transaction->getUser() != this) {
		return false;
	}
	if (uri->getChallengeLength() == 0) {
		return false;
	}

	if (this->updateStorage(transaction)) {
		if( this->storage->save( uri, transaction->getExportType(), transaction->getEncodingType())) {
			return true;
		}
	}
	return false;
}

bool SqrlUser::saveToBuffer( SqrlTransaction *transaction )
{
	if( !transaction ) return false;
	if (transaction->getUser() != this) {
		return false;
	}
	bool retVal = true;
	UT_string *buf;
	utstring_new( buf );
	struct Sqrl_User_s_callback_data cbdata;
	cbdata.transaction = transaction;
	cbdata.adder = 0;
	cbdata.multiplier = 1;

	if( this->updateStorage( transaction )) {
		if( this->storage->save( buf, transaction->getExportType(), transaction->getEncodingType())) {
			transaction->setString( utstring_body( buf ), utstring_len( buf ));
			goto DONE;
		}
	}

	transaction->setString(NULL, 0);
	retVal = false;

DONE:
	if( buf ) {
		utstring_free(buf);
	}
	return retVal;
}

bool SqrlUser::tryLoadPassword( SqrlTransaction *transaction, bool retry )
{
	if( !transaction ) return false;
	if (transaction->getUser() != this) {
		return false;
	}
	bool retVal = false;
	SqrlBlock *block = SqrlBlock::create();
	struct Sqrl_User_s_callback_data cbdata;
	cbdata.transaction = transaction;
	cbdata.adder = 0;
	cbdata.multiplier = 1;
LOOP:
	if( ! this->storage->hasBlock( SQRL_BLOCK_USER )) {
		retVal = this->tryLoadRescue( transaction, retry );
		goto DONE;
	}
	if( this->keys->password_len == 0 ) {
		goto NEEDAUTH;
	}

	this->storage->getBlock( block, SQRL_BLOCK_USER );
	if( ! sul_block_1( transaction, block, cbdata )) {
		goto NEEDAUTH;
	}
	if( this->storage->hasBlock( SQRL_BLOCK_PREVIOUS ) &&
		this->storage->getBlock( block, SQRL_BLOCK_PREVIOUS ))
	{
		sul_block_3( transaction, block, cbdata );
	}
	retVal = true;
	goto DONE;

NEEDAUTH:
	if( retry ) {
		retry = false;
		SqrlClient::getClient()->callAuthenticationRequired(transaction, SQRL_CREDENTIAL_PASSWORD);
		goto LOOP;
	}

DONE:
	block->release();
	return retVal;
}

bool SqrlUser::tryLoadRescue( SqrlTransaction *transaction, bool retry )
{
	if( !transaction ) return false;
	if( transaction->getUser() != this ) {
		return false;
	}
	bool retVal = false;
	struct Sqrl_User_s_callback_data cbdata;
	cbdata.transaction = transaction;
	cbdata.adder = 0;
	cbdata.multiplier = 1;
	SqrlBlock *block = SqrlBlock::create();

LOOP:
	if( !this->storage->hasBlock( SQRL_BLOCK_RESCUE )) {
		goto DONE;
	}
	if( !this->hasKey( KEY_RESCUE_CODE ) ) {
		goto NEEDAUTH;
	}

	this->storage->getBlock( block, SQRL_BLOCK_RESCUE );
	if( ! sul_block_2( transaction, block, cbdata )) {
		goto NEEDAUTH;
	}
	this->regenKeys( transaction );
	if( this->storage->hasBlock( SQRL_BLOCK_PREVIOUS ) &&
		this->storage->getBlock( block, SQRL_BLOCK_PREVIOUS ))
	{
		sul_block_3( transaction, block, cbdata );
	}
	goto DONE;

NEEDAUTH:
	if( retry ) {
		retry = false;
		SqrlClient::getClient()->callAuthenticationRequired( transaction, SQRL_CREDENTIAL_RESCUE_CODE );
		goto LOOP;
	}

DONE:
	block->release();
	return retVal;
}


