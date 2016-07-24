/** @file user_storage.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/
#include "sqrl_internal.h"
#include "sqrl.h"
#include "SqrlUser.h"
#include "SqrlBlock.h"
#include "SqrlStorage.h"
#include "SqrlUri.h"
#include "SqrlClient.h"
#include "SqrlCrypt.h"
#include "SqrlBase64.h"
#include "SqrlActionSave.h"
#include "SqrlEntropy.h"

SqrlCrypt* SqrlUser::_init_t2( 
	SqrlAction *transaction, 
	SqrlBlock *block,
	bool forSaving )
{
	if (transaction->getUser() != this) return false;
	SqrlCrypt *crypt = new SqrlCrypt();
	crypt->plain_text = this->scratch();
    crypt->text_len = SQRL_KEY_SIZE;
	if( forSaving ) {
		if( !block->init( 2, 73 )) {
			delete crypt;
			return NULL;
		}
		block->writeInt16( 73 );
		block->writeInt16( 2 );
		uint8_t ent[16];
		SqrlEntropy::bytes(ent, 16);
		block->write(ent, 16);
		crypt->nFactor = SQRL_DEFAULT_N_FACTOR;
		block->writeInt8( SQRL_DEFAULT_N_FACTOR );
		memcpy( crypt->plain_text, this->key( transaction, KEY_IUK ), SQRL_KEY_SIZE );
		crypt->flags = SQRL_ENCRYPT | SQRL_MILLIS;
		crypt->count = SQRL_RESCUE_ENSCRYPT_SECONDS * SQRL_MILLIS_PER_SECOND;
	} else {
		block->seek( 0 );
		if( 73 != block->readInt16() ||
				2 != block->readInt16()) {
			delete crypt;
			return NULL;
		}
		block->seek( 20 );
		crypt->nFactor = block->readInt8();
		crypt->flags = SQRL_DECRYPT | SQRL_ITERATIONS;
	}
	crypt->add = block->getDataPointer();
	crypt->add_len = 25;
	crypt->iv = NULL;
	crypt->salt = crypt->add + 4;
	crypt->cipher_text = crypt->add + crypt->add_len;
	crypt->tag = crypt->cipher_text + crypt->text_len;
	return crypt;
}

bool SqrlUser::sul_block_2( SqrlAction *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
{
	if (transaction->getUser() != this) return false;
	bool retVal = false;
	if( ! this->hasKey( KEY_RESCUE_CODE )) {
		return false;
	}
	
	SqrlCrypt *crypt = this->_init_t2( transaction, block, false );
	if( !crypt ) {
		goto ERR;
	}

	crypt->key = this->scratch() + crypt->text_len;
	char *rc = (char*)this->key( transaction, KEY_RESCUE_CODE );
	block->seek( 21 );
	crypt->count = block->readInt32();
	crypt->flags = SQRL_DECRYPT | SQRL_ITERATIONS;
	if( crypt->genKey( transaction, rc, SQRL_RESCUE_CODE_LENGTH ) ) {
		if( crypt->doCrypt() ) {
			uint8_t *iuk = this->newKey( KEY_IUK );
			memcpy( iuk, crypt->plain_text, SQRL_KEY_SIZE );
			retVal = true;
			goto DONE;
		}
	}

ERR:
	retVal = false;

DONE:
	sodium_memzero( this->keys->scratch, crypt->text_len + SQRL_KEY_SIZE );
	if( crypt ) delete crypt;
	return retVal;
}

bool SqrlUser::sus_block_2( SqrlAction *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
{
	if (transaction->getUser() != this) return false;
	bool retVal = true;
	if( ! this->hasKey( KEY_IUK )
		|| ! this->hasKey( KEY_RESCUE_CODE )) {
		return false;
	}
	
	SqrlCrypt *crypt = this->_init_t2( transaction, block, true );
	if( !crypt ) {
		goto ERR;
	}

	crypt->key = this->scratch() + crypt->text_len;
	char *rc = (char*)this->key( transaction, KEY_RESCUE_CODE );
	if( !crypt->genKey( transaction, rc, SQRL_RESCUE_CODE_LENGTH ) ) {
	}
	block->seek( 21 );
	block->writeInt32( crypt->count );

	// Cipher Text
	crypt->flags = SQRL_ENCRYPT | SQRL_ITERATIONS;
	uint8_t *iuk = this->key( transaction, KEY_IUK );
	memcpy( crypt->plain_text, iuk, crypt->text_len );
	if( crypt->doCrypt() ) {
		// Save unique id
		std::string str;
		std::string tstr;
		tstr.append( (char*)crypt->cipher_text, SQRL_KEY_SIZE );
		SqrlBase64().encode( &str, &tstr );
		strcpy_s( this->uniqueId, str.data() );

		goto DONE;
	}

ERR:
	retVal = false;

DONE:
	sodium_memzero( this->keys->scratch, crypt->text_len + SQRL_KEY_SIZE );
	if( crypt ) delete crypt;
	return retVal;
}

bool SqrlUser::sul_block_3( SqrlAction *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
{
	if (transaction->getUser() != this) return false;
	bool retVal = true;
	int i;
	SqrlCrypt crypt = SqrlCrypt();
	uint8_t *keyPointer;
	block->seek(0);
	crypt.add = block->getDataPointer();
	crypt.add_len = 4;
	if( block->readInt16() != 148 ||
		block->readInt16() != 3 ) {
		return false;
	}
	crypt.text_len = SQRL_KEY_SIZE * 4;
	crypt.cipher_text = crypt.add + 4;
	crypt.tag = crypt.cipher_text + (SQRL_KEY_SIZE * 4);
	crypt.plain_text = this->keys->scratch;
	crypt.iv = crypt.plain_text + crypt.text_len;
	memset( crypt.iv, 0, 12 );
	keyPointer = this->key( transaction, KEY_MK );
	crypt.flags = SQRL_DECRYPT | SQRL_ITERATIONS;
	if( !crypt.doCrypt() ) goto ERR;

	int pt_offset = 0;
	int piuks[] = { KEY_PIUK0, KEY_PIUK1, KEY_PIUK2, KEY_PIUK3 };
	for( i = 0; i < 4; i++ ) {
		keyPointer = this->newKey( piuks[i] );
		memcpy( keyPointer, crypt.plain_text + pt_offset, SQRL_KEY_SIZE );
		pt_offset += SQRL_KEY_SIZE;
	}
	goto DONE;

ERR:
	retVal = false;

DONE:
	sodium_memzero( this->keys->scratch, crypt.text_len );
	return retVal;

}

bool SqrlUser::sus_block_3( SqrlAction *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
{
	if (transaction->getUser() != this) return false;
	bool retVal = true;
	int i;
	SqrlCrypt crypt = SqrlCrypt();
	uint8_t *keyPointer;
	block->init( 3, 148 );
	crypt.add = block->getDataPointer();
	crypt.add_len = 4;
	block->writeInt16( 148 );
	block->writeInt16( 3 );
	crypt.text_len = SQRL_KEY_SIZE * 4;
	crypt.cipher_text = crypt.add + 4;
	crypt.tag = crypt.cipher_text + (SQRL_KEY_SIZE * 4);
	crypt.plain_text = this->keys->scratch;

	int pt_offset = 0;
	int piuks[] = { KEY_PIUK0, KEY_PIUK1, KEY_PIUK2, KEY_PIUK3 };
	for( i = 0; i < 4; i++ ) {
		if( this->hasKey( piuks[i] )) {
			keyPointer = this->key( transaction, piuks[i] );
			memcpy( crypt.plain_text + pt_offset, keyPointer, SQRL_KEY_SIZE );
		} else {
			memset( crypt.plain_text + pt_offset, 0, SQRL_KEY_SIZE );
		}
		pt_offset += SQRL_KEY_SIZE;
	}
	crypt.iv = crypt.plain_text + pt_offset;
	memset( crypt.iv, 0, 12 );
	keyPointer = this->key( transaction, KEY_MK );
	crypt.count = 100;
	crypt.flags = SQRL_ENCRYPT | SQRL_MILLIS;
	if( !crypt.doCrypt()) {
		goto ERR;
	}
	goto DONE;

ERR:
	retVal = false;

DONE:
	sodium_memzero( this->keys->scratch, crypt.text_len );
	return retVal;
}

bool SqrlUser::sul_block_1( SqrlAction *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
{
	if (transaction->getUser() != this) return false;
	bool retVal = true;
	SqrlCrypt crypt = SqrlCrypt();
    crypt.text_len = SQRL_KEY_SIZE * 2;

	block->seek(0);
	if( block->readInt16() != 125 ) {
		goto ERR;
	}

	// ADD
	crypt.add = block->getDataPointer();
	block->seek( 4 );
	crypt.add_len = block->readInt16();
	if( crypt.add_len != 45 ) {
		goto ERR;
	}
	// IV and Salt
	crypt.iv = block->getDataPointer(true);
	block->seek(12, true);
	crypt.salt = block->getDataPointer(true);
	block->seek(16, true);
	// N Factor
	crypt.nFactor = block->readInt8();
	// Iteration Count
	crypt.count = block->readInt32();
	// Options
	this->options.flags = block->readInt16();
	this->options.hintLength = block->readInt8();
	this->options.enscryptSeconds = block->readInt8();
	this->options.timeoutMinutes = block->readInt16();
	// Cipher Text
	crypt.cipher_text = block->getDataPointer(true);
	// Verification Tag
	crypt.tag = crypt.cipher_text + crypt.text_len;
	// Plain Text
	crypt.plain_text = this->keys->scratch;

	// Iteration Count
	uint8_t *key = crypt.plain_text + crypt.text_len;
	crypt.flags = SQRL_DECRYPT | SQRL_ITERATIONS;
	if( crypt.genKey( transaction, this->keys->password, this->keys->password_len ) 
		&& crypt.doCrypt() ) {
			key = this->newKey( KEY_MK );
			memcpy( key, crypt.plain_text, SQRL_KEY_SIZE );
			key = this->newKey( KEY_ILK );
			memcpy( key, crypt.plain_text + SQRL_KEY_SIZE, SQRL_KEY_SIZE );
			goto DONE;
	}
ERR:
	retVal = false;

DONE:
	sodium_memzero( this->keys->scratch, crypt.text_len + SQRL_KEY_SIZE );
	return retVal;
}

bool SqrlUser::sus_block_1( SqrlAction *transaction, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata )
{
	if (transaction->getUser() != this) return false;
	bool retVal = true;
	SqrlCrypt crypt = SqrlCrypt();
	SqrlClient::getClient()->onAuthenticationRequired( cbdata.transaction, SQRL_CREDENTIAL_PASSWORD );
	// TODO: Verify Password obtained

	uint8_t *keyPointer;
	block->init( 1, 125 );
	// Block Length
	block->writeInt16( 125 );
	// Block Type
	block->writeInt16( 1 );
	// ADD
	crypt.add = block->getDataPointer();
	crypt.add_len = 45;
	block->writeInt16( 45 );
	// IV and Salt
	uint8_t ent[28];
	SqrlEntropy::bytes(ent, 28);
	block->write(ent, 28);
	block->seekBack(28, true);
	crypt.iv = block->getDataPointer(true);
	block->seek(12, true);
	crypt.salt = block->getDataPointer(true);
	block->seek(16, true);
	// N Factor
	crypt.nFactor = SQRL_DEFAULT_N_FACTOR;
	block->writeInt8( crypt.nFactor );
	// Options
	block->seek( 39 );
	block->writeInt16( this->options.flags );
	block->writeInt8( this->options.hintLength );
	block->writeInt8( this->options.enscryptSeconds );
	block->writeInt16( this->options.timeoutMinutes );
	// Cipher Text
	crypt.text_len = SQRL_KEY_SIZE * 2;
	crypt.cipher_text = block->getDataPointer(true);
	// Verification Tag
	block->seek(crypt.text_len, true);
	crypt.tag = block->getDataPointer(true);
	// Plain Text
	crypt.plain_text = this->keys->scratch;
	if( this->hasKey( KEY_MK )) {
		keyPointer = this->key( transaction, KEY_MK );
		memcpy( crypt.plain_text, keyPointer, SQRL_KEY_SIZE );
	} else {
		memset( crypt.plain_text, 0, SQRL_KEY_SIZE );
	}
	if( this->hasKey( KEY_ILK )) {
		keyPointer = this->key( transaction, KEY_ILK );
		memcpy( crypt.plain_text + SQRL_KEY_SIZE, keyPointer, SQRL_KEY_SIZE );
	} else {
		memset( crypt.plain_text + SQRL_KEY_SIZE, 0, SQRL_KEY_SIZE );
	}

	// Iteration Count
	crypt.key = crypt.plain_text + crypt.text_len;
	crypt.flags = SQRL_ENCRYPT | SQRL_MILLIS;
	crypt.count = this->options.enscryptSeconds * SQRL_MILLIS_PER_SECOND;
	if( !crypt.genKey( transaction, this->keys->password, this->keys->password_len ) ) {
		goto ERR;
	}
	block->seek( 35 );
	block->writeInt32( crypt.count );

	// Cipher Text
	crypt.flags = SQRL_ENCRYPT | SQRL_ITERATIONS;
	if( !crypt.doCrypt() ) {
		goto ERR;
	}
	goto DONE;

ERR:
	retVal = false;

DONE:
	sodium_memzero( this->keys->scratch, crypt.text_len + SQRL_KEY_SIZE );
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

bool SqrlUser::updateStorage( SqrlAction *transaction )
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
	std::string buf;
	buf.append( buffer, buffer_len );
	this->storage = SqrlStorage::from( &buf );
	if( this->storage ) {
		this->_load_unique_id();
	}
}

bool SqrlUser::save( SqrlActionSave *transaction )
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

	if (this->updateStorage((SqrlAction*)transaction)) {
		if( this->storage->save( uri, transaction->getExportType(), transaction->getEncodingType())) {
			return true;
		}
	}
	return false;
}

bool SqrlUser::saveToBuffer( SqrlActionSave *transaction )
{
	if( !transaction ) return false;
	if (transaction->getUser() != this) {
		return false;
	}
	bool retVal = true;
	struct Sqrl_User_s_callback_data cbdata;
	cbdata.transaction = transaction;
	cbdata.adder = 0;
	cbdata.multiplier = 1;

	std::string *buf = NULL;
	if( this->updateStorage( transaction )) {
		buf = this->storage->save( transaction->getExportType(), transaction->getEncodingType() );
		if( buf ) {
			transaction->setString( buf->data(), buf->length());
			delete buf;
			goto DONE;
		}
	}

	transaction->setString(NULL, 0);
	retVal = false;

DONE:
	return retVal;
}

bool SqrlUser::tryLoadPassword( SqrlAction *transaction, bool retry )
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
		SqrlClient::getClient()->onAuthenticationRequired(transaction, SQRL_CREDENTIAL_PASSWORD);
		goto LOOP;
	}

DONE:
	block->release();
	return retVal;
}

bool SqrlUser::tryLoadRescue( SqrlAction *transaction, bool retry )
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
		SqrlClient::getClient()->onAuthenticationRequired( transaction, SQRL_CREDENTIAL_RESCUE_CODE );
		goto LOOP;
	}

DONE:
	block->release();
	return retVal;
}


