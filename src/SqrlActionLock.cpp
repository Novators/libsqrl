/** \file SqrlActionLock.cpp
 *
 * \author Adam Comley
 * 
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlActionLock.h"

#include "SqrlClient.h"
#include "SqrlUser.h"

SqrlActionLock::SqrlActionLock( SqrlUser *user) : SqrlIdentityAction( user ) {

}

int SqrlActionLock::run( int cs ) {
	size_t password_len;
	uint8_t *key = NULL;
	SqrlClient *client = SqrlClient::getClient();
	if( this->shouldCancel ) {
		return this->retActionComplete( SQRL_ACTION_CANCELED );
	}

	switch( this->state ) {
	case 0:
		if( !this->user ) {
			client->callSelectUser( this );
			return cs;
		}
		return cs + 1;
	case 1:
		if( this->user->isHintLocked() ) {
			return this->retActionComplete( SQRL_ACTION_SUCCESS );
		}
		return cs + 1;
	case 2:
		if( !this->user->keys || this->user->keys->password_len == 0 ) {
			// locking not required
			return this->retActionComplete( SQRL_ACTION_SUCCESS );
		}
		this->cbdata.action = this;
		this->cbdata.adder = 0;
		this->cbdata.multiplier = 1;
		crypt.plain_text = this->user->keys->keys[0];
		crypt.text_len = sizeof( struct Sqrl_Keys ) - KEY_SCRATCH_SIZE;
		crypt.salt = this->user->keys->scratch;
		crypt.iv = this->iv;
		crypt.tag = this->user->keys->scratch + 16;
		crypt.cipher_text = this->user->keys->scratch + 64;
		crypt.add = NULL;
		crypt.add_len = 0;
		crypt.nFactor = SQRL_DEFAULT_N_FACTOR;
		crypt.count = this->user->options.enscryptSeconds * SQRL_MILLIS_PER_SECOND;
		crypt.flags = SQRL_ENCRYPT | SQRL_MILLIS;

		sqrl_randombytes( crypt.salt, 16 );
		key = this->user->keys->scratch + 32;
		password_len = this->user->options.hintLength;
		if( password_len == 0 || this->user->keys->password_len < password_len ) {
			password_len = this->user->keys->password_len;
		}

		if( crypt.genKey( this, this->user->keys->password, password_len ) ) {
			this->user->hint_iterations = crypt.count;
		}
		if( this->user->hint_iterations <= 0 ||
			!crypt.doCrypt() ) {
			// Encryption failed!
			this->user->hint_iterations = 0;
			sqrl_memzero( this->user->keys->scratch, KEY_SCRATCH_SIZE );
			return this->retActionComplete( SQRL_ACTION_FAIL );
		}
		sqrl_memzero( crypt.plain_text, crypt.text_len );
		sqrl_memzero( key, SQRL_KEY_SIZE );
		return this->retActionComplete( SQRL_ACTION_SUCCESS );
	default:
		return this->retActionComplete( SQRL_ACTION_FAIL );
	}
}
