/** \file SqrlActionLock.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlActionLock.h"
#include "SqrlFixedString.h"
#include "SqrlMLockedString.h"

#include "SqrlClient.h"
#include "SqrlUser.h"

namespace libsqrl
{
    SqrlActionLock::SqrlActionLock( SqrlUser *user ) : SqrlIdentityAction( user ) {

    }

    int SqrlActionLock::run( int cs ) {
        size_t password_len;
        uint8_t *key = NULL;
        SqrlClient *client = SqrlClient::getClient();
        SqrlFixedString *str;
        SqrlFixedString *scratch = (*this->user->keys)[SQRL_KEY_SCRATCH];
        SqrlMLockedString *pw;

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
            if( !this->user->keys || this->user->key( this, SQRL_KEY_PASSWORD )->length() == 0 ) {
                // locking not required
                return this->retActionComplete( SQRL_ACTION_SUCCESS );
            }
            crypt.plain_text = (uint8_t*)(*this->user->keys)[0];
            crypt.text_len = (uint16_t)((uint8_t*)scratch - crypt.plain_text);
            crypt.salt = scratch->data();
            crypt.iv = this->iv;
            crypt.tag = scratch->data() + 16;
            crypt.cipher_text = scratch->data() + 64;
            crypt.add = NULL;
            crypt.add_len = 0;
            crypt.nFactor = SQRL_DEFAULT_N_FACTOR;
            crypt.count = this->user->options.enscryptSeconds * SQRL_MILLIS_PER_SECOND;
            crypt.flags = SQRL_ENCRYPT | SQRL_MILLIS;

            sqrl_randombytes( crypt.salt, 16 );
            key = scratch->data() + 32;
            password_len = this->user->options.hintLength;
            str = (*this->user->keys)[SQRL_KEY_PASSWORD];

            if( password_len == 0 || str->length() < password_len ) {
                password_len = str->length();
            }

            pw = new SqrlMLockedString( str );
            pw->erase( password_len, pw->length() - password_len );
            if( crypt.genKey( this, pw ) ) {
                this->user->hint_iterations = crypt.count;
            }
            delete pw;

            if( this->user->hint_iterations <= 0 ||
                !crypt.doCrypt() ) {
                // Encryption failed!
                this->user->hint_iterations = 0;
                this->user->key( this, SQRL_KEY_SCRATCH )->secureClear();
                return this->retActionComplete( SQRL_ACTION_FAIL );
            }
            sqrl_memzero( crypt.plain_text, crypt.text_len );
            sqrl_memzero( key, SQRL_KEY_SIZE );
            return this->retActionComplete( SQRL_ACTION_SUCCESS );
        default:
            return this->retActionComplete( SQRL_ACTION_FAIL );
        }
    }
}