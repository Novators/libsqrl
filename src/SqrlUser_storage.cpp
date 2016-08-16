/** \file SqrlUser_storage.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
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

namespace libsqrl
{
    bool SqrlUser::loadType2Block(
        SqrlAction *action,
        SqrlBlock *block ) {
        if( !block || !action ) return false;
        if( action->getUser() != this ) return false;
        if( !this->hasKey( SQRL_KEY_RESCUE_CODE ) ) return false;

        SqrlCrypt crypt = SqrlCrypt();

        struct t2scratch *t2s = (struct t2scratch*)this->scratch()->data();
        crypt.plain_text = t2s->iuk;
        crypt.text_len = SQRL_KEY_SIZE;
        crypt.key = t2s->key;

        block->seek( 0 );
        if( 73 != block->readInt16() ||
            2 != block->readInt16() ) {
            return false;
        }
        block->seek( 20 );
        crypt.nFactor = block->readInt8();
        crypt.flags = SQRL_DECRYPT | SQRL_ITERATIONS;
        crypt.count = block->readInt32();

        crypt.add = block->getDataPointer();
        crypt.add_len = 25;
        crypt.iv = NULL;
        crypt.salt = crypt.add + 4;
        crypt.cipher_text = crypt.add + crypt.add_len;
        crypt.tag = crypt.cipher_text + crypt.text_len;

        SqrlFixedString *str;
        str = this->key( action, SQRL_KEY_RESCUE_CODE );
        if( str ) {
            if( crypt.genKey( action, str ) && crypt.doCrypt() ) {
                SqrlFixedString *str = (*this->keys)[SQRL_KEY_IUK];
                if( str ) {
                    str->clear();
                    str->append( t2s->iuk, SQRL_KEY_SIZE );
                    sqrl_memzero( t2s, sizeof( struct t2scratch ) );
                    return true;
                }
            }
        }
        sqrl_memzero( t2s, sizeof( struct t2scratch ) );
        return false;
    }

    bool SqrlUser::saveOrLoadType3Block(
        SqrlAction *action,
        SqrlBlock *block,
        bool saving ) {
        if( action->getUser() != this ) return false;
        
        SqrlCrypt crypt = SqrlCrypt();
        struct t3scratch *t3s = (struct t3scratch*)this->scratch()->data();
        int piuks[] = {SQRL_KEY_PIUK0, SQRL_KEY_PIUK1, SQRL_KEY_PIUK2, SQRL_KEY_PIUK3};

        if( saving ) {
            block->init( 3, 148 );
        } else {
            block->seek( 0 );
            if( block->readInt16() != 148 ||
                block->readInt16() != 3 ) {
                return false;
            }
        }

        crypt.add = block->getDataPointer();
        crypt.add_len = 4;
        crypt.text_len = SQRL_KEY_SIZE * 4;
        crypt.cipher_text = crypt.add + 4;
        crypt.tag = crypt.cipher_text + crypt.text_len;
        crypt.plain_text = (uint8_t*)t3s;
        crypt.iv = crypt.plain_text + crypt.text_len;
        memset( crypt.iv, 0, 12 );
        crypt.flags = SQRL_DECRYPT | SQRL_ITERATIONS;

        if( saving ) {
            for( int i = 0; i < 4; i++ ) {
                SqrlFixedString *str = (*this->keys)[piuks[i]];
                if( str && str->length() == SQRL_KEY_SIZE ) {
                    memcpy( t3s->piuks[i], str->data(), SQRL_KEY_SIZE );
                } else {
                    memset( t3s->piuks[i], 0, SQRL_KEY_SIZE );
                }
            }
            crypt.count = 100;
            crypt.flags = SQRL_ENCRYPT | SQRL_MILLIS;
        }

        SqrlFixedString *mk = this->key( action, SQRL_KEY_MK );
        if( mk && mk->length() == SQRL_KEY_SIZE ) {
            memcpy( t3s->key, mk->data(), SQRL_KEY_SIZE );
            crypt.key = t3s->key;

            if( crypt.doCrypt() ) {
                if( !saving ) {
                    for( int i = 0; i < 4; i++ ) {
                        SqrlFixedString *str = this->key( action, piuks[i] );
                        str->clear();
                        str->append( t3s->piuks[i], SQRL_KEY_SIZE );
                    }
                }
                sqrl_memzero( t3s, sizeof( struct t3scratch ) );
                return true;
            }
        }
        sqrl_memzero( t3s, sizeof( struct t3scratch ) );
        return false;
    }

    bool SqrlUser::loadType1Block( SqrlAction *action, SqrlBlock *block ) {
        if( !action || !block ) return false;
        if( action->getUser() != this ) return false;
        if( block->readInt16( 0 ) != 125 ) return false;
        if( block->readInt16( 4 ) != 45 ) return false;

        SqrlFixedString *pw, *key;
        SqrlCrypt crypt = SqrlCrypt();
        crypt.text_len = SQRL_KEY_SIZE * 2;
        struct t1scratch *t1s = (struct t1scratch*)this->scratch()->data();
        Sqrl_User_Options tmpOptions;

        // ADD
        crypt.add = block->getDataPointer();
        crypt.add_len = 45;

        // IV and Salt
        block->seek( 6 );
        crypt.iv = block->getDataPointer( true );
        block->seek( 12, true );
        crypt.salt = block->getDataPointer( true );
        block->seek( 16, true );
        // N Factor
        crypt.nFactor = block->readInt8();
        // Iteration Count
        crypt.count = block->readInt32();
        // Options
        tmpOptions.flags = block->readInt16();
        tmpOptions.hintLength = block->readInt8();
        tmpOptions.enscryptSeconds = block->readInt8();
        tmpOptions.timeoutMinutes = block->readInt16();
        // Cipher Text
        crypt.cipher_text = block->getDataPointer( true );
        // Verification Tag
        crypt.tag = crypt.cipher_text + crypt.text_len;
        // Plain Text
        crypt.plain_text = (uint8_t*)t1s;

        // Iteration Count
        crypt.flags = SQRL_DECRYPT | SQRL_ITERATIONS;
        pw = this->key( action, SQRL_KEY_PASSWORD );
        if( crypt.genKey( action, pw )
            && crypt.doCrypt() ) {
            key = (*this->keys)[SQRL_KEY_MK];
            key->clear();
            key->append( t1s->mk, SQRL_KEY_SIZE );
            key = (*this->keys)[SQRL_KEY_ILK];
            key->clear();
            key->append( t1s->ilk + SQRL_KEY_SIZE, SQRL_KEY_SIZE );
            this->options.flags = tmpOptions.flags;
            this->options.hintLength = tmpOptions.hintLength;
            this->options.enscryptSeconds = tmpOptions.enscryptSeconds;
            this->options.timeoutMinutes = tmpOptions.timeoutMinutes;
            sqrl_memzero( t1s, sizeof( struct t1scratch ) );
            return true;
        }
        sqrl_memzero( t1s, sizeof( struct t1scratch ) );
        return false;
    }

    void SqrlUser::_load_unique_id() {
        if( this->storage ) {
            this->storage->getUniqueId( &this->uniqueId );
        }
    }

    SqrlUser::SqrlUser( SqrlUri *uri ) {
        this->initialize();
        if( uri->getScheme() != SQRL_SCHEME_FILE ) {
            return;
        }
        this->storage = new SqrlStorage( uri );
        if( this->storage ) {
            this->_load_unique_id();
            // TODO: Load Options
        }
    }

    SqrlUser::SqrlUser( const char *buffer, size_t buffer_len ) {
        this->initialize();
        SqrlString buf( buffer, buffer_len );
        this->storage = new SqrlStorage( &buf );
        if( this->storage ) {
            this->_load_unique_id();
        }
    }

    bool SqrlUser::tryLoadPassword( SqrlAction *action, bool retry ) {
        if( !action ) return false;
        if( action->getUser() != this ) {
            return false;
        }
        bool retVal = false;
        SqrlBlock block = SqrlBlock();
    LOOP:
        if( !this->storage->hasBlock( SQRL_BLOCK_USER ) ) {
            retVal = this->tryLoadRescue( action, retry );
            goto DONE;
        }
        if( !this->hasKey( SQRL_KEY_PASSWORD ) ) {
            goto NEEDAUTH;
        }

        this->storage->getBlock( &block, SQRL_BLOCK_USER );
        if( !loadType1Block( action, &block ) ) {
            goto NEEDAUTH;
        }
        if( this->storage->hasBlock( SQRL_BLOCK_PREVIOUS ) &&
            this->storage->getBlock( &block, SQRL_BLOCK_PREVIOUS ) ) {
            this->saveOrLoadType3Block( action, &block, false );
        }
        retVal = true;
        goto DONE;

    NEEDAUTH:
        if( retry ) {
            retry = false;
            SqrlClient::getClient()->callAuthenticationRequired( action, SQRL_CREDENTIAL_PASSWORD );
            goto LOOP;
        }

    DONE:
        return retVal;
    }

    bool SqrlUser::tryLoadRescue( SqrlAction *action, bool retry ) {
        if( !action ) return false;
        if( action->getUser() != this ) {
            return false;
        }
        bool retVal = false;
        SqrlBlock block = SqrlBlock();

    LOOP:
        if( !this->storage->hasBlock( SQRL_BLOCK_RESCUE ) ) {
            goto DONE;
        }
        if( !this->hasKey( SQRL_KEY_RESCUE_CODE ) ) {
            goto NEEDAUTH;
        }

        this->storage->getBlock( &block, SQRL_BLOCK_RESCUE );
        if( !this->loadType2Block( action, &block ) ) {
            goto NEEDAUTH;
        }
        this->regenKeys( action );
        if( this->storage->hasBlock( SQRL_BLOCK_PREVIOUS ) &&
            this->storage->getBlock( &block, SQRL_BLOCK_PREVIOUS ) ) {
            this->saveOrLoadType3Block( action, &block, false );
        }
        goto DONE;

    NEEDAUTH:
        if( retry ) {
            retry = false;
            SqrlClient::getClient()->callAuthenticationRequired( action, SQRL_CREDENTIAL_RESCUE_CODE );
            goto LOOP;
        }

    DONE:
        return retVal;
    }
}
