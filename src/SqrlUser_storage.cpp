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
#pragma pack(push)
#pragma pack(1)
    struct t1scratch
    {
        uint8_t mk[SQRL_KEY_SIZE];
        uint8_t ilk[SQRL_KEY_SIZE];
        uint8_t key[SQRL_KEY_SIZE];
    };
    struct t2scratch
    {
        uint8_t iuk[SQRL_KEY_SIZE];
        uint8_t key[SQRL_KEY_SIZE];
    };
    struct t3scratch
    {
        uint8_t piuks[4][SQRL_KEY_SIZE];
        uint8_t key[SQRL_KEY_SIZE];
    };
#pragma pack(pop)

    bool SqrlUser::saveOrLoadType2Block(
        SqrlAction *action,
        SqrlBlock *block,
        bool saving ) {
        if( !block || !action ) return false;
        if( action->getUser() != this ) return false;
        if( !this->hasKey( SQRL_KEY_RESCUE_CODE ) ) return false;

        SqrlCrypt crypt = SqrlCrypt();

        struct t2scratch *t2s = (struct t2scratch*)this->scratch()->data();
        crypt.plain_text = t2s->iuk;
        crypt.text_len = SQRL_KEY_SIZE;
        crypt.key = t2s->key;

        if( saving ) {
            if( !this->hasKey( SQRL_KEY_IUK )
                || !this->hasKey( SQRL_KEY_RESCUE_CODE ) ) {
                return false;
            }
            block->init( 2, 73 );
            SqrlEntropy::bytes( block->getDataPointer( true ), 16 );
            block->seek( 16, true );
            crypt.nFactor = SQRL_DEFAULT_N_FACTOR;
            block->writeInt8( crypt.nFactor );
            SqrlFixedString *iuk = this->key( action, SQRL_KEY_IUK );
            if( iuk ) {
                memcpy( crypt.plain_text, iuk->data(), SQRL_KEY_SIZE );
            }
            crypt.flags = SQRL_ENCRYPT | SQRL_MILLIS;
            crypt.count = SQRL_RESCUE_ENSCRYPT_SECONDS * SQRL_MILLIS_PER_SECOND;
        } else {
            block->seek( 0 );
            if( 73 != block->readInt16() ||
                2 != block->readInt16() ) {
                return false;
            }
            block->seek( 20 );
            crypt.nFactor = block->readInt8();
            crypt.flags = SQRL_DECRYPT | SQRL_ITERATIONS;
            crypt.count = block->readInt32();
        }

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
                if( saving ) {
                    block->seek( 21 );
                    block->writeInt32( crypt.count );

                    // Cipher Text
                    crypt.flags = SQRL_ENCRYPT | SQRL_ITERATIONS;
                    SqrlFixedString *iuk = this->key( action, SQRL_KEY_IUK );
                    if( iuk ) {
                        memcpy( crypt.plain_text, iuk->data(), crypt.text_len );
                        if( crypt.doCrypt() ) {
                            // Save unique id
                            SqrlString tstr( (char*)crypt.cipher_text, SQRL_KEY_SIZE );
                            SqrlBase64().encode( &this->uniqueId, &tstr );
                            sqrl_memzero( t2s, sizeof( struct t2scratch ) );
                            return true;
                        }
                    }
                } else {
                    SqrlFixedString *str = (*this->keys)[SQRL_KEY_IUK];
                    if( str ) {
                        str->clear();
                        str->append( t2s->iuk, SQRL_KEY_SIZE );
                        sqrl_memzero( t2s, sizeof( struct t2scratch ) );
                        return true;
                    }
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

    bool SqrlUser::saveType1Block( SqrlAction *action, SqrlBlock *block ) {
        if( action->getUser() != this ) return false;
        bool retVal = false;
        if( this->getPasswordLength() == 0 ) {
            return false;
        }

        SqrlCrypt crypt = SqrlCrypt();
        uint8_t ent[28];
        struct t1scratch *t1s = (struct t1scratch*)this->scratch()->data();

        SqrlFixedString *keyString;
        block->init( 1, 125 );
        // ADD
        crypt.add = block->getDataPointer();
        crypt.add_len = 45;
        block->writeInt16( 45 );
        // IV and Salt
        crypt.iv = block->getDataPointer( true );
        SqrlEntropy::bytes( ent, 28 );
        block->write( ent, 12 );
        crypt.salt = block->getDataPointer( true );
        block->write( ent + 12, 16 );
        // N Factor
        crypt.nFactor = SQRL_DEFAULT_N_FACTOR;
        block->writeInt8( crypt.nFactor );
        // Options
        block->seek( 4, true );
        block->writeInt16( this->options.flags );
        block->writeInt8( this->options.hintLength );
        block->writeInt8( this->options.enscryptSeconds );
        block->writeInt16( this->options.timeoutMinutes );
        // Cipher Text
        crypt.text_len = SQRL_KEY_SIZE * 2;
        crypt.cipher_text = block->getDataPointer( true );
        // Verification Tag
        block->seek( crypt.text_len, true );
        crypt.tag = block->getDataPointer( true );
        // Plain Text
        crypt.plain_text = (uint8_t*)t1s;
        if( this->hasKey( SQRL_KEY_MK ) ) {
            keyString = this->key( action, SQRL_KEY_MK );
            memcpy( t1s->mk, keyString->data(), SQRL_KEY_SIZE );
        } else {
            memset( t1s->mk, 0, SQRL_KEY_SIZE );
        }
        if( this->hasKey( SQRL_KEY_ILK ) ) {
            keyString = this->key( action, SQRL_KEY_ILK );
            memcpy( t1s->ilk, keyString->data(), SQRL_KEY_SIZE );
        } else {
            memset( t1s->ilk, 0, SQRL_KEY_SIZE );
        }

        // Iteration Count
        crypt.key = t1s->key;
        crypt.flags = SQRL_ENCRYPT | SQRL_MILLIS;
        crypt.count = this->options.enscryptSeconds * SQRL_MILLIS_PER_SECOND;
        
        if( crypt.genKey( action, (*this->keys)[SQRL_KEY_PASSWORD] ) ) {
            block->seek( 35 );
            block->writeInt32( crypt.count );

            // Cipher Text
            crypt.flags = SQRL_ENCRYPT | SQRL_ITERATIONS;
            retVal = crypt.doCrypt();
        }
        sqrl_memzero( t1s, sizeof( struct t1scratch ) );
        return retVal;
    }

    bool SqrlUser::updateStorage( SqrlAction *action ) {
        if( !action ) return false;
        if( action->getUser() != this ) {
            return false;
        }
        if( this->storage == NULL ) {
            this->storage = new SqrlStorage();
        }

        SqrlBlock block = SqrlBlock();
        bool retVal = true;

        if( (this->flags & USER_FLAG_T1_CHANGED) == USER_FLAG_T1_CHANGED ||
            !this->storage->hasBlock( SQRL_BLOCK_USER ) ) {
            if( saveType1Block( action, &block ) ) {
                this->storage->putBlock( &block );
            }
        }

        if( (this->flags & USER_FLAG_T2_CHANGED) == USER_FLAG_T2_CHANGED ||
            !this->storage->hasBlock( SQRL_BLOCK_RESCUE ) ) {
            if( this->saveOrLoadType2Block( action, &block, true ) ) {
                this->storage->putBlock( &block );
            }
        }

        if( (this->flags & USER_FLAG_T2_CHANGED) == USER_FLAG_T2_CHANGED ||
            !this->storage->hasBlock( SQRL_BLOCK_PREVIOUS ) ) {
            if( this->saveOrLoadType3Block( action, &block, true ) ) {
                this->storage->putBlock( &block );
            }
        }
        return retVal;
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

    bool SqrlUser::save( SqrlActionSave *action ) {
        if( !action ) return false;

        SqrlUri *uri = action->getUri();
        if( !uri || (uri->getScheme() != SQRL_SCHEME_FILE) ) {
            return false;
        }
        if( action->getUser() != this ) {
            return false;
        }
        if( uri->getChallengeLength() == 0 ) {
            return false;
        }

        if( this->updateStorage( (SqrlAction*)action ) ) {
            if( this->storage->save( uri, action->getExportType(), action->getEncodingType() ) ) {
                return true;
            }
        }
        return false;
    }

    bool SqrlUser::saveToBuffer( SqrlActionSave *action ) {
        if( !action ) return false;
        if( action->getUser() != this ) {
            return false;
        }
        /*
        struct Sqrl_User_s_callback_data cbdata;
        cbdata.action = action;
        cbdata.adder = 0;
        cbdata.multiplier = 1;
        */

        SqrlString *buf = NULL;
        if( this->updateStorage( action ) ) {
            buf = this->storage->save( action->getExportType(), action->getEncodingType() );
            if( buf ) {
                action->setString( buf->cstring(), buf->length() );
                delete buf;
                return true;
            }
        }

        action->setString( NULL, 0 );
        return false;
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
        if( !this->saveOrLoadType2Block( action, &block, false ) ) {
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
