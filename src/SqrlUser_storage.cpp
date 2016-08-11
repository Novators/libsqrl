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
    SqrlCrypt* SqrlUser::_init_t2(
        SqrlAction *action,
        SqrlBlock *block,
        bool forSaving ) {
        if( action->getUser() != this ) return NULL;
        SqrlCrypt *crypt = new SqrlCrypt();
        SqrlFixedString *iuk;
        crypt->plain_text = this->scratch()->data();
        crypt->text_len = SQRL_KEY_SIZE;
        if( forSaving ) {
            if( !block->init( 2, 73 ) ) {
                delete crypt;
                return NULL;
            }
            block->writeInt16( 73 );
            block->writeInt16( 2 );
            uint8_t ent[16];
            SqrlEntropy::bytes( ent, 16 );
            block->write( ent, 16 );
            crypt->nFactor = SQRL_DEFAULT_N_FACTOR;
            block->writeInt8( SQRL_DEFAULT_N_FACTOR );
            iuk = this->key( action, SQRL_KEY_IUK );
            if( iuk ) {
                memcpy( crypt->plain_text, iuk->data(), SQRL_KEY_SIZE );
            }
            crypt->flags = SQRL_ENCRYPT | SQRL_MILLIS;
            crypt->count = SQRL_RESCUE_ENSCRYPT_SECONDS * SQRL_MILLIS_PER_SECOND;
        } else {
            block->seek( 0 );
            if( 73 != block->readInt16() ||
                2 != block->readInt16() ) {
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

    bool SqrlUser::sul_block_2( SqrlAction *action, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata ) {
        if( action->getUser() != this ) return false;
        bool retVal = false;
        SqrlFixedString *str = NULL;
        if( !this->hasKey( SQRL_KEY_RESCUE_CODE ) ) {
            return false;
        }

        SqrlCrypt *crypt = this->_init_t2( action, block, false );
        if( !crypt ) {
            goto ERR;
        }

        crypt->key = this->scratch()->data() + crypt->text_len;
        block->seek( 21 );
        crypt->count = block->readInt32();
        crypt->flags = SQRL_DECRYPT | SQRL_ITERATIONS;
        str = this->key( action, SQRL_KEY_RESCUE_CODE );
        if( crypt->genKey( action, str ) ) {
            if( crypt->doCrypt() ) {
                str = (*this->keys)[SQRL_KEY_IUK];
                str->clear();
                str->append( crypt->plain_text, SQRL_KEY_SIZE );
                retVal = true;
                goto DONE;
            }
        }

    ERR:
        retVal = false;

    DONE:
        this->key( action, SQRL_KEY_SCRATCH )->secureClear();
        if( crypt ) {
            delete crypt;
        }
        return retVal;
    }

    bool SqrlUser::sus_block_2( SqrlAction *action, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata ) {
        if( action->getUser() != this ) return false;
        bool retVal = true;
        uint8_t *iuk;
        SqrlFixedString *rc = NULL;
        if( !this->hasKey( SQRL_KEY_IUK )
            || !this->hasKey( SQRL_KEY_RESCUE_CODE ) ) {
            return false;
        }

        SqrlCrypt *crypt = this->_init_t2( action, block, true );
        if( !crypt ) {
            goto ERR;
        }

        crypt->key = this->scratch()->data() + crypt->text_len;
        rc = this->key( action, SQRL_KEY_RESCUE_CODE );
        if( !crypt->genKey( action, rc ) ) {
            goto ERR;
        }
        block->seek( 21 );
        block->writeInt32( crypt->count );

        // Cipher Text
        crypt->flags = SQRL_ENCRYPT | SQRL_ITERATIONS;
        iuk = this->key( action, SQRL_KEY_IUK )->data();
        memcpy( crypt->plain_text, iuk, crypt->text_len );
        if( crypt->doCrypt() ) {
            // Save unique id
            SqrlString str;
            SqrlString tstr( (char*)crypt->cipher_text, SQRL_KEY_SIZE );
            SqrlBase64().encode( &str, &tstr );
            memcpy( this->uniqueId, str.cdata(), str.length() );
            this->uniqueId[str.length()] = 0;

            goto DONE;
        }

    ERR:
        retVal = false;

    DONE:
        (*this->keys)[SQRL_KEY_SCRATCH]->secureClear();
        if( crypt ) {
            delete crypt;
        }
        return retVal;
    }

    bool SqrlUser::sul_block_3( SqrlAction *action, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata ) {
        if( action->getUser() != this ) return false;
        bool retVal = true;
        int i, pt_offset = 0;
        int piuks[] = {SQRL_KEY_PIUK0, SQRL_KEY_PIUK1, SQRL_KEY_PIUK2, SQRL_KEY_PIUK3};
        SqrlFixedString *str;

        SqrlCrypt crypt = SqrlCrypt();
        block->seek( 0 );
        crypt.add = block->getDataPointer();
        crypt.add_len = 4;
        if( block->readInt16() != 148 ||
            block->readInt16() != 3 ) {
            return false;
        }
        crypt.text_len = SQRL_KEY_SIZE * 4;
        crypt.cipher_text = crypt.add + 4;
        crypt.tag = crypt.cipher_text + (SQRL_KEY_SIZE * 4);
        crypt.plain_text = this->key( action, SQRL_KEY_SCRATCH )->data();
        crypt.iv = crypt.plain_text + crypt.text_len;
        memset( crypt.iv, 0, 12 );
        crypt.key = this->key( action, SQRL_KEY_MK )->data();
        crypt.flags = SQRL_DECRYPT | SQRL_ITERATIONS;
        if( crypt.doCrypt() ) {
            for( i = 0; i < 4; i++ ) {
                str = this->key( action, piuks[i] );
                str->clear();
                str->append( crypt.plain_text + pt_offset, SQRL_KEY_SIZE );
                pt_offset += SQRL_KEY_SIZE;
            }
        } else {
            retVal = false;
        }
        this->key( action, SQRL_KEY_SCRATCH )->secureClear();
        return retVal;
    }

    bool SqrlUser::sus_block_3( SqrlAction *action, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata ) {
        if( action->getUser() != this ) return false;
        bool retVal = true;
        int i;
        SqrlCrypt crypt = SqrlCrypt();
        SqrlFixedString *keyString;
        block->init( 3, 148 );
        crypt.add = block->getDataPointer();
        crypt.add_len = 4;
        block->writeInt16( 148 );
        block->writeInt16( 3 );
        crypt.text_len = SQRL_KEY_SIZE * 4;
        crypt.cipher_text = crypt.add + 4;
        crypt.tag = crypt.cipher_text + (SQRL_KEY_SIZE * 4);
        crypt.plain_text = (*this->keys)[SQRL_KEY_SCRATCH]->data();

        int pt_offset = 0;
        int piuks[] = {SQRL_KEY_PIUK0, SQRL_KEY_PIUK1, SQRL_KEY_PIUK2, SQRL_KEY_PIUK3};
        for( i = 0; i < 4; i++ ) {
            keyString = (*this->keys)[piuks[i]];
            if( keyString->length() == SQRL_KEY_SIZE ) {
                memcpy( crypt.plain_text + pt_offset, keyString->data(), SQRL_KEY_SIZE );
            } else {
                memset( crypt.plain_text + pt_offset, 0, SQRL_KEY_SIZE );
            }
            pt_offset += SQRL_KEY_SIZE;
        }
        crypt.iv = crypt.plain_text + pt_offset;
        memset( crypt.iv, 0, 12 );
        crypt.count = 100;
        crypt.flags = SQRL_ENCRYPT | SQRL_MILLIS;
        if( !crypt.doCrypt() ) {
            goto ERR;
        }
        goto DONE;

    ERR:
        retVal = false;

    DONE:
        (*this->keys)[SQRL_KEY_SCRATCH]->secureClear();
        return retVal;
    }

    bool SqrlUser::sul_block_1( SqrlAction *action, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata ) {
        if( action->getUser() != this ) return false;
        bool retVal = true;
        SqrlFixedString *pw, *key;
        SqrlCrypt crypt = SqrlCrypt();
        crypt.text_len = SQRL_KEY_SIZE * 2;

        block->seek( 0 );
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
        crypt.iv = block->getDataPointer( true );
        block->seek( 12, true );
        crypt.salt = block->getDataPointer( true );
        block->seek( 16, true );
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
        crypt.cipher_text = block->getDataPointer( true );
        // Verification Tag
        crypt.tag = crypt.cipher_text + crypt.text_len;
        // Plain Text
        crypt.plain_text = (*this->keys)[SQRL_KEY_SCRATCH]->data();

        // Iteration Count
        crypt.flags = SQRL_DECRYPT | SQRL_ITERATIONS;
        pw = this->key( action, SQRL_KEY_PASSWORD );
        if( crypt.genKey( action, pw )
            && crypt.doCrypt() ) {
            key = (*this->keys)[SQRL_KEY_MK];
            key->clear();
            key->append( crypt.plain_text, SQRL_KEY_SIZE );
            key = (*this->keys)[SQRL_KEY_ILK];
            key->clear();
            key->append( crypt.plain_text + SQRL_KEY_SIZE, SQRL_KEY_SIZE );
            goto DONE;
        }
    ERR:
        retVal = false;

    DONE:
        (*this->keys)[SQRL_KEY_SCRATCH]->secureClear();
        return retVal;
    }

    bool SqrlUser::sus_block_1( SqrlAction *action, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata ) {
        if( action->getUser() != this ) return false;
        bool retVal = true;
        SqrlCrypt crypt = SqrlCrypt();
        if( this->getPasswordLength() == 0 ) {
            return false;
        }

        SqrlFixedString *keyString;
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
        SqrlEntropy::bytes( ent, 28 );
        block->write( ent, 28 );
        block->seekBack( 28, true );
        crypt.iv = block->getDataPointer( true );
        block->seek( 12, true );
        crypt.salt = block->getDataPointer( true );
        block->seek( 16, true );
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
        crypt.cipher_text = block->getDataPointer( true );
        // Verification Tag
        block->seek( crypt.text_len, true );
        crypt.tag = block->getDataPointer( true );
        // Plain Text
        crypt.plain_text = (*this->keys)[SQRL_KEY_SCRATCH]->data();
        if( this->hasKey( SQRL_KEY_MK ) ) {
            keyString = this->key( action, SQRL_KEY_MK );
            memcpy( crypt.plain_text, keyString->data(), SQRL_KEY_SIZE );
        } else {
            memset( crypt.plain_text, 0, SQRL_KEY_SIZE );
        }
        if( this->hasKey( SQRL_KEY_ILK ) ) {
            keyString = this->key( action, SQRL_KEY_ILK );
            memcpy( crypt.plain_text + SQRL_KEY_SIZE, keyString->data(), SQRL_KEY_SIZE );
        } else {
            memset( crypt.plain_text + SQRL_KEY_SIZE, 0, SQRL_KEY_SIZE );
        }

        // Iteration Count
        crypt.key = crypt.plain_text + crypt.text_len;
        crypt.flags = SQRL_ENCRYPT | SQRL_MILLIS;
        crypt.count = this->options.enscryptSeconds * SQRL_MILLIS_PER_SECOND;
        
        if( !crypt.genKey( action, (*this->keys)[SQRL_KEY_PASSWORD] ) ) {
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
        (*this->keys)[SQRL_KEY_SCRATCH]->secureClear();
        return retVal;
    }

    void SqrlUser::saveCallbackData( struct Sqrl_User_s_callback_data *cbdata ) {
        SqrlUser *user = cbdata->action->getUser();
        if( !user ) return;
        cbdata->adder = 0;
        cbdata->multiplier = 1;
        cbdata->total = 0;
        cbdata->t1 = 0;
        cbdata->t2 = 0;
        int eS = (int)user->getEnscryptSeconds();
        bool t1 = user->checkFlags( USER_FLAG_T1_CHANGED ) == USER_FLAG_T1_CHANGED;
        bool t2 = user->checkFlags( USER_FLAG_T2_CHANGED ) == USER_FLAG_T2_CHANGED;
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

    bool SqrlUser::updateStorage( SqrlAction *action ) {
        if( !action ) return false;
        if( action->getUser() != this ) {
            return false;
        }
        if( this->storage == NULL ) {
            this->storage = SqrlStorage::empty();
        }
        struct Sqrl_User_s_callback_data cbdata;
        memset( &cbdata, 0, sizeof( struct Sqrl_User_s_callback_data ) );
        cbdata.action = action;
        this->saveCallbackData( &cbdata );

        SqrlBlock *block = SqrlBlock::create();
        bool retVal = true;

        if( (this->flags & USER_FLAG_T1_CHANGED) == USER_FLAG_T1_CHANGED ||
            !this->storage->hasBlock( SQRL_BLOCK_USER ) ) {
            if( sus_block_1( action, block, cbdata ) ) {
                this->storage->putBlock( block );
            }
        }

        if( (this->flags & USER_FLAG_T2_CHANGED) == USER_FLAG_T2_CHANGED ||
            !this->storage->hasBlock( SQRL_BLOCK_RESCUE ) ) {
            cbdata.adder = cbdata.t1;
            if( cbdata.total > cbdata.t2 ) {
                cbdata.adder = (cbdata.t1 * 100 / cbdata.total);
                cbdata.multiplier = (cbdata.t2 / (double)cbdata.total);
            } else {
                cbdata.multiplier = 1;
            }
            if( sus_block_2( action, block, cbdata ) ) {
                this->storage->putBlock( block );
            }
        }

        if( (this->flags & USER_FLAG_T2_CHANGED) == USER_FLAG_T2_CHANGED ||
            !this->storage->hasBlock( SQRL_BLOCK_PREVIOUS ) ) {
            if( sus_block_3( action, block, cbdata ) ) {
                this->storage->putBlock( block );
            }
        }
        block->release();
        return retVal;
    }

    void SqrlUser::_load_unique_id() {
        if( this->storage ) {
            this->storage->getUniqueId( this->uniqueId );
        }
    }

    SqrlUser::SqrlUser( SqrlUri *uri ) {
        this->initialize();
        if( uri->getScheme() != SQRL_SCHEME_FILE ) {
            return;
        }
        this->storage = SqrlStorage::from( uri );
        if( this->storage ) {
            this->_load_unique_id();
            // TODO: Load Options
        }
    }

    SqrlUser::SqrlUser( const char *buffer, size_t buffer_len ) {
        this->initialize();
        SqrlString buf( buffer, buffer_len );
        this->storage = SqrlStorage::from( &buf );
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
        bool retVal = true;
        struct Sqrl_User_s_callback_data cbdata;
        cbdata.action = action;
        cbdata.adder = 0;
        cbdata.multiplier = 1;

        SqrlString *buf = NULL;
        if( this->updateStorage( action ) ) {
            buf = this->storage->save( action->getExportType(), action->getEncodingType() );
            if( buf ) {
                action->setString( buf->cstring(), buf->length() );
                delete buf;
                goto DONE;
            }
        }

        action->setString( NULL, 0 );
        retVal = false;

    DONE:
        return retVal;
    }

    bool SqrlUser::tryLoadPassword( SqrlAction *action, bool retry ) {
        if( !action ) return false;
        if( action->getUser() != this ) {
            return false;
        }
        bool retVal = false;
        SqrlBlock *block = SqrlBlock::create();
        struct Sqrl_User_s_callback_data cbdata;
        cbdata.action = action;
        cbdata.adder = 0;
        cbdata.multiplier = 1;
    LOOP:
        if( !this->storage->hasBlock( SQRL_BLOCK_USER ) ) {
            retVal = this->tryLoadRescue( action, retry );
            goto DONE;
        }
        if( !this->hasKey( SQRL_KEY_PASSWORD ) ) {
            goto NEEDAUTH;
        }

        this->storage->getBlock( block, SQRL_BLOCK_USER );
        if( !sul_block_1( action, block, cbdata ) ) {
            goto NEEDAUTH;
        }
        if( this->storage->hasBlock( SQRL_BLOCK_PREVIOUS ) &&
            this->storage->getBlock( block, SQRL_BLOCK_PREVIOUS ) ) {
            sul_block_3( action, block, cbdata );
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
        block->release();
        return retVal;
    }

    bool SqrlUser::tryLoadRescue( SqrlAction *action, bool retry ) {
        if( !action ) return false;
        if( action->getUser() != this ) {
            return false;
        }
        bool retVal = false;
        struct Sqrl_User_s_callback_data cbdata;
        cbdata.action = action;
        cbdata.adder = 0;
        cbdata.multiplier = 1;
        SqrlBlock *block = SqrlBlock::create();

    LOOP:
        if( !this->storage->hasBlock( SQRL_BLOCK_RESCUE ) ) {
            goto DONE;
        }
        if( !this->hasKey( SQRL_KEY_RESCUE_CODE ) ) {
            goto NEEDAUTH;
        }

        this->storage->getBlock( block, SQRL_BLOCK_RESCUE );
        if( !sul_block_2( action, block, cbdata ) ) {
            goto NEEDAUTH;
        }
        this->regenKeys( action );
        if( this->storage->hasBlock( SQRL_BLOCK_PREVIOUS ) &&
            this->storage->getBlock( block, SQRL_BLOCK_PREVIOUS ) ) {
            sul_block_3( action, block, cbdata );
        }
        goto DONE;

    NEEDAUTH:
        if( retry ) {
            retry = false;
            SqrlClient::getClient()->callAuthenticationRequired( action, SQRL_CREDENTIAL_RESCUE_CODE );
            goto LOOP;
        }

    DONE:
        block->release();
        return retVal;
    }
}
