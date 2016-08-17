/** \file SqrlActionSave.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlActionSave.h"
#include "SqrlUri.h"
#include "SqrlUser.h"
#include "SqrlClient.h"
#include "SqrlStorage.h"
#include "SqrlBlock.h"
#include "SqrlBase64.h"

#define SAS_T1 100
#define SAS_T2 200
#define SAS_T3 300

namespace libsqrl
{
    SqrlActionSave::SqrlActionSave( SqrlUser *user, SqrlUri *uri, Sqrl_Export exportType, Sqrl_Encoding encodingType )
        : SqrlIdentityAction( user ),
        exportType( exportType ),
        encodingType( encodingType ),
        buffer( NULL ),
        buffer_len( 0 ),
        crypt(NULL),
        block(NULL) {
        if( uri ) {
            this->uri = new SqrlUri( uri );
        } else {
            this->uri = NULL;
        }
        double t1ms = user->getEnscryptSeconds() * 1000.0;
        double t2ms = SQRL_RESCUE_ENSCRYPT_SECONDS * 1000.0;
        double total = t1ms + t2ms;
        this->t1per = t1ms / total;
        this->t2per = t2ms / total;

    }

    SqrlActionSave::SqrlActionSave( SqrlUser *user, const char *path, Sqrl_Export exportType, Sqrl_Encoding encodingType )
        : SqrlActionSave( user ) {
        if( path ) {
            SqrlString ps = SqrlString( path );
            this->uri = new SqrlUri( &ps );
        } else {
            this->uri = NULL;
        }
    }

    SqrlActionSave::~SqrlActionSave() {
        if( this->crypt ) delete this->crypt;
        if( this->block ) delete this->block;
    }

    int SqrlActionSave::run( int cs ) {
        SqrlClient *client = SqrlClient::getClient();
        if( this->shouldCancel ) {
            return this->retActionComplete( SQRL_ACTION_CANCELED );
        }
        SqrlString *buf = NULL;

        switch( cs ) {
        case 0:
            if( !this->user ) {
                client->callSelectUser( this );
                return cs;
            }
            NEXT_STATE( cs );
        case 1:
            if( this->user->getPasswordLength() == 0 ) {
                client->callAuthenticationRequired( this, SQRL_CREDENTIAL_NEW_PASSWORD );
                return cs;
            }
            NEXT_STATE( cs );
        case 2:
            if( this->uri ) {
                if( uri->getScheme() != SQRL_SCHEME_FILE ||
                    uri->getChallengeLength() == 0 ) {
                    return this->retActionComplete( SQRL_ACTION_FAIL );
                }
            }
            NEXT_STATE( cs );
        case 3:
            if( this->user->storage == NULL ) {
                this->user->storage = new SqrlStorage();
            }
            TO_STATE( SAS_T1 );
        case 100:
            if( (this->user->flags & USER_FLAG_T1_CHANGED) == USER_FLAG_T1_CHANGED ||
                !this->user->storage->hasBlock( SQRL_BLOCK_USER ) ) {
                if( this->t1_init() ) {
                    NEXT_STATE( cs );
                } else {
                    COMPLETE( SQRL_ACTION_FAIL );
                }
            }
            TO_STATE( SAS_T2 );
        case 101:
            if( this->crypt->genKey_step( this ) ) {
                client->rapid = true;
                SAME_STATE( cs );
            } else {
                NEXT_STATE( cs );
            }
        case 102:
            if( this->t1_finalize() ) {
                this->user->storage->putBlock( this->block );
                delete this->block;
                this->block = NULL;
                TO_STATE( SAS_T2 );
            } else {
                COMPLETE( SQRL_ACTION_FAIL );
            }
        case 200:
            if( (this->user->flags & USER_FLAG_T2_CHANGED) == USER_FLAG_T2_CHANGED ||
                !this->user->storage->hasBlock( SQRL_BLOCK_RESCUE ) ) {
                if( this->t2_init() ) {
                    NEXT_STATE( cs );
                } else {
                    COMPLETE( SQRL_ACTION_FAIL );
                }
            }
            TO_STATE( SAS_T3 );
        case 201:
            if( this->crypt->genKey_step( this ) ) {
                client->rapid = true;
                SAME_STATE( cs );
            } else {
                NEXT_STATE( cs );
            }
        case 202:
            if( this->t2_finalize() ) {
                this->user->storage->putBlock( this->block );
                delete this->block;
                this->block = NULL;
                TO_STATE( SAS_T3 );
            } else {
                COMPLETE( SQRL_ACTION_FAIL );
            }
        case 300:
            if( (this->user->flags & USER_FLAG_T2_CHANGED) == USER_FLAG_T2_CHANGED ||
                !this->user->storage->hasBlock( SQRL_BLOCK_PREVIOUS ) ) {
                this->block = new SqrlBlock();
                if( this->user->saveOrLoadType3Block( this, this->block, true ) ) {
                    this->user->storage->putBlock( this->block );
                }
                delete this->block;
                this->block = NULL;
            }
            NEXT_STATE( cs );
        case 301:
            if( this->uri ) {
                if( this->user->storage->save( uri, this->exportType, this->encodingType ) ) {
                    this->status = SQRL_ACTION_SUCCESS;
                } else {
                    this->status = SQRL_ACTION_FAIL;
                }
            } else {
                buf = this->user->storage->save( this->exportType, this->encodingType );
                if( buf ) {
                    this->setString( buf->cstring(), buf->length() );
                    this->status = SQRL_ACTION_SUCCESS;
                    delete buf;
                } else {
                    this->status = SQRL_ACTION_FAIL;
                }
            }
            NEXT_STATE( cs );
        case 302:
            COMPLETE( this->status );
        default:
            // Invalid State
            COMPLETE( SQRL_ACTION_FAIL );
        }
    }

    bool SqrlActionSave::t1_init() {
        if( !this->user || this->user->getPasswordLength() == 0 ) return false;
        if( this->crypt ) delete this->crypt;
        if( this->block ) delete this->block;
        this->crypt = new SqrlCrypt();
        this->block = new SqrlBlock();
        uint8_t ent[28];
        struct t1scratch *t1s = (struct t1scratch*)this->user->scratch()->data();

        SqrlFixedString *keyString;
        block->init( 1, 125 );
        // ADD
        this->crypt->add = block->getDataPointer();
        this->crypt->add_len = 45;
        block->writeInt16( 45 );
        // IV and Salt
        this->crypt->iv = block->getDataPointer( true );
        SqrlEntropy::bytes( ent, 28 );
        block->write( ent, 12 );
        this->crypt->salt = block->getDataPointer( true );
        block->write( ent + 12, 16 );
        // N Factor
        this->crypt->nFactor = SQRL_DEFAULT_N_FACTOR;
        block->writeInt8( this->crypt->nFactor );
        // Options
        block->seek( 4, true );
        block->writeInt16( this->user->options.flags );
        block->writeInt8( this->user->options.hintLength );
        block->writeInt8( this->user->options.enscryptSeconds );
        block->writeInt16( this->user->options.timeoutMinutes );
        // Cipher Text
        this->crypt->text_len = SQRL_KEY_SIZE * 2;
        this->crypt->cipher_text = block->getDataPointer( true );
        // Verification Tag
        block->seek( this->crypt->text_len, true );
        this->crypt->tag = block->getDataPointer( true );
        // Plain Text
        this->crypt->plain_text = (uint8_t*)t1s;
        if( this->user->hasKey( SQRL_KEY_MK ) ) {
            keyString = this->user->key( this, SQRL_KEY_MK );
            memcpy( t1s->mk, keyString->data(), SQRL_KEY_SIZE );
        } else {
            memset( t1s->mk, 0, SQRL_KEY_SIZE );
        }
        if( this->user->hasKey( SQRL_KEY_ILK ) ) {
            keyString = this->user->key( this, SQRL_KEY_ILK );
            memcpy( t1s->ilk, keyString->data(), SQRL_KEY_SIZE );
        } else {
            memset( t1s->ilk, 0, SQRL_KEY_SIZE );
        }

        // Iteration Count
        this->crypt->key = t1s->key;
        this->crypt->flags = SQRL_ENCRYPT | SQRL_MILLIS;
        this->crypt->count = this->user->options.enscryptSeconds * SQRL_MILLIS_PER_SECOND;
        return this->crypt->genKey_init( this, (*this->user->keys)[SQRL_KEY_PASSWORD] );
    }

    bool SqrlActionSave::t1_finalize() {
        bool retVal = false;
        if( this->crypt->genKey_finalize( this ) ) {
            this->block->seek( 35 );
            this->block->writeInt32( this->crypt->count );
            this->crypt->flags = SQRL_ENCRYPT | SQRL_ITERATIONS;
            retVal = this->crypt->doCrypt();
        }
        sqrl_memzero( this->user->scratch()->data(), sizeof( struct t1scratch ) );
        return retVal;
    }

    bool SqrlActionSave::t2_init() {
        if( !this->user || !this->user->hasKey( SQRL_KEY_RESCUE_CODE ) ) return false;

        if( this->crypt ) delete this->crypt;
        if( this->block ) delete this->block;

        struct t2scratch *t2s = (struct t2scratch*)this->user->scratch()->data();
        SqrlFixedString *iuk = this->user->key( this, SQRL_KEY_IUK );
        SqrlFixedString *str = NULL;

        if( iuk ) {
            memcpy( t2s->iuk, iuk->data(), SQRL_KEY_SIZE );
        } else {
            return false;
        }

        this->crypt = new SqrlCrypt();
        this->crypt->plain_text = t2s->iuk;
        this->crypt->text_len = SQRL_KEY_SIZE;
        this->crypt->key = t2s->key;

        this->block = new SqrlBlock();
        this->block->init( 2, 73 );
        SqrlEntropy::bytes( this->block->getDataPointer( true ), 16 );
        this->block->seek( 16, true );
        this->crypt->nFactor = SQRL_DEFAULT_N_FACTOR;
        this->block->writeInt8( this->crypt->nFactor );
        this->crypt->flags = SQRL_ENCRYPT | SQRL_MILLIS;
        this->crypt->count = SQRL_RESCUE_ENSCRYPT_SECONDS * SQRL_MILLIS_PER_SECOND;

        this->crypt->add = this->block->getDataPointer();
        this->crypt->add_len = 25;
        this->crypt->iv = NULL;
        this->crypt->salt = this->crypt->add + 4;
        this->crypt->cipher_text = this->crypt->add + this->crypt->add_len;
        this->crypt->tag = this->crypt->cipher_text + this->crypt->text_len;

        str = this->user->key( this, SQRL_KEY_RESCUE_CODE );
        return this->crypt->genKey_init( this, str );
    }

    bool SqrlActionSave::t2_finalize() {
        if( !this->crypt || !this->block ) return false;
        if( this->crypt->genKey_finalize( this ) ) {
            this->block->seek( 21 );
            this->block->writeInt32( this->crypt->count );

            // Cipher Text
            this->crypt->flags = SQRL_ENCRYPT | SQRL_ITERATIONS;
            SqrlFixedString *iuk = this->user->key( this, SQRL_KEY_IUK );
            if( iuk ) {
                memcpy( this->crypt->plain_text, iuk->data(), this->crypt->text_len );
                if( this->crypt->doCrypt() ) {
                    // Save unique id
                    SqrlString tstr( (char*)this->crypt->cipher_text, SQRL_KEY_SIZE );
                    SqrlBase64().encode( &this->user->uniqueId, &tstr );
                    sqrl_memzero( this->user->scratch()->data(), sizeof( struct t2scratch ) );
                    return true;
                }
            }
        }
        return false;
    }
    
    void SqrlActionSave::onProgress( int progress ) {
        if( this->state < SAS_T2 ) {
            progress = (int)(progress * this->t1per);
        } else {
            progress = (int)((progress * this->t2per) + (100 * this->t1per));
        }
        SqrlClient *client = SqrlClient::getClient();
        client->callProgress( this, progress );
    }

    Sqrl_Export SqrlActionSave::getExportType() {
        return this->exportType;
    }

    void SqrlActionSave::setExportType( Sqrl_Export type ) {
        this->exportType = type;
    }

    Sqrl_Encoding SqrlActionSave::getEncodingType() {
        return this->encodingType;
    }

    void SqrlActionSave::setEncodingType( Sqrl_Encoding type ) {
        this->encodingType = type;
    }

    void SqrlActionSave::onRelease() {
        if( this->buffer ) { free( this->buffer ); }
        SqrlIdentityAction::onRelease();
    }

    size_t SqrlActionSave::getString( char *buf, size_t *len ) {
        size_t retVal = this->buffer_len;
        if( this->buffer ) {
            if( buf && len && *len ) {
                if( retVal < *len ) {
                    memcpy( buf, this->buffer, retVal );
                    buf[retVal] = 0;
                    *len = retVal;
                } else {
                    memcpy( buf, this->buffer, *len );
                }
            }
        }
        return retVal;
    }

    void SqrlActionSave::setString( const char *buf, size_t len ) {
        if( this->buffer ) {
            free( this->buffer );
        }
        this->buffer = NULL;
        this->buffer_len = 0;
        if( buf && len > 0 ) {
            this->buffer = (char*)malloc( len + 1 );
            if( this->buffer ) {
                memcpy( this->buffer, buf, len );
                this->buffer[len] = 0;
                this->buffer_len = len;
            }
        }
    }
}