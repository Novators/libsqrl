/** \file SqrlUser.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include <new>
#include "sqrl_internal.h"
#include "SqrlUser.h"
#include "SqrlAction.h"
#include "SqrlClient.h"
#include "SqrlCrypt.h"
#include "SqrlEntropy.h"
#include "SqrlActionLock.h"
#include "SqrlStorage.h"
#include "SqrlDeque.h"
#include "SqrlBigInt.h"
#include "SqrlUri.h"

namespace libsqrl
{
    void SqrlUser::ensureKeysAllocated() {
        if( this->keys == NULL ) {
            this->keys = new SqrlKeySet();
            FLAG_CLEAR( this->flags, USER_FLAG_MEMLOCKED );
        }
    }

    SqrlUser::SqrlUser() {
#ifndef ARDUINO
		SqrlClient *client = SqrlClient::getClient();
#endif
		SqrlUser::defaultOptions( &this->options );
		this->keys = NULL;
		this->storage = NULL;
		this->tag = NULL;
		this->edition = 0;
		SQRL_MUTEX_LOCK( &client->userMutex );
		client->users.push( this );
		SQRL_MUTEX_UNLOCK( &client->userMutex );
	}

	SqrlUser::SqrlUser( SqrlUri *uri ) : SqrlUser() {
		if( uri->getScheme() != SQRL_SCHEME_FILE ) {
			return;
		}
		this->storage = new SqrlStorage( uri );
		if( this->storage ) {
			this->_load_unique_id();
			// TODO: Load Options
		}
	}

	SqrlUser::SqrlUser( const char *buffer, size_t buffer_len ) : SqrlUser() {
		SqrlString buf( buffer, buffer_len );
		this->storage = new SqrlStorage( &buf );
		if( this->storage ) {
			this->_load_unique_id();
		}
	}

    SqrlUser::~SqrlUser() {
		SqrlClient *client = SqrlClient::getClient();
		if( client ) {
			SQRL_MUTEX_LOCK( &client->actionMutex );
			size_t i, end = client->actions.count();
			for( i = 0; i < end; i++ ) {
				SqrlAction *action = client->actions.peek( i );
				if( action->getUser() == this ) {
					action->setUser( NULL );
					action->cancel();
				}
			}
			SQRL_MUTEX_UNLOCK( &client->actionMutex );
			SQRL_MUTEX_LOCK( &client->userMutex );
			client->users.erase( this );
			SQRL_MUTEX_UNLOCK( &client->userMutex );
		}
        if( this->keys ) {
            delete this->keys;
        }
        if( this->storage ) {
            delete this->storage;
        }
    }

    bool SqrlUser::isMemLocked() {
        if( FLAG_CHECK( this->flags, USER_FLAG_MEMLOCKED ) ) {
            return true;
        }
        return false;
    }

    bool SqrlUser::isHintLocked() {
        if( this->hint_iterations == 0 ) return false;
        return true;
    }

    void SqrlUser::hintUnlock( SqrlAction *action, SqrlString *hint ) {
        if( hint == NULL || hint->length() == 0 ) {
            SqrlClient::getClient()->callAuthenticationRequired( action, SQRL_CREDENTIAL_HINT );
            return;
        }
        if( !action ) return;
        if( action->getUser() != this || !this->isHintLocked() ) {
            return;
        }
        /*
        struct Sqrl_User_s_callback_data cbdata;
        cbdata.action = action;
        cbdata.adder = 0;
        cbdata.multiplier = 1;
        */

        SqrlFixedString *scratch = (*this->keys)[SQRL_KEY_SCRATCH];
        SqrlCrypt crypt = SqrlCrypt();
        uint8_t iv[12] = {0};
        crypt.plain_text = (uint8_t*)(*this->keys)[0];
        crypt.text_len = (uint16_t)((uint8_t*)scratch - crypt.plain_text);
        crypt.salt = scratch->data();
        crypt.tag = scratch->data() + 16;
        crypt.cipher_text = scratch->data() + 64;
        crypt.iv = iv;
        crypt.add = NULL;
        crypt.add_len = 0;
        crypt.nFactor = SQRL_DEFAULT_N_FACTOR;
        crypt.count = this->hint_iterations;
        crypt.flags = SQRL_DECRYPT | SQRL_ITERATIONS;

        uint8_t *key = scratch->data() + 32;
        if( !crypt.genKey( action, hint ) ||
            !crypt.doCrypt() ) {
            sqrl_memzero( crypt.plain_text, crypt.text_len );
        }
        this->hint_iterations = 0;
        sqrl_memzero( key, SQRL_KEY_SIZE );
        (*this->keys)[SQRL_KEY_SCRATCH]->secureClear();
    }

    static void bin2rc( SqrlString *buf, SqrlString *bin ) {
        SqrlBigInt src = SqrlBigInt( bin );
        int i;
        buf->clear();
        for( i = 0; i < 24; i++ ) {
            buf->append( src.divideBy( 10 ) + '0', 1 );
        }
    }

    bool SqrlUser::_keyGen( SqrlAction *action, int key_type ) {
        if( !action ) return false;
        if( action->getUser() != this ) {
            return false;
        }
        bool retVal = false;
        int curKey;
        SqrlFixedString *cur, *prev;
        switch( key_type ) {
        case SQRL_KEY_IUK:
            if( this->hasKey( SQRL_KEY_IUK ) ) {
                this->edition++;
                curKey = SQRL_KEY_PIUK3;
                do {
                    cur = (*this->keys)[curKey];
                    prev = (*this->keys)[curKey - 1];
                    cur->clear();
                    if( prev->length() ) cur->append( prev );
                    curKey--;
                } while( curKey > SQRL_KEY_PIUK0 );
                cur = (*this->keys)[SQRL_KEY_PIUK0];
                prev = (*this->keys)[SQRL_KEY_IUK];
                cur->clear();
                cur->append( prev );
            } else {
                this->edition = 0;
                prev = (*this->keys)[SQRL_KEY_IUK];
            }
            prev->clear();
            prev->appendEntropy( SQRL_KEY_SIZE );
            retVal = true;
            break;
        case SQRL_KEY_MK:
            cur = (*this->keys)[SQRL_KEY_MK];
            cur->clear();
            prev = (*this->keys)[SQRL_KEY_IUK];
            if( prev->length() == SQRL_KEY_SIZE ) {
                cur->append( (char)0, SQRL_KEY_SIZE );
                SqrlCrypt::generateMasterKey( cur->data(), prev->data() );
                retVal = true;
            }
            break;
        case SQRL_KEY_ILK:
            cur = (*this->keys)[SQRL_KEY_ILK];
            cur->clear();
            prev = (*this->keys)[SQRL_KEY_IUK];
            if( prev->length() == SQRL_KEY_SIZE ) {
                cur->append( (char)0, SQRL_KEY_SIZE );
                SqrlCrypt::generateIdentityLockKey( cur->data(), prev->data() );
                retVal = true;
            }
            break;
        case SQRL_KEY_LOCAL:
            cur = (*this->keys)[SQRL_KEY_LOCAL];
            cur->clear();
            prev = (*this->keys)[SQRL_KEY_MK];
            if( prev->length() == SQRL_KEY_SIZE ) {
                cur->append( (char)0, SQRL_KEY_SIZE );
                SqrlCrypt::generateLocalKey( cur->data(), prev->data() );
                retVal = true;
            }
            break;
        case SQRL_KEY_RESCUE_CODE:
            cur = (*this->keys)[SQRL_KEY_RESCUE_CODE];
            prev = (*this->keys)[SQRL_KEY_SCRATCH];
            prev->clear();
            prev->appendEntropy( 32 );
            bin2rc( cur, prev );
            retVal = true;
            break;
        }
        return retVal;
    }

    bool SqrlUser::regenKeys( SqrlAction *action ) {
        if( !action ) return false;
        if( action->getUser() != this ) {
            return false;
        }
        this->_keyGen( action, SQRL_KEY_MK );
        this->_keyGen( action, SQRL_KEY_ILK );
        this->_keyGen( action, SQRL_KEY_LOCAL );
        return true;
    }

    bool SqrlUser::rekey( SqrlAction *action ) {
        if( !action ) return false;
        if( action->getUser() != this ) {
            return false;
        }
        this->ensureKeysAllocated();
        if( this->_keyGen( action, SQRL_KEY_IUK ) &&
            this->_keyGen( action, SQRL_KEY_RESCUE_CODE ) &&
            this->regenKeys( action )) {
            this->flags |= (USER_FLAG_T1_CHANGED | USER_FLAG_T2_CHANGED);
            return true;
        }
        return false;
    }

    SqrlFixedString *SqrlUser::key( SqrlAction *action, int key_type ) {
        if( !action ) return NULL;
        if( action->getUser() != this ) {
            return NULL;
        }
        SqrlFixedString *ret = NULL;
        int loop = -1;
        for( loop = 0; loop < 3; loop++ ) {
            ret = (*this->keys)[key_type];
            if( ret->length() ) {
                return ret;
            }
            switch( key_type ) {
            case SQRL_KEY_RESCUE_CODE:
                // We cannot regenerate this key!
                return NULL;
            case SQRL_KEY_IUK:
                this->tryLoadRescue( action, true );
                continue;
            case SQRL_KEY_MK:
            case SQRL_KEY_ILK:
            case SQRL_KEY_PIUK0:
            case SQRL_KEY_PIUK1:
            case SQRL_KEY_PIUK2:
            case SQRL_KEY_PIUK3:
                this->tryLoadPassword( action, true );
                continue;
            }
        }
        if( ret && ret->length() ) return ret;
        return NULL;
    }

    bool SqrlUser::hasKey( int key_type ) {
        SqrlFixedString *key = (*this->keys)[key_type];
        return (key && key->length());
    }

    void SqrlUser::removeKey( int key_type ) {
        SqrlFixedString *key = (*this->keys)[key_type];
        if( key ) {
            key->secureClear();
        }
    }

    char *SqrlUser::getRescueCode( SqrlAction *action ) {
        if( !action ) return NULL;
        if( action->getUser() != this ) return NULL;
        return (*this->keys)[SQRL_KEY_RESCUE_CODE]->string();
    }

    bool SqrlUser::setRescueCode( char *rc ) {
        if( strlen( rc ) != SQRL_RESCUE_CODE_LENGTH ) return false;
        int i;
        for( i = 0; i < SQRL_RESCUE_CODE_LENGTH; i++ ) {
            if( rc[i] < '0' || rc[i] > '9' ) {
                return false;
            }
        }
        SqrlFixedString *m = (*this->keys)[SQRL_KEY_RESCUE_CODE];
        if( m ) {
            m->clear();
            m->append( rc, SQRL_RESCUE_CODE_LENGTH );
            return true;
        }
        return false;
    }

    bool SqrlUser::forceDecrypt( SqrlAction *t ) {
        if( t && this->key( t, SQRL_KEY_MK ) ) {
            return true;
        }
        return false;
    }

	void * SqrlUser::getTag() {
		return this->tag;
	}

	void SqrlUser::setTag( void * tag ) {
		this->tag = tag;
	}

    bool SqrlUser::forceRescue( SqrlAction *t ) {
        if( !t ) return false;
        if( this->key( t, SQRL_KEY_IUK ) ) {
            return true;
        }
        return false;
    }

    size_t SqrlUser::getPasswordLength() {
        if( this->isHintLocked() ) return 0;
        SqrlFixedString *pw = (*this->keys)[SQRL_KEY_PASSWORD];
        if( pw ) {
            return pw->length();
        }
        return 0;
    }

    bool SqrlUser::setPassword( const char *password, size_t password_len ) {
        if( this->isHintLocked() ) return false;
        SqrlFixedString *pw = (*this->keys)[SQRL_KEY_PASSWORD];
        if( pw ) {
            if( pw->length() ) {
                FLAG_SET( this->flags, USER_FLAG_T1_CHANGED );
            }
            pw->secureClear();
            pw->append( password, password_len );
            return true;
        }
        return false;
    }

    SqrlFixedString *SqrlUser::scratch() {
        this->ensureKeysAllocated();
        return (*this->keys)[SQRL_KEY_SCRATCH];
    }

    uint8_t SqrlUser::getHintLength() {
        uint8_t retVal = 0;
        retVal = this->options.hintLength;
        return retVal;
    }

    uint8_t SqrlUser::getEnscryptSeconds() {
        uint8_t retVal = 0;
        retVal = this->options.enscryptSeconds;
        return retVal;
    }

    uint16_t SqrlUser::getTimeoutMinutes() {
        uint16_t retVal = 0;
        retVal = this->options.timeoutMinutes;
        return retVal;
    }

    void SqrlUser::setHintLength( uint8_t length ) {
        this->options.hintLength = length;
        FLAG_SET( this->flags, USER_FLAG_T1_CHANGED );
    }

    void SqrlUser::setEnscryptSeconds( uint8_t seconds ) {
        this->options.enscryptSeconds = seconds;
        FLAG_SET( this->flags, USER_FLAG_T1_CHANGED );
    }

    void SqrlUser::setTimeoutMinutes( uint16_t minutes ) {
        this->options.timeoutMinutes = minutes;
        FLAG_SET( this->flags, USER_FLAG_T1_CHANGED );
    }

    uint16_t SqrlUser::getFlags() {
        return this->options.flags;
    }

    uint16_t SqrlUser::checkFlags( uint16_t flags ) {
        uint16_t retVal = 0;
        retVal = this->options.flags & flags;
        return retVal;
    }

    void SqrlUser::setFlags( uint16_t flags ) {
        if( (this->options.flags & flags) != flags ) {
            this->options.flags |= flags;
            FLAG_SET( this->flags, USER_FLAG_T1_CHANGED );
        }
    }

    void SqrlUser::clearFlags( uint16_t flags ) {
        if( (this->flags & flags) != 0 ) {
            this->options.flags &= ~flags;
            FLAG_SET( this->flags, USER_FLAG_T1_CHANGED );
        }
    }

    void SqrlUser::defaultOptions( Sqrl_User_Options *options ) {
        options->flags = SQRL_DEFAULT_FLAGS;
        options->hintLength = SQRL_DEFAULT_HINT_LENGTH;
        options->enscryptSeconds = SQRL_DEFAULT_ENSCRYPT_SECONDS;
        options->timeoutMinutes = SQRL_DEFAULT_TIMEOUT_MINUTES;
    }

    bool SqrlUser::getUniqueId( char *buffer ) {
        if( !buffer ) return false;
        if( this->uniqueId.length() == SQRL_UNIQUE_ID_LENGTH ) {
            strcpy( buffer, this->uniqueId.cstring() );
            return true;
        }
        return false;
    }

    bool SqrlUser::uniqueIdMatches( const char *unique_id ) {
        if( !unique_id ) return false;
        return(0 == this->uniqueId.compare( unique_id ));
    }
}
