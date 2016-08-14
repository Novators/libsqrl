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

namespace libsqrl
{
    struct SqrlUserList
    {
        SqrlUser *user;
        struct SqrlUserList *next;
    };

    struct SqrlUserList *SQRL_USER_LIST;

    int SqrlUser::enscryptCallback( int percent, void *data ) {
        struct Sqrl_User_s_callback_data *cbdata = (struct Sqrl_User_s_callback_data*)data;
        if( cbdata ) {
            int progress = cbdata->adder + (int)((double)percent * cbdata->multiplier);
            if( progress > 100 ) progress = 100;
            if( progress < 0 ) progress = 0;
            if( percent == 100 && progress >= 99 ) progress = 100;
            SqrlClient::getClient()->onProgress( cbdata->action, progress );
            return 0;
        } else {
            return 1;
        }
    }

    SqrlUser *SqrlUser::create() {
        SqrlUser *user = (SqrlUser*)malloc( sizeof( SqrlUser ) );
        new (user) SqrlUser();
        return user;
    }

    SqrlUser *SqrlUser::create( const char *buffer, size_t buffer_len ) {
        SqrlUser *user = (SqrlUser*)malloc( sizeof( SqrlUser ) );
        new (user) SqrlUser( buffer, buffer_len );
        return user;
    }

    SqrlUser *SqrlUser::create( SqrlUri *uri ) {
        SqrlUser *user = (SqrlUser*)malloc( sizeof( SqrlUser ) );
        new (user) SqrlUser();
        return user;
    }

    void SqrlUser::ensureKeysAllocated() {
        if( this->keys == NULL ) {
            this->keys = new SqrlKeySet();
            FLAG_CLEAR( this->flags, USER_FLAG_MEMLOCKED );
        }
    }

    SqrlUser* SqrlUser::find( const char *unique_id ) {
        SqrlUser *user = NULL;
        struct SqrlUserList *l;
#ifndef ARDUINO
        SqrlClient *client = SqrlClient::getClient();
#endif
        SQRL_MUTEX_LOCK( &client->userMutex )
            l = SQRL_USER_LIST;
        while( l ) {
            if( l->user && l->user->uniqueIdMatches( unique_id ) ) {
                user = l->user;
                user->hold();
                break;
            }
            l = l->next;
        }
        SQRL_MUTEX_UNLOCK( &client->userMutex )
            return user;
    }

    void SqrlUser::initialize() {
#ifndef ARDUINO
        SqrlClient *client = SqrlClient::getClient();
#endif
        SqrlUser::defaultOptions( &this->options );
        this->referenceCount = 1;
        this->keys = NULL;
        this->storage = NULL;
        struct SqrlUserList *l = (struct SqrlUserList*)calloc( 1, sizeof( struct SqrlUserList ) );
        if( l ) {
            l->user = this;
            SQRL_MUTEX_LOCK( &client->userMutex )
                l->next = SQRL_USER_LIST;
            SQRL_USER_LIST = l;
            SQRL_MUTEX_UNLOCK( &client->userMutex )
        }
    }

    SqrlUser::SqrlUser() {
        this->initialize();
    }

    int SqrlUser::countUsers() {
#ifndef ARDUINO
        SqrlClient *client = SqrlClient::getClient();
#endif
        SQRL_MUTEX_LOCK( &client->userMutex )
            int i = 0;
        struct SqrlUserList *list = SQRL_USER_LIST;
        while( list ) {
            i++;
            list = list->next;
        }
        SQRL_MUTEX_UNLOCK( &client->userMutex )
            return i;
    }

    void SqrlUser::hold() {
#ifndef ARDUINO
        SqrlClient *client = SqrlClient::getClient();
        client->userMutex.lock();
#endif
        // Make sure the user is still in active memory...
        struct SqrlUserList *c = SQRL_USER_LIST;
        while( c ) {
            if( c->user == this ) {
                SQRL_MUTEX_LOCK( &this->referenceCountMutex )
                    this->referenceCount++;
                SQRL_MUTEX_UNLOCK( &this->referenceCountMutex )
                    break;
            }
            c = c->next;
        }
#ifndef ARDUINO
        client->userMutex.unlock();
#endif
    }

    void SqrlUser::release() {
#ifndef ARDUINO
        SqrlClient *client = SqrlClient::getClient();
#endif
        bool shouldFreeThis = false;
        SQRL_MUTEX_LOCK( &client->userMutex )
            struct SqrlUserList *list = SQRL_USER_LIST;
        if( list == NULL ) {
            // Not saved in memory... Go ahead and release it.
            SQRL_MUTEX_UNLOCK( &client->userMutex )
                shouldFreeThis = true;
            goto END;
        }
        struct SqrlUserList *prev;
        if( list->user == this ) {
            prev = NULL;
        } else {
            prev = list;
            list = NULL;
            while( prev ) {
                if( prev->next && prev->next->user == this ) {
                    list = prev->next;
                    break;
                }
                prev = prev->next;
            }
        }
        if( list == NULL ) {
            // Not saved in memory... Go ahead and release it.
            SQRL_MUTEX_LOCK( &client->userMutex )
                shouldFreeThis = true;
            goto END;
        }
        // Release this reference
        SQRL_MUTEX_LOCK( &this->referenceCountMutex )
            this->referenceCount--;

        if( this->referenceCount > 0 ) {
            // There are other references... Do not delete.
            SQRL_MUTEX_UNLOCK( &this->referenceCountMutex )
                SQRL_MUTEX_UNLOCK( &client->userMutex )
                goto END;
        }
        SQRL_MUTEX_UNLOCK( &this->referenceCountMutex );
        // There were no other references... We can delete this.
        shouldFreeThis = true;

        if( prev == NULL ) {
            SQRL_USER_LIST = list->next;
        } else {
            prev->next = list->next;
        }
        free( list );
        SQRL_MUTEX_UNLOCK( &client->userMutex )

            END:
        if( shouldFreeThis ) {
            delete(this);
        }
    }

    SqrlUser::~SqrlUser() {
        if( this->keys ) {
            delete this->keys;
        }
        if( this->storage ) {
            this->storage->release();
        }
    }

    bool SqrlUser::isMemLocked() {
        if( FLAG_CHECK( this->flags, USER_FLAG_MEMLOCKED ) ) {
            return true;
        }
        return false;
    }

    void SqrlUser::memLock() {
#ifndef ARDUINO
        if( this->keys != NULL ) {
            sqrl_mprotect_noaccess( this->keys );
        }
#endif
        FLAG_SET( this->flags, USER_FLAG_MEMLOCKED );
    }

    void SqrlUser::memUnlock() {
#ifndef ARDUINO
        if( this->keys != NULL ) {
            sqrl_mprotect_readwrite( this->keys );
        }
#endif
        FLAG_CLEAR( this->flags, USER_FLAG_MEMLOCKED );
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
        struct Sqrl_User_s_callback_data cbdata;
        cbdata.action = action;
        cbdata.adder = 0;
        cbdata.multiplier = 1;

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

    static void bin2rc( char *buf, uint8_t *bin ) {
        // bin must be 512+ bits of entropy!
        int i, j, k;
        uint64_t *tmp = (uint64_t*)bin;
        for( i = 0, j = 0; i < 3; i++ ) {
            for( k = 0; k < 8; k++ ) {
                buf[j++] = '0' + (tmp[k] % 10);
                tmp[k] /= 10;
            }
        }
        buf[j] = 0;
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
            curKey = SQRL_KEY_PIUK3;
            do {
                cur = (*this->keys)[curKey];
                prev = (*this->keys)[curKey - 1];
                cur->clear();
                cur->append( prev );
                curKey--;
            } while( curKey > SQRL_KEY_PIUK0 );
            cur = (*this->keys)[SQRL_KEY_PIUK0];
            prev = (*this->keys)[SQRL_KEY_IUK];
            cur->clear();
            cur->append( prev );
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
            cur->clear();
            prev = (*this->keys)[SQRL_KEY_SCRATCH];
            prev->clear();
            prev->appendEntropy( 512 );
            cur->append( (char)0, SQRL_RESCUE_CODE_LENGTH );
            bin2rc( cur->string(), prev->data() );
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
        bool retVal = true;
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
        memcpy( buffer, this->uniqueId, SQRL_UNIQUE_ID_LENGTH );
        buffer[SQRL_UNIQUE_ID_LENGTH] = 0;
        return true;
    }

    bool SqrlUser::uniqueIdMatches( const char *unique_id ) {
        bool retVal = false;
        if( unique_id == NULL ) {
            if( this->uniqueId[0] == 0 ) {
                retVal = true;
            }
        } else {
            if( 0 == strcmp( unique_id, this->uniqueId ) ) {
                retVal = true;
            }
        }
        return retVal;
    }
}
