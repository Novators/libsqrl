#include "SqrlEnScrypt.h"
/** \file SqrlEnScrypt.cpp
*
* \author Adam Comley
*
* This file is part of libsqrl.  It is released under the MIT license.
* For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlEnScrypt.h"

namespace libsqrl
{
    ////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Constructor.</summary>
///
/// <param name="action">			If non-null, the action.</param>
/// <param name="password">			The password.</param>
/// <param name="salt">				The salt.</param>
/// <param name="count">			Number of iterations or milliseconds.</param>
/// <param name="countIsIterations">If 'count' is iterations, true.  If milliseconds, false.</param>
/// <param name="nFactor">			The N-Factor.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
    SqrlEnScrypt::SqrlEnScrypt( const SqrlAction *action, const SqrlString * password, const SqrlString * salt, uint16_t count, bool countIsIterations, uint8_t nFactor ) {
        this->action = action;
        this->result = new SqrlString( 32 );
        const uint8_t *thePassword = NULL;
        size_t password_len = 0;
        if( password ) {
            this->password = new SqrlString( password );
            thePassword = this->password->cdata();
            password_len = this->password->length();
        }
        const uint8_t *theSalt = salt ? salt->cdata() : NULL;
        size_t salt_len = salt ? salt->length() : 0;
        this->count = count;
        this->countIsIterations = countIsIterations;
        this->N = (((uint64_t)1) << nFactor);
        isComplete = false;

#ifdef ARDUINO
        SHA256 sha = SHA256();
        sha.update( this->password.cdata(), this->password.length() );
        uint8_t buf[SQRL_KEY_SIZE];
        sha.finalize( buf, SQRL_KEY_SIZE );
        this->result = new SqrlString( buf, SQRL_KEY_SIZE );
        this->isComplete = true;
        return true;
#else
        this->local = (void*)malloc( sizeof( escrypt_local_t ) );
        if( escrypt_init_local( (escrypt_local_t*)this->local ) ) {
            this->didError = true;
            this->done();
            return;
        }
        this->escrypt_kdf = (void*)(sodium_runtime_has_sse2() ? escrypt_kdf_sse : escrypt_kdf_nosse);
        this->startTime = sqrl_get_real_time();

        this->iCount = 1;
        int retVal = ((escrypt_kdf_t)this->escrypt_kdf)((escrypt_local_t*)this->local, thePassword, password_len, theSalt, salt_len, this->N, ENSCRYPT_R, ENSCRYPT_P, t[1], 32);
        if( retVal != 0 ) {
            this->done();
            return;
        }
        memcpy( this->result->data(), this->t[1], 32 );
#endif
    }

    SqrlEnScrypt::~SqrlEnScrypt() {
        if( this->result ) {
            delete this->result;
        }
        if( this->password ) {
            delete this->password;
        }
        if( this->local ) {
            escrypt_free_local( (escrypt_local_t*)this->local );
            free( this->local );
            this->local = NULL;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Query if this SqrlEnScrypt is finished.</summary>
    ///
    /// <returns>true if finished, false if not.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    bool SqrlEnScrypt::isFinished() {
        return this->isComplete;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Query if this SqrlEnScrypt is successful.</summary>
    ///
    /// <returns>true if successful, false if not.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    bool SqrlEnScrypt::isSuccessful() {
        if( !this->isComplete ) return false;
        return !this->didError;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the result.</summary>
    ///
    /// <remarks>Invalid when this SqrlEnScrypt is deleted.</remarks>
    /// 
    /// <returns>null if it fails, else the result.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    SqrlString * SqrlEnScrypt::getResult() {
        if( !this->isComplete ) return NULL;
        if( this->didError ) return NULL;
        return this->result;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the number of iterations.</summary>
    ///
    /// <returns>The number of iterations.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    uint16_t SqrlEnScrypt::getIterations() {
        if( this->isComplete && !this->didError ) {
            return this->iCount;
        }
        return 0;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets elapsed time.</summary>
    ///
    /// <returns>The elapsed time.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    int SqrlEnScrypt::getElapsedTime() {
        if( this->isComplete && !this->didError ) {
            return (int)(1000 * (this->endTime - this->startTime));
        }
        return 0;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Updates this SqrlEnScrypt.</summary>
    /// 
    /// <remarks>Called repeatedly, until it returns true.</remarks>
    ///
    /// <returns>true if the operation is complete, false if more iterations are required.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    bool SqrlEnScrypt::update() {
        if( this->isComplete ) return true;
        const uint8_t *thePassword = this->password ? this->password->cdata() : NULL;
        size_t password_len = this->password ? this->password->length() : NULL;
        int retVal;
        uint64_t *buf = (uint64_t*)this->result->cdata();
        bool go = false;
        if( this->countIsIterations ) {
            if( this->iCount < this->count ) go = true;
        } else {
            double elapsed = 1000 * (sqrl_get_real_time() - this->startTime);
            if( elapsed < this->count ) go = true;
        }
        if( go ) {
            if( this->iCount & 1 ) {
                retVal = ((escrypt_kdf_t)this->escrypt_kdf)((escrypt_local_t*)this->local, thePassword, password_len, t[1], 32, this->N, ENSCRYPT_R, ENSCRYPT_P, t[0], 32);
                buf[0] ^= ((uint64_t*)t[0])[0];
                buf[1] ^= ((uint64_t*)t[0])[1];
                buf[2] ^= ((uint64_t*)t[0])[2];
                buf[3] ^= ((uint64_t*)t[0])[3];
            } else {
                retVal = ((escrypt_kdf_t)this->escrypt_kdf)((escrypt_local_t*)this->local, thePassword, password_len, t[0], 32, this->N, ENSCRYPT_R, ENSCRYPT_P, t[1], 32);
                buf[0] ^= ((uint64_t*)t[1])[0];
                buf[1] ^= ((uint64_t*)t[1])[1];
                buf[2] ^= ((uint64_t*)t[1])[2];
                buf[3] ^= ((uint64_t*)t[1])[3];
            }
            this->iCount++;
            if( retVal != 0 ) {
                this->didError = true;
                this->done();
            }
        } else {
            this->done();
        }
        // TODO: Update progress
        return this->isComplete;
    }

    /// <summary>Call this when the operations is complete.</summary>
    void SqrlEnScrypt::done() {
        this->endTime = sqrl_get_real_time();
        if( escrypt_free_local( (escrypt_local_t*)this->local ) ) {
            this->didError = true;
        }
        if( this->local ) free( this->local );
        this->local = NULL;
        if( this->didError ) {
            if( this->result ) {
                delete this->result;
                this->result = NULL;
            }
        }
        this->isComplete = true;
    }
}
