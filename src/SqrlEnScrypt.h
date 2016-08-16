/** \file SqrlEnScrypt.h
*
* \author Adam Comley
*
* This file is part of libsqrl.  It is released under the MIT license.
* For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLENSCRYPT_H
#define SQRLENSCRYPT_H

#include "sqrl.h"
#include "SqrlAction.h"
#include "SqrlClient.h"
#include "SqrlString.h"

namespace libsqrl
{
#define ENSCRYPT_R 256
#define ENSCRYPT_P 1
#define SODIUM_SCRYPT crypto_pwhash_scryptsalsa208sha256_ll


    /// <summary>Performs SQRL's EnScrypt operation.</summary>
    class DLL_PUBLIC SqrlEnScrypt
    {
    public:
        SqrlEnScrypt( const SqrlAction *action, const SqrlString *password, const SqrlString *salt, uint16_t count, bool countIsIterations = true, uint8_t nFactor = 9 );
        ~SqrlEnScrypt();
        bool isFinished();
        bool isSuccessful();
        SqrlString *getResult();
        uint16_t getIterations();
        int getElapsedTime();
        int getCurrentProgress();

        bool update();

    private:
        void done();

        SqrlString *result;
        SqrlString *password;
        uint16_t count;
        bool countIsIterations;
        uint64_t N;
        bool isComplete;
        bool didError;

        uint8_t t[2][32] = {{0}, {0}};
        double startTime, endTime, elapsed;
        void *escrypt_kdf;
        void *local;
        int iCount;

        const SqrlAction *action;
    };
}
#endif // SQRLENSCRYPT_H
