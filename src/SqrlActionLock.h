/** \file SqrlActionLock.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLACTIONLOCK_H
#define SQRLACTIONLOCK_H

#include "sqrl.h"
#include "SqrlIdentityAction.h"
#include "SqrlCrypt.h"

namespace libsqrl
{
    class DLL_PUBLIC SqrlActionLock : public SqrlIdentityAction
    {
        friend class SqrlUser;
    public:
        SqrlActionLock( SqrlUser *user );
        int run( int cs );

    private:
        SqrlCrypt crypt;
        uint8_t iv[12] = {0};

    };
}
#endif // SQRLACTIONLOCK_H
