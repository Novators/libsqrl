/** \file SqrlActionRekey.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLACTIONREKEY_H
#define SQRLACTIONREKEY_H

#include "sqrl.h"
#include "SqrlIdentityAction.h"

namespace libsqrl
{
    class DLL_PUBLIC SqrlActionRekey : public SqrlIdentityAction
    {
        SqrlActionRekey();
        int run( int cs );
    };
}
#endif // SQRLACTIONREKEY_H
