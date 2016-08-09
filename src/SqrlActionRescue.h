/** \file SqrlActionRescue.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLACTIONRESCUE_H
#define SQRLACTIONRESCUE_H

#include "sqrl.h"
#include "SqrlIdentityAction.h"

namespace libsqrl
{
    class DLL_PUBLIC SqrlActionRescue : public SqrlIdentityAction
    {
        SqrlActionRescue();
        int run( int cs );
    };
}
#endif // SQRLACTIONRESCUE_H
