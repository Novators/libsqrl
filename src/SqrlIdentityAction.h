/** \file SqrlIdentityAction.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLIDENTITYACTION_H
#define SQRLIDENTITYACTION_H

#include "sqrl.h"
#include "SqrlAction.h"

namespace libsqrl
{
    class DLL_PUBLIC SqrlIdentityAction : public SqrlAction
    {
        friend class SqrlUser;
        friend class SqrlActionSave;

    public:
        SqrlIdentityAction( SqrlUser *user );


    protected:
        virtual void onRelease();
    };
}
#endif // SQRLIDENTITYACTION_H
