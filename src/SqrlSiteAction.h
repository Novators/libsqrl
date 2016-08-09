/** \file SqrlSiteAction.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLSITEACTION_H
#define SQRLSITEACTION_H

#include "sqrl.h"
#include "SqrlAction.h"

namespace libsqrl
{
    class DLL_PUBLIC SqrlSiteAction : public SqrlAction
    {
    public:
        void setAlternateIdentity( const char *altIdentity );
        char *getAltIdentity();
        void setAltIdentity( const char *alt );
        void dataReceived( const char *payload, size_t payload_len );
        void answer( Sqrl_Button answer );

    protected:
        char *altIdentity;
        void onRelease();
    };
}
#endif // SQRLSITEACTION_H
