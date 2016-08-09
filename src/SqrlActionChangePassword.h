/** \file SqrlActionChangePassword.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLACTIONCHANGEPASSWORD_H
#define SQRLACTIONCHANGEPASSWORD_H

#include "sqrl.h"
#include "SqrlIdentityAction.h"

namespace libsqrl
{

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Changes a user's password.</summary>
    /// <remarks>
    /// Callbacks Used:
    ///   - SqrlClient::onSelectUser: If not specified when action is created.
    ///   - SqrlClient::onAuthenticationRequired: SQRL_CREDENTIAL_PASSWORD: (old password)
    ///   - SqrlClient::onAuthenticationRequired: SQRL_CREDENTIAL_NEW_PASSWORD: (new password)
    ///   - SqrlClient::onSaveSuggested: When successfully completed.  </remarks>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    class DLL_PUBLIC SqrlActionChangePassword : public SqrlIdentityAction
    {
        SqrlActionChangePassword();
        SqrlActionChangePassword( SqrlUser *user );
        int run( int cs );
    };
}
#endif // SQRLACTIONCHANGEPASSWORD_H
