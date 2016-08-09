/** \file SqrlActionChangePassword.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlActionChangePassword.h"

#include "SqrlClient.h"
#include "SqrlUser.h"

namespace libsqrl
{
	SqrlActionChangePassword::SqrlActionChangePassword() : SqrlIdentityAction( NULL ) {}

	SqrlActionChangePassword::SqrlActionChangePassword( SqrlUser *user ) : SqrlIdentityAction( user ) {}

	int SqrlActionChangePassword::run( int cs ) {
		SqrlClient *client = SqrlClient::getClient();
		if( this->shouldCancel ) {
			COMPLETE( SQRL_ACTION_CANCELED );
		}

		switch( cs ) {
		case 0:
			// Ensure that a User is selected; call client::callSelectUser() if not.
			if( !this->user ) {
				client->callSelectUser( this );
				SAME_STATE( cs )
			}
			NEXT_STATE( cs )
		case 1:
			// Decrypt the user identity, requesting authentication if needed.
			// TODO: forceDecrypt should be a SqrlAction ?
			if( !this->user->forceDecrypt( this ) ) {
				COMPLETE( SQRL_ACTION_FAIL )
			}
			NEXT_STATE( cs )
		case 2:
			// Request a new Password
			client->callAuthenticationRequired( this, SQRL_CREDENTIAL_NEW_PASSWORD );
			NEXT_STATE( cs )
		case 3:
			// Suggest saving the modified identity.
			client->callSaveSuggested( this->user );
			COMPLETE( SQRL_ACTION_SUCCESS );
		default:
			COMPLETE( SQRL_ACTION_FAIL );
		}
	}
}