/** \file SqrlActionRekey.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlActionRekey.h"

#include "SqrlUser.h"
#include "SqrlClient.h"

using libsqrl::SqrlActionRekey;

SqrlActionRekey::SqrlActionRekey() : SqrlIdentityAction( NULL ) {

}

int SqrlActionRekey::run( int cs ) {
	SqrlClient *client = SqrlClient::getClient();
	if( this->shouldCancel ) {
		return this->retActionComplete( SQRL_ACTION_CANCELED );
	}

	switch( cs ) {
	case 0:
		if( !this->user ) {
			client->callSelectUser( this );
			return cs;
		}
		return cs + 1;
	case 1:
		if( !this->user->forceRescue( this ) ) {
			return this->retActionComplete( SQRL_ACTION_FAIL );
		}
		return cs + 1;
	case 2:
		if( !this->user->rekey( this ) ) {
			return this->retActionComplete( SQRL_ACTION_FAIL );
		}
		return cs + 1;
	case 3:
		if( this->user->getPasswordLength() == 0 ) {
			client->callAuthenticationRequired( this, SQRL_CREDENTIAL_NEW_PASSWORD );
			return cs;
		}
		return cs + 1;
	case 4:
		client->callSaveSuggested( this->user );
		return cs + 1;
	case 5:
		return this->retActionComplete( SQRL_ACTION_SUCCESS );
	default:
		return this->retActionComplete( SQRL_ACTION_FAIL );
	}
}
