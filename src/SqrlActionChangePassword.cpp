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

SqrlActionChangePassword::SqrlActionChangePassword() : SqrlIdentityAction( NULL ) {

}

SqrlActionChangePassword::SqrlActionChangePassword( SqrlUser *user ) : SqrlIdentityAction( user ) {

}

int SqrlActionChangePassword::run( int cs ) {
	SqrlClient *client = SqrlClient::getClient();
	if( this->shouldCancel ) {
		return this->retActionComplete( SQRL_ACTION_CANCELED );
	}

	switch( this->state ) {
	case 0:
		if( !this->user ) {
			client->callSelectUser( this );
		}
		return cs;
	case 1:
		if( !this->user->forceDecrypt( this ) ) {
			return this->retActionComplete( SQRL_ACTION_FAIL );
		}
		return cs + 1;
	case 2:
		client->callAuthenticationRequired( this, SQRL_CREDENTIAL_NEW_PASSWORD );
		return this->retActionComplete( SQRL_ACTION_SUCCESS );
	default:
		return this->retActionComplete( SQRL_ACTION_FAIL );
	}
}
