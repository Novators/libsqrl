/** @file SqrlActionGenerate.cpp
@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlActionGenerate.h"
#include "SqrlUser.h"
#include "SqrlClient.h"

SqrlActionGenerate::SqrlActionGenerate() : SqrlIdentityAction(NULL) {

}

int SqrlActionGenerate::run( int cs ) {
	SqrlClient *client = SqrlClient::getClient();
	if( this->shouldCancel ) {
		return this->retActionComplete( SQRL_ACTION_CANCELED );
	}

	switch( cs ) {
	case 0:
		if( !this->user ) {
			SqrlUser *user = new SqrlUser();
			this->setUser( user );
		}
		if( !this->user->rekey( this ) ) {
			return this->retActionComplete( SQRL_ACTION_FAIL );
		}
		return cs + 1;
	case 1:
		if( this->user->getPasswordLength() == 0 ) {
			client->callAuthenticationRequired( this, SQRL_CREDENTIAL_NEW_PASSWORD );
			return cs;
		}
		return cs + 1;
	case 2:
		client->callSaveSuggested( this->user );
		return cs + 1;
	case 3:
		return this->retActionComplete( SQRL_ACTION_SUCCESS );
	default:
		// Invalid State
		return this->retActionComplete( SQRL_ACTION_FAIL );
	}
}
