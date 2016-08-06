/** \file SqrlActionGenerate.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
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
		COMPLETE( SQRL_ACTION_CANCELED)
	}

	switch( cs ) {
	case 0:
		if( !this->user ) {
			SqrlUser *user = new SqrlUser();
			this->setUser( user );
		}
		NEXT_STATE( cs )
	case 1:
		if( !this->user->rekey( this ) ) {
			COMPLETE( SQRL_ACTION_FAIL )
		}
		NEXT_STATE( cs )
	case 2:
		if( this->user->getPasswordLength() == 0 ) {
			client->callAuthenticationRequired( this, SQRL_CREDENTIAL_NEW_PASSWORD );
			SAME_STATE( cs )
		}
		NEXT_STATE( cs )
	case 3:
		client->callSaveSuggested( this->user );
		NEXT_STATE( cs )
	case 4:
		COMPLETE( SQRL_ACTION_SUCCESS )
	default:
		COMPLETE( SQRL_ACTION_FAIL )
	}
}
