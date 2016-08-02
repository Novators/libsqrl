/** @file SqrlActionRescue.cpp
@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlActionRescue.h"
#include "SqrlClient.h"
#include "SqrlUser.h"

SqrlActionRescue::SqrlActionRescue() : SqrlIdentityAction( NULL ) {

}

int SqrlActionRescue::run( int cs ) {
	SqrlClient *client = SqrlClient::getClient();
	if( this->shouldCancel ) {
		return this->retActionComplete( SQRL_ACTION_CANCELED );
	}

	switch( this->state ) {
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
		return this->retActionComplete( SQRL_ACTION_SUCCESS );
	default:
		return this->retActionComplete( SQRL_ACTION_FAIL );
	}
}
