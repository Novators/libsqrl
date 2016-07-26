#include "sqrl_internal.h"
#include "SqrlActionLock.h"

#include "SqrlClient.h"
#include "SqrlUser.h"

SqrlActionLock::SqrlActionLock( SqrlUser *user) : SqrlIdentityAction( user ) {

}

int SqrlActionLock::run( int cs ) {
	SqrlClient *client = SqrlClient::getClient();
	if( this->shouldCancel ) {
		return this->retActionComplete( SQRL_ACTION_CANCELED );
	}

	switch( this->state ) {
	case 0:
		if( !this->user ) {
			client->callSelectUser( this );
		}
		return cs + 1;
	case 1:
		if( !this->user->isHintLocked() ) {
			this->user->hintLock();
		}
		return this->retActionComplete( SQRL_ACTION_SUCCESS );
	default:
		return this->retActionComplete( SQRL_ACTION_FAIL );
	}
}
