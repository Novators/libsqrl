#include "sqrl_internal.h"
#include "SqrlActionLock.h"

#include "SqrlClient.h"
#include "SqrlUser.h"

SqrlActionLock::SqrlActionLock( SqrlUser *user) : SqrlIdentityAction( user ) {

}

void SqrlActionLock::run() {
	if( this->running || this->finished || this->runState < 0 ) return;
	this->running = true;

	SqrlClient *client = SqrlClient::getClient();

	switch( this->runState ) {
	case 0:
		if( !this->user ) {
			client->onSelectUser( this );
		}
		if( !this->user ) {
			this->runState = -1;
			this->finished = true;
			break;
		}
		this->runState++;
	case 1:
		if( !this->user->isHintLocked() ) {
			this->user->hintLock();
		}
		this->finished = true;
		break;
	}
	this->running = false;
	if( this->finished ) {
		client->onActionComplete( this );
	}
}
