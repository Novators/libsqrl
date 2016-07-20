#include "sqrl_internal.h"
#include "SqrlActionRescue.h"
#include "SqrlClient.h"
#include "SqrlUser.h"

SqrlActionRescue::SqrlActionRescue() : SqrlIdentityAction( NULL ) {

}

void SqrlActionRescue::run() {
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
		if( !this->user->forceRescue( this ) ) {
			this->runState = -1;
			this->finished = true;
			break;
		}
		this->runState++;
	case 2:
		client->onSaveSuggested( this->user );
		this->finished = true;
		break;
	}
	this->running = false;
	if( this->finished ) {
		client->onActionComplete( this );
	}
}
