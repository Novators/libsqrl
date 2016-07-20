#include "sqrl_internal.h"
#include "SqrlActionRekey.h"

#include "SqrlUser.h"
#include "SqrlClient.h"

SqrlActionRekey::SqrlActionRekey() : SqrlIdentityAction( NULL ) {

}

void SqrlActionRekey::run() {
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
		if( !this->user->rekey( this ) ) {
			this->runState = -1;
			this->finished = true;
			break;
		}
		this->runState++;
	case 3:
		client->onAuthenticationRequired( this, SQRL_CREDENTIAL_NEW_PASSWORD );
		if( this->user->getPasswordLength() == 0 ) {
			this->runState = -1;
			this->finished = true;
			break;
		}
		this->runState++;
	case 4:
		client->onSaveSuggested( this->user );
		this->finished = true;
		break;
	}
	this->running = false;
	if( this->finished ) {
		client->onActionComplete( this );
	}
}
