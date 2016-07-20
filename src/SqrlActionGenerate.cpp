#include "sqrl_internal.h"
#include "SqrlActionGenerate.h"
#include "SqrlUser.h"
#include "SqrlClient.h"

SqrlActionGenerate::SqrlActionGenerate() : SqrlIdentityAction(NULL) {

}

void SqrlActionGenerate::run() {
	if( this->running || this->finished || this->runState < 0 ) return;
	this->running = true;
	if( !this->user ) {
		SqrlUser *user = new SqrlUser();
		this->setUser( user );
		user->release();
	}
	SqrlClient *client = SqrlClient::getClient();

	switch( this->runState ) {
	case 0:
		if( !this->user->rekey( this ) ) {
			this->runState = -1;
			this->finished = true;
			break;
		}
		this->runState++;
	case 1:
		client->onAuthenticationRequired( this, SQRL_CREDENTIAL_NEW_PASSWORD );
		if( this->user->getPasswordLength() == 0 ) {
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