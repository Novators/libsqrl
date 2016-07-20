#include "sqrl_internal.h"
#include "SqrlActionChangePassword.h"

#include "SqrlClient.h"
#include "SqrlUser.h"

SqrlActionChangePassword::SqrlActionChangePassword() : SqrlIdentityAction( NULL ) {

}

SqrlActionChangePassword::SqrlActionChangePassword( SqrlUser *user ) : SqrlIdentityAction( user ) {

}

void SqrlActionChangePassword::run() {
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
		if( !this->user->forceDecrypt( this ) ) {
			this->runState = -1;
			this->finished = true;
			break;
		}
		this->runState++;
	case 2:
		client->onAuthenticationRequired( this, SQRL_CREDENTIAL_NEW_PASSWORD );
		this->finished = true;
		break;
	}
	this->running = false;
	if( this->finished ) {
		client->onActionComplete( this );
	}
}
