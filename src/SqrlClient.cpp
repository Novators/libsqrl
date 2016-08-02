#include "sqrl_internal.h"

#include "SqrlClient.h"
#include "SqrlAction.h"
#include "SqrlUser.h"
#include "SqrlEntropy.h"
#include "gcm.h"


#define SQRL_CALLBACK_SAVE_SUGGESTED 0
#define SQRL_CALLBACK_SELECT_USER 1
#define SQRL_CALLBACK_SELECT_ALT 2
#define SQRL_CALLBACK_ACTION_COMPLETE 3
#define SQRL_CALLBACK_AUTH_REQUIRED 4
#define SQRL_CALLBACK_SEND 5
#define SQRL_CALLBACK_ASK 6
#define SQRL_CALLBACK_PROGRESS 7

SqrlClient *SqrlClient::client = NULL;
#ifndef ARDUINO
static std::mutex sqrl_client_mutex;
#endif

SqrlClient::SqrlClient() {
	this->initialize();
}

void SqrlClient::initialize() {
#ifndef ARDUINO
	sqrl_client_mutex.lock();
#endif
	if( SqrlClient::client != NULL ) {
		// Enforce a single SqrlClient object
		exit( 1 );
	}
	SqrlInit();

	SqrlEntropy::start();
	SqrlClient::client = this;
#ifndef ARDUINO
	sqrl_client_mutex.unlock();
#endif
}

SqrlClient::~SqrlClient() {
#ifndef ARDUINO
	sqrl_client_mutex.lock();
#endif
	SqrlEntropy::stop();
	SqrlClient::client = NULL;
#ifndef ARDUINO
	sqrl_client_mutex.unlock();
#endif
}

SqrlClient *SqrlClient::getClient() {
	return SqrlClient::client;
}

int SqrlClient::getUserIdleSeconds() {
	return 0;
}

bool SqrlClient::isScreenLocked() {
	return false;
}

bool SqrlClient::isUserChanged() {
	return false;
}

void SqrlClient::onLoop() {
}

bool SqrlClient::loop() {
	this->onLoop();
	SqrlAction *action;
	while( !this->callbackQueue.empty() ) {
		struct CallbackInfo *info = SQRL_QUEUE_POP( this->callbackQueue );

		switch( info->cbType ) {
		case SQRL_CALLBACK_SAVE_SUGGESTED:
			this->onSaveSuggested( (SqrlUser*)info->ptr );
			((SqrlUser*)info->ptr)->release();
			break;
		case SQRL_CALLBACK_SELECT_USER:
			action = (SqrlAction*)info->ptr;
			this->onSelectUser( action );
			break;
		case SQRL_CALLBACK_SELECT_ALT:
			action = (SqrlAction*)info->ptr;
			this->onSelectAlternateIdentity( action );
			break;
		case SQRL_CALLBACK_ACTION_COMPLETE:
			action = (SqrlAction*)info->ptr;
			this->onActionComplete( action );
			break;
		case SQRL_CALLBACK_AUTH_REQUIRED:
			action = (SqrlAction*)info->ptr;
			this->onAuthenticationRequired( action, info->credentialType );
			break;
		case SQRL_CALLBACK_SEND:
			action = (SqrlAction*)info->ptr;
			this->onSend( action, *info->str[0], *info->str[1] );
			break;
		case SQRL_CALLBACK_ASK:
			action = (SqrlAction*)info->ptr;
			this->onAsk( action, *info->str[0], *info->str[1], *info->str[2] );
			break;
		case SQRL_CALLBACK_PROGRESS:
			action = (SqrlAction*)info->ptr;
			this->onProgress( action, info->progress );
			break;
		}
		delete info;
	}
	SQRL_QUEUE<SqrlAction *> *nq = new SQRL_QUEUE<SqrlAction *>();
	if( ! SQRL_QUEUE_IS_EMPTY( this->actions ) ) {
		action = SQRL_QUEUE_POP( this->actions );
		if( action ) {
			if( action->exec() ) {
				SQRL_QUEUE_PUSH( this->actions, action );
			}
		}
	}
	while( !SQRL_QUEUE_IS_EMPTY( this->actions ) ) {
		SQRL_QUEUE_PUSH( nq, SQRL_QUEUE_POP( this->actions ) );
	}
#ifndef ARDUINO
	this->actionMutex.lock();
#endif
	delete this->actions;
	this->actions = nq;
#ifndef ARDUNIO
	this->actionMutex.unlock();
#endif
	if( SQRL_QUEUE_IS_EMPTY( this->actions ) && SQRL_QUEUE_IS_EMPTY( this->callbackQueue ) ) {
		return false;
	}
	return true;
}

void SqrlClient::callSaveSuggested( SqrlUser * user ) {
	user->hold();
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_SAVE_SUGGESTED;
	info->ptr = user;
	SQRL_QUEUE_PUSH( this->callbackQueue, info );
}

void SqrlClient::callSelectUser( SqrlAction * action ) {
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_SELECT_USER;
	info->ptr = action;
	SQRL_QUEUE_PUSH( this->callbackQueue, info );
}

void SqrlClient::callSelectAlternateIdentity( SqrlAction * action ) {
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_SELECT_ALT;
	info->ptr = action;
	SQRL_QUEUE_PUSH( this->callbackQueue, info );
}

void SqrlClient::callActionComplete( SqrlAction * action ) {
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_ACTION_COMPLETE;
	info->ptr = action;
	SQRL_QUEUE_PUSH( this->callbackQueue, info );
}

void SqrlClient::callProgress( SqrlAction * action, int progress ) {
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_PROGRESS;
	info->ptr = action;
	info->progress = progress;
	SQRL_QUEUE_PUSH( this->callbackQueue, info );
}

void SqrlClient::callAuthenticationRequired( SqrlAction * action, Sqrl_Credential_Type credentialType ) {
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_AUTH_REQUIRED;
	info->ptr = action;
	info->credentialType = credentialType;
	SQRL_QUEUE_PUSH( this->callbackQueue, info );
}

void SqrlClient::callSend( SqrlAction * action, std::string *url, std::string * payload ) {
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_SEND;
	info->ptr = action;
	info->str[0] = new std::string( *url );
	info->str[1] = new std::string( *payload );
	SQRL_QUEUE_PUSH( this->callbackQueue, info );
}

void SqrlClient::callAsk( SqrlAction * action, std::string * message, std::string * firstButton, std::string * secondButton ) {
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_ASK;
	info->ptr = action;
	info->str[0] = new std::string( *message );
	info->str[1] = new std::string( *firstButton );
	info->str[2] = new std::string( *secondButton );
	SQRL_QUEUE_PUSH( this->callbackQueue, info );
}

SqrlClient::CallbackInfo::CallbackInfo() {
	this->cbType = 0;
	this->progress = 0;
	this->credentialType = SQRL_CREDENTIAL_PASSWORD;
	this->ptr = NULL;
	this->str[0] = NULL;
	this->str[1] = NULL;
	this->str[2] = NULL;

}

SqrlClient::CallbackInfo::~CallbackInfo() {
	int i;
	if( this->ptr ) {
		if( this->cbType == SQRL_CALLBACK_SAVE_SUGGESTED ) {
			SqrlUser *user = (SqrlUser*)this->ptr;
			user->release();
		}
	}
	for( i = 0; i < 3; i++ ) {
		if( this->str[i] ) {
			delete this->str[i];
		}
	}
}
