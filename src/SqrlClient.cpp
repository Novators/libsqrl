/** \file SqrlClient.cpp
 *
 * \author Adam Comley
 * 
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"

#include "SqrlClient.h"
#include "SqrlAction.h"
#include "SqrlUser.h"
#include "SqrlEntropy.h"
#include "gcm.h"

template class SqrlDeque<SqrlClient::CallbackInfo *>;

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
		exit( 4 );
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
		struct CallbackInfo *info = this->callbackQueue.pop();

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
	if( !this->actions.empty() ) {
		action = this->actions.pop();
		if( action->exec() ) {
			this->actions.push_back( action );
		}
	}
	if( this->actions.empty() && this->callbackQueue.empty() ) {
		return false;
	}
	return true;
}

void SqrlClient::callSaveSuggested( SqrlUser * user ) {
	user->hold();
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_SAVE_SUGGESTED;
	info->ptr = user;
	this->callbackQueue.push( info );
}

void SqrlClient::callSelectUser( SqrlAction * action ) {
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_SELECT_USER;
	info->ptr = action;
	this->callbackQueue.push( info );
}

void SqrlClient::callSelectAlternateIdentity( SqrlAction * action ) {
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_SELECT_ALT;
	info->ptr = action;
	this->callbackQueue.push( info );
}

void SqrlClient::callActionComplete( SqrlAction * action ) {
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_ACTION_COMPLETE;
	info->ptr = action;
	this->callbackQueue.push( info );
}

void SqrlClient::callProgress( SqrlAction * action, int progress ) {
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_PROGRESS;
	info->ptr = action;
	info->progress = progress;
	this->callbackQueue.push( info );
}

void SqrlClient::callAuthenticationRequired( SqrlAction * action, Sqrl_Credential_Type credentialType ) {
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_AUTH_REQUIRED;
	info->ptr = action;
	info->credentialType = credentialType;
	this->callbackQueue.push( info );
}

void SqrlClient::callSend( SqrlAction * action, SQRL_STRING *url, SQRL_STRING * payload ) {
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_SEND;
	info->ptr = action;
	info->str[0] = new SQRL_STRING( *url );
	info->str[1] = new SQRL_STRING( *payload );
	this->callbackQueue.push( info );
}

void SqrlClient::callAsk( SqrlAction * action, SQRL_STRING * message, SQRL_STRING * firstButton, SQRL_STRING * secondButton ) {
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_ASK;
	info->ptr = action;
	info->str[0] = new SQRL_STRING( *message );
	info->str[1] = new SQRL_STRING( *firstButton );
	info->str[2] = new SQRL_STRING( *secondButton );
	this->callbackQueue.push( info );
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
