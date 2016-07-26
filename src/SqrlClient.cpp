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
static bool sqrl_is_initialized = false;

SqrlClient::SqrlClient() {
	if( SqrlClient::client != NULL ) {
		// Enforce a single SqrlClient object
		exit( 1 );
	}
	if( !sqrl_is_initialized ) {
		sqrl_is_initialized = true;
		gcm_initialize();
		sodium_init();
	}

	SqrlEntropy::start();
	SqrlClient::client = this;
	this->myThread = new std::thread( SqrlClient::clientThread );
}

SqrlClient::~SqrlClient() {
	this->stopping = true;
	this->myThread->join();
	delete this->myThread;
	SqrlClient::client = NULL;
	SqrlEntropy::stop();
}

SqrlClient *SqrlClient::getClient() {
	return SqrlClient::client;
}

void SqrlClient::onLoop() {
}

void SqrlClient::loop() {
	this->onLoop();
	SqrlAction *action;
	while( !this->callbackQueue.empty() ) {
		struct CallbackInfo *info = this->callbackQueue.front();
		this->callbackQueue.pop();

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
	if( this->actions.size() > 0 ) {
		action = this->actions.front();
		if( action ) {
			if( action->exec() ) {
				this->actionMutex.lock();
				this->actions.pop_front();
				this->actions.push_back( action );
				this->actionMutex.unlock();
			}
		}
	}
}

void SqrlClient::clientThread() {
	SqrlClient *client;
	while( (client = SqrlClient::getClient()) && !client->stopping ) {
		client->loop();
		sqrl_sleep( 100 );
	}
	while( !client->callbackQueue.empty() ) {
		struct CallbackInfo *info = client->callbackQueue.front();
		client->callbackQueue.pop();
		delete info;
	}
	client->actionMutex.lock();
	while( client->actions.size() > 0 ) {
		SqrlAction *action = client->actions.front();
		delete action;
	}
	client->actionMutex.unlock();
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

void SqrlClient::callSend( SqrlAction * action, std::string *url, std::string * payload ) {
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_SEND;
	info->ptr = action;
	info->str[0] = new std::string( *url );
	info->str[1] = new std::string( *payload );
	this->callbackQueue.push( info );
}

void SqrlClient::callAsk( SqrlAction * action, std::string * message, std::string * firstButton, std::string * secondButton ) {
	struct CallbackInfo *info = new struct CallbackInfo();
	info->cbType = SQRL_CALLBACK_ASK;
	info->ptr = action;
	info->str[0] = new std::string( *message );
	info->str[1] = new std::string( *firstButton );
	info->str[2] = new std::string( *secondButton );
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
