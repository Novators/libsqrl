/** @file transaction.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/
#include "sqrl_internal.h"
#include "sqrl.h"
#include "SqrlAction.h"
#include "SqrlUri.h"
#include "SqrlUser.h"
#include "SqrlClient.h"
#include <algorithm>

struct Sqrl_Transaction_List {
	SqrlAction *transaction;
	struct Sqrl_Transaction_List *next;
};

struct Sqrl_Transaction_List *SQRL_TRANSACTION_LIST = NULL;

#if defined(DEBUG) && DEBUG_PRINT_TRANSACTION_COUNT==1
#define PRINT_TRANSACTION_COUNT(tag) \
int _ptcI = 0;\
struct Sqrl_Transaction_List *_ptcC = SQRL_TRANSACTION_LIST;\
while( _ptcC ) {\
    _ptcI++;\
    _ptcC = _ptcC->next;\
}\
printf( "%10s: %d\n", tag, _ptcI )
#else
#define PRINT_TRANSACTION_COUNT(tag)
#endif

SqrlAction::SqrlAction()
: user(NULL),
  uri(NULL),
  state(0),
  status(SQRL_ACTION_RUNNING),
  shouldCancel(false) {
	SqrlClient *client = SqrlClient::getClient();
	if( !client ) {
		exit( 1 );
	}
	client->actionMutex.lock();
	client->actions.push_back( this );
	client->actionMutex.unlock();
}

SqrlAction::~SqrlAction() {
	SqrlClient *client = SqrlClient::getClient();
	client->actionMutex.lock();
	client->actions.erase( 
		std::remove_if( 
			client->actions.begin(),
			client->actions.end(),
			[this]( SqrlAction* i ) { return i == this; } ),
		client->actions.end() );
	client->actionMutex.unlock();

	this->onRelease();
	if( this->user ) {
		this->user->release();
	}
	if( this->uri ) {
		this->uri->release();
	}
}

int SqrlAction::retActionComplete( int status ) {
	this->status = status;
	SqrlClient::getClient()->callActionComplete( this );
	return SQRL_ACTION_STATE_DELETE;
}

bool SqrlAction::exec() {
	if( this->state == SQRL_ACTION_STATE_DELETE ) {
		delete this;
		return false;
	} else {
		this->state = this->run( this->state );
		return true;
	}
}

void SqrlAction::onRelease() {
}

void SqrlAction::setUser( SqrlUser *u )
{
    if( !u ) return;
	if (this->user) {
		this->user->release();
	}
	this->user = u;
	u->hold();
}

SqrlUser *SqrlAction::getUser()
{
	return this->user;
}

SqrlUri *SqrlAction::getUri()
{
	return this->uri;
}

void SqrlAction::setUri(SqrlUri *uri)
{
	if (this->uri) {
		this->uri = this->uri->release();
	}
	this->uri = uri->copy();
}

void SqrlAction::authenticate( Sqrl_Credential_Type credentialType, const char *credential, size_t length ) {
	if( !this->user ) return;
	switch( credentialType ) {
	case SQRL_CREDENTIAL_HINT:
		break;
	case SQRL_CREDENTIAL_PASSWORD:
		break;
	case SQRL_CREDENTIAL_NEW_PASSWORD:
		this->user->setPassword( credential, length );
		break;
	case SQRL_CREDENTIAL_RESCUE_CODE:
		break;
	}
}

void SqrlAction::cancel() {
	this->shouldCancel = true;
}
