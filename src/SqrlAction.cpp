/** \file SqrlAction.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "sqrl.h"
#include "SqrlAction.h"
#include "SqrlUri.h"
#include "SqrlUser.h"
#include "SqrlClient.h"

struct Sqrl_action_List {
	SqrlAction *action;
	struct Sqrl_action_List *next;
};

struct Sqrl_action_List *SQRL_action_LIST = NULL;

SqrlAction::SqrlAction()
: user(NULL),
  uri(NULL),
  state(0),
  status(SQRL_ACTION_RUNNING),
  shouldCancel(false) {
	SqrlClient *client = SqrlClient::getClient();
	if( !client ) {
		exit( 3 );
	}
	SQRL_MUTEX_LOCK( &client->actionMutex )
	client->actions.push_back( this );
	SQRL_MUTEX_UNLOCK( &client->actionMutex )
}

SqrlAction::~SqrlAction() {
	SqrlClient *client = SqrlClient::getClient();
	SQRL_MUTEX_LOCK( &client->actionMutex )
		client->actions.erase( this );
	SQRL_MUTEX_UNLOCK( &client->actionMutex )

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
