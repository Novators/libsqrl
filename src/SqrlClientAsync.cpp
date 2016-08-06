/** \file SqrlClientAsync.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"

#include "SqrlClient.h"
#include "SqrlClientAsync.h"
#include "SqrlAction.h"
#include "SqrlUser.h"
#include "SqrlEntropy.h"
#include "gcm.h"

SqrlClientAsync::SqrlClientAsync() {
	this->myThread = new std::thread( SqrlClientAsync::clientThread );
}

SqrlClientAsync::~SqrlClientAsync() {
	this->stopping = true;
	this->myThread->join();
	delete this->myThread;
}

void SqrlClientAsync::clientThread() {
	SqrlClientAsync *client = (SqrlClientAsync*)SqrlClient::getClient();
	if( !client ) return;
	while( !client->stopping ) {
		if( client->loop() ) {
			sqrl_sleep( 50 );
		} else {
			sqrl_sleep( 100 );
		}
	}
	while( !client->callbackQueue.empty() ) {
		struct CallbackInfo *info = client->callbackQueue.pop();
		delete info;
	}
	SQRL_MUTEX_LOCK( &client->actionMutex )
	while( !client->actions.empty() ) {
		SqrlAction *action = client->actions.pop();
		delete action;
	}
	SQRL_MUTEX_UNLOCK( &client->actionMutex )
}

