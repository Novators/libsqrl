/** @file SqrlClientAsync.cpp
@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
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
	SqrlClientAsync *client;
	while( (client = (SqrlClientAsync*)SqrlClient::getClient()) && !client->stopping ) {
		if( client->loop() ) {
			sqrl_sleep( 50 );
		} else {
			sqrl_sleep( 100 );
		}
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

