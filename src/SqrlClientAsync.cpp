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

namespace libsqrl
{
	SqrlClientAsync::SqrlClientAsync() : SqrlClient() {
		this->myThread = new std::thread( SqrlClientAsync::clientThread );
	}

	SqrlClientAsync::~SqrlClientAsync() {
	}

	void SqrlClientAsync::onClientIsStopping() {
		this->stopping = true;
		if( this->myThread ) {
			this->myThread->join();
			delete this->myThread;
		}
	}

	void SqrlClientAsync::clientThread() {
		SqrlClientAsync *client = (SqrlClientAsync*)SqrlClient::getClient();
		while( client && !client->stopping ) {
			if( client->loop() ) {
				if( client->rapid ) {
					client->rapid = false;
				} else {
					sqrl_sleep( 50 );
				}
			} else {
				sqrl_sleep( 100 );
			}
		}
		while( !client->callbackQueue.empty() ) {
			struct CallbackInfo *info = client->callbackQueue.pop();
			delete info;
		}
	}
}
