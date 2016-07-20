#include "sqrl_internal.h"

#include "SqrlClient.h"
#include "SqrlAction.h"

SqrlClient *SqrlClient::client = NULL;

SqrlClient::SqrlClient() {
	if( SqrlClient::client != NULL ) {
		// Enforce a single SqrlClient object
		exit( 1 );
	}
	SqrlClient::client = this;
}

SqrlClient::~SqrlClient() {
	SqrlClient::client = NULL;
}

SqrlClient *SqrlClient::getClient() {
	return SqrlClient::client;
}

