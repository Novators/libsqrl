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

void SqrlClient::callSaveSuggested( SqrlUser * user ) {
	this->onSaveSuggested( user );
}

void SqrlClient::callSelectUser( SqrlAction * transaction ) {
	this->onSelectUser( transaction );
}

void SqrlClient::callSelectAlternateIdentity( SqrlAction * transaction ) {
	this->onSelectAlternateIdentity( transaction );
}

void SqrlClient::callActionComplete( SqrlAction * transaction ) {
	this->onActionComplete( transaction );
}

int SqrlClient::callProgress( SqrlAction * transaction, int progress ) {
	return this->onProgress( transaction, progress );
}

void SqrlClient::callAuthenticationRequired( SqrlAction * transaction, Sqrl_Credential_Type credentialType ) {
	this->onAuthenticationRequired( transaction, credentialType );
}

void SqrlClient::callSend( SqrlAction * t, const char * url, size_t url_len, const char * payload, size_t payload_len ) {
	this->onSend( t, url, url_len, payload, payload_len );
}

void SqrlClient::callAsk( SqrlAction * transaction, const char * message, size_t message_len, const char * firstButton, size_t firstButton_len, const char * secondButton, size_t secondButton_len ) {
	this->onAsk( transaction, message, message_len, firstButton, firstButton_len, secondButton, secondButton_len );
}
