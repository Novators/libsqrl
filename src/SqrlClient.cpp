#include "sqrl_internal.h"

#include "SqrlClient.h"
#include "SqrlTransaction.h"

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

void SqrlClient::callSend(
	SqrlTransaction *t,
	const char *url, size_t url_len,
	const char *payload, size_t payload_len ) {
	this->onSend( t, url, url_len, payload, payload_len );
}
int SqrlClient::callProgress(
	SqrlTransaction *transaction,
	int progress ) {
	return this->onProgress( transaction, progress );
}
void SqrlClient::callAsk(
	SqrlTransaction *transaction,
	const char *message, size_t message_len,
	const char *firstButton, size_t firstButton_len,
	const char *secondButton, size_t secondButton_len ) {
	this->onAsk( transaction, message, message_len, firstButton, firstButton_len, secondButton, secondButton_len );
}
void SqrlClient::callAuthenticationRequired(
	SqrlTransaction *transaction,
	Sqrl_Credential_Type credentialType ) {
	this->onAuthenticationRequired( transaction, credentialType );
}
void SqrlClient::callSelectUser( SqrlTransaction *transaction ) {
	this->onSelectUser( transaction );
}
void SqrlClient::callSelectAlternateIdentity(
	SqrlTransaction *transaction ) {
	this->onSelectAlternateIdentity( transaction );
}
void SqrlClient::callSaveSuggested(
	SqrlUser *user ) {
	this->onSaveSuggested( user );
}
void SqrlClient::callTransactionComplete(
	SqrlTransaction *transaction ) {
	this->onTransactionComplete( transaction );
}

