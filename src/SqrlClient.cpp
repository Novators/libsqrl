#include "sqrl_internal.h"

#include "SqrlClient.h"

SqrlClient *SqrlClient::client = NULL;

SqrlClient::SqrlClient() {
	if (!SqrlClient::client) {
		SqrlClient::client = this;
	}
}

SqrlClient *SqrlClient::getClient() {
	return SqrlClient::client;
}

void SqrlClient::callSend(
	SqrlTransaction *t,
	const char *url, size_t url_len,
	const char *payload, size_t payload_len) {
	this->onSend(t, url, url_len, payload, payload_len);
}
int SqrlClient::callProgress(
	SqrlTransaction *transaction,
	int progress) {
	return this->onProgress(transaction, progress);
}
void SqrlClient::callAsk(
	SqrlTransaction *transaction,
	const char *message, size_t message_len,
	const char *firstButton, size_t firstButton_len,
	const char *secondButton, size_t secondButton_len) {
	this->onAsk(transaction, message, message_len, firstButton, firstButton_len, secondButton, secondButton_len);
}
bool SqrlClient::callAuthenticationRequired(
	SqrlTransaction *transaction,
	Sqrl_Credential_Type credentialType) {
	return this->onAuthenticationRequired(transaction, credentialType);
}
SqrlUser *SqrlClient::callSelectUser(SqrlTransaction *transaction) {
	return this->onSelectUser(transaction);
}
void SqrlClient::callSelectAlternateIdentity(
	SqrlTransaction *transaction) {
	this->onSelectAlternateIdentity(transaction);
}
void SqrlClient::callSaveSuggested(
	SqrlUser *user) {
	this->onSaveSuggested(user);
}
void SqrlClient::callTransactionComplete(
	SqrlTransaction *transaction) {
	this->onTransactionComplete(transaction);
}

void SqrlClient::authenticate(
	SqrlTransaction *transaction,
	Sqrl_Credential_Type credentialType,
	char *credential, size_t credentialLength) {

}

Sqrl_Transaction_Status SqrlClient::beginTransaction(
	Sqrl_Transaction_Type type,
	SqrlUser *user,
	const char *string,
	size_t string_len) {
	return SQRL_TRANSACTION_STATUS_CANCELLED;
}

Sqrl_Transaction_Status SqrlClient::exportUser(
	SqrlUser *user,
	const char *uri,
	Sqrl_Export exportType,
	Sqrl_Encoding encodingType) {
	return SQRL_TRANSACTION_STATUS_FAILED;
}

void SqrlClient::dataReceived(
	SqrlTransaction *transaction,
	const char *payload, size_t payload_len) {

}

void SqrlClient::answer(
	SqrlTransaction *transaction,
	Sqrl_Button answer) {

}

void SqrlClient::setAlternateIdentity(
	SqrlTransaction *transaction,
	const char *altIdentity) {

}
