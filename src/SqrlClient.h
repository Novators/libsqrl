#pragma once

#include "sqrl.h"

class DLL_PUBLIC SqrlClient
{
	friend class SqrlTransaction;
	friend class SqrlUser;
public:
	static SqrlClient *client;

protected:

	virtual void onSend(
		SqrlTransaction *t,
		const char *url, size_t url_len,
		const char *payload, size_t payload_len) = 0;
	virtual int onProgress(
		SqrlTransaction *transaction,
		int progress) = 0;
	virtual void onAsk(
		SqrlTransaction *transaction,
		const char *message, size_t message_len,
		const char *firstButton, size_t firstButton_len,
		const char *secondButton, size_t secondButton_len) = 0;
	virtual bool onAuthenticationRequired(
		SqrlTransaction *transaction,
		Sqrl_Credential_Type credentialType) = 0;
	virtual SqrlUser *onSelectUser(SqrlTransaction *transaction) = 0;
	virtual void onSelectAlternateIdentity(
		SqrlTransaction *transaction) = 0;
	virtual void onSaveSuggested(
		SqrlUser *user) = 0;
	virtual void onTransactionComplete(
		SqrlTransaction *transaction) = 0;

	void authenticate(
		SqrlTransaction *transaction,
		Sqrl_Credential_Type credentialType,
		char *credential, size_t credentialLength);
	Sqrl_Transaction_Status beginTransaction(
		Sqrl_Transaction_Type type,
		SqrlUser *user,
		const char *string,
		size_t string_len);
	Sqrl_Transaction_Status exportUser(
		SqrlUser *user,
		const char *uri,
		Sqrl_Export exportType,
		Sqrl_Encoding encodingType);
	void dataReceived(
		SqrlTransaction *transaction,
		const char *payload, size_t payload_len);
	void answer(
		SqrlTransaction *transaction,
		Sqrl_Button answer);
	void setAlternateIdentity(
		SqrlTransaction *transaction,
		const char *altIdentity);
public:
	SqrlClient();
	static SqrlClient *getClient();

private:
	void callSend(
		SqrlTransaction *t,
		const char *url, size_t url_len,
		const char *payload, size_t payload_len);
	int callProgress(
		SqrlTransaction *transaction,
		int progress);
	void callAsk(
		SqrlTransaction *transaction,
		const char *message, size_t message_len,
		const char *firstButton, size_t firstButton_len,
		const char *secondButton, size_t secondButton_len);
	bool callAuthenticationRequired(
		SqrlTransaction *transaction,
		Sqrl_Credential_Type credentialType);
	SqrlUser *callSelectUser(SqrlTransaction *transaction);
	void callSelectAlternateIdentity(
		SqrlTransaction *transaction);
	void callSaveSuggested(
		SqrlUser *user);
	void callTransactionComplete(
		SqrlTransaction *transaction);

};