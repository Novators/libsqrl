#pragma once

#include "sqrl.h"

class DLL_PUBLIC SqrlClient
{
	friend class SqrlTransaction;
	friend class SqrlUser;

private:
	static SqrlClient *client;

public:
	SqrlClient();
	~SqrlClient();
	static SqrlClient *getClient();

	void updateIdleTime( int idleTime );
	void screenLocked();
	void userChanged();

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
	virtual void onAuthenticationRequired(
		SqrlTransaction *transaction,
		Sqrl_Credential_Type credentialType) = 0;
	virtual void onSelectUser(SqrlTransaction *transaction) = 0;
	virtual void onSelectAlternateIdentity(
		SqrlTransaction *transaction) = 0;
	virtual void onSaveSuggested(
		SqrlUser *user) = 0;
	virtual void onTransactionComplete(
		SqrlTransaction *transaction) = 0;

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
	void callAuthenticationRequired(
		SqrlTransaction *transaction,
		Sqrl_Credential_Type credentialType);
	void callSelectUser(SqrlTransaction *transaction);
	void callSelectAlternateIdentity(
		SqrlTransaction *transaction);
	void callSaveSuggested(
		SqrlUser *user);
	void callTransactionComplete(
		SqrlTransaction *transaction);

};