#pragma once

#include "sqrl.h"

class DLL_PUBLIC SqrlClient
{
	friend class SqrlAction;
	friend class SqrlUser;
	friend class SqrlActionSave;
	friend class SqrlActionGenerate;
	friend class SqrlActionRekey;
	friend class SqrlActionRescue;
	friend class SqrlActionLock;
	friend class SqrlActionChangePassword;

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
		SqrlAction *t,
		const char *url, size_t url_len,
		const char *payload, size_t payload_len) = 0;
	virtual int onProgress(
		SqrlAction *transaction,
		int progress) = 0;
	virtual void onAsk(
		SqrlAction *transaction,
		const char *message, size_t message_len,
		const char *firstButton, size_t firstButton_len,
		const char *secondButton, size_t secondButton_len) = 0;
	virtual void onAuthenticationRequired(
		SqrlAction *transaction,
		Sqrl_Credential_Type credentialType) = 0;
	virtual void onSelectUser(SqrlAction *transaction) = 0;
	virtual void onSelectAlternateIdentity(
		SqrlAction *transaction) = 0;
	virtual void onSaveSuggested(
		SqrlUser *user) = 0;
	virtual void onActionComplete(
		SqrlAction *transaction) = 0;

private:

};