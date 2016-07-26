#pragma once

#include "sqrl.h"
#include <queue>

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

	virtual void onLoop();
	virtual void onSend(
		SqrlAction *t, std::string url, std::string payload ) = 0;
	virtual void onProgress(
		SqrlAction *transaction, int progress) = 0;
	virtual void onAsk(
		SqrlAction *transaction,
		std::string message, std::string firstButton, std::string secondButton ) = 0;
	virtual void onAuthenticationRequired(
		SqrlAction *transaction, Sqrl_Credential_Type credentialType) = 0;
	virtual void onSelectUser(SqrlAction *transaction) = 0;
	virtual void onSelectAlternateIdentity(
		SqrlAction *transaction) = 0;
	virtual void onSaveSuggested(
		SqrlUser *user) = 0;
	virtual void onActionComplete(
		SqrlAction *transaction) = 0;

private:
	struct CallbackInfo
	{
		CallbackInfo();
		~CallbackInfo();

		int cbType;
		int progress;
		Sqrl_Credential_Type credentialType;
		void *ptr;
		std::string* str[3];
	};
	std::queue<struct CallbackInfo*> callbackQueue;
	std::deque<SqrlAction *>actions;
	std::mutex actionMutex;

	void loop();

	void callSaveSuggested(
		SqrlUser *user );
	void callSelectUser( SqrlAction *transaction );
	void callSelectAlternateIdentity(
		SqrlAction *transaction );
	void callActionComplete(
		SqrlAction *transaction );
	void callProgress(
		SqrlAction *transaction,
		int progress );
	void callAuthenticationRequired(
		SqrlAction *transaction,
		Sqrl_Credential_Type credentialType );
	void callSend(
		SqrlAction *t, std::string *url, std::string *payload );
	void callAsk(
		SqrlAction *transaction,
		std::string *message, std::string *firstButton, std::string *secondButton );

	static void clientThread();
	std::thread *myThread;
	bool stopping = false;

};