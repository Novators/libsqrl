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
		SqrlAction *action, int progress) = 0;
	virtual void onAsk(
		SqrlAction *action,
		std::string message, std::string firstButton, std::string secondButton ) = 0;
	virtual void onAuthenticationRequired(
		SqrlAction *action, Sqrl_Credential_Type credentialType) = 0;
	virtual void onSelectUser(SqrlAction *action) = 0;
	virtual void onSelectAlternateIdentity(
		SqrlAction *action) = 0;
	virtual void onSaveSuggested(
		SqrlUser *user) = 0;
	virtual void onActionComplete(
		SqrlAction *action) = 0;

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
	void callSelectUser( SqrlAction *action );
	void callSelectAlternateIdentity(
		SqrlAction *action );
	void callActionComplete(
		SqrlAction *action );
	void callProgress(
		SqrlAction *action,
		int progress );
	void callAuthenticationRequired(
		SqrlAction *action,
		Sqrl_Credential_Type credentialType );
	void callSend(
		SqrlAction *t, std::string *url, std::string *payload );
	void callAsk(
		SqrlAction *action,
		std::string *message, std::string *firstButton, std::string *secondButton );

	static void clientThread();
	std::thread *myThread;
	bool stopping = false;

};