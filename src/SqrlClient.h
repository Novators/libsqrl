#pragma once

#include "sqrl.h"
#ifdef ARDUINO
#include "QueueList.h"
#define SQRL_QUEUE QueueList
#define SQRL_QUEUE_POP( obj ) obj.pop()
#define SQRL_QUEUE_IS_EMPTY( obj ) obj.isEmpty()
#define SQRL_QUEUE_PUSH( obj, item ) obj.push( item )
#define SQRL_QUEUE_PEEK( obj ) obj.peek()
#else
#include <queue>
#define SQRL_QUEUE std::deque
#define SQRL_QUEUE_POP( obj ) obj.front(); obj.pop_front()
#define SQRL_QUEUE_IS_EMPTY( obj ) obj.empty()
#define SQRL_QUEUE_PUSH( obj, item ) obj.push_back( item )
#define SQRL_QUEUE_PEEK( obj ) obj.front()
#endif

class DLL_PUBLIC SqrlClient
{
	friend class SqrlClientAsync;
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

protected:
	void initialize();

	virtual int getUserIdleSeconds();
	virtual bool isScreenLocked();
	virtual bool isUserChanged();

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
	SQRL_QUEUE<struct CallbackInfo*> callbackQueue;
	SQRL_QUEUE<SqrlAction *>actions;
#ifndef ARDUINO
	std::mutex actionMutex;
	std::mutex userMutex;
#endif

	bool loop();

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

};