/** \file SqrlClient.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLCLIENT_H
#define SQRLCLIENT_H

#include "sqrl.h"
#include "SqrlDeque.h"

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
		SqrlAction *t, SQRL_STRING url, SQRL_STRING payload ) = 0;
	virtual void onProgress(
		SqrlAction *action, int progress) = 0;
	virtual void onAsk(
		SqrlAction *action,
		SQRL_STRING message, SQRL_STRING firstButton, SQRL_STRING secondButton ) = 0;
	virtual void onAuthenticationRequired(
		SqrlAction *action, Sqrl_Credential_Type credentialType) = 0;
	virtual void onSelectUser(SqrlAction *action) = 0;
	virtual void onSelectAlternateIdentity(
		SqrlAction *action) = 0;
	virtual void onSaveSuggested(
		SqrlUser *user) = 0;
	virtual void onActionComplete(
		SqrlAction *action) = 0;

	struct CallbackInfo
	{
		CallbackInfo();
		~CallbackInfo();

		int cbType;
		int progress;
		Sqrl_Credential_Type credentialType;
		void *ptr;
		SQRL_STRING* str[3];
	};

private:
	SqrlDeque<struct CallbackInfo*> callbackQueue;
	SqrlDeque<SqrlAction *>actions;
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
		SqrlAction *t, SQRL_STRING *url, SQRL_STRING *payload );
	void callAsk(
		SqrlAction *action,
		SQRL_STRING *message, SQRL_STRING *firstButton, SQRL_STRING *secondButton );

};


#endif // SQRLCLIENT_H
